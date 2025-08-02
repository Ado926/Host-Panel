const express = require("express");
const http = require("http");
const socketIO = require("socket.io");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const os = require('os');
const cors = require("cors");
const chokidar = require("chokidar");

const app = express();
const server = http.createServer(app);

// Configuración inicial
const SESSIONS_DIR = path.join(__dirname, "sessions");
const USERS_FILE = path.join(__dirname, "users.json");
const OWNER_USERNAME = "SoyMaycol";
const OWNER_EMAIL = "soymaycol.cn@gmail.com";

// Crear directorio de sesiones si no existe
if (!fs.existsSync(SESSIONS_DIR)) {
  fs.mkdirSync(SESSIONS_DIR, { recursive: true });
}

// Inicializar archivo de usuarios si no existe
if (!fs.existsSync(USERS_FILE)) {
  const initialData = {
    users: [{
      username: OWNER_USERNAME,
      email: OWNER_EMAIL,
      password: hashPassword("maycol123"),
      token: generateToken(),
      sessionId: `${OWNER_USERNAME}/shell`,
      role: "owner",
      createdAt: new Date().toISOString()
    }]
  };
  fs.writeFileSync(USERS_FILE, JSON.stringify(initialData, null, 2), 'utf8');
}

// Middleware para servir archivos estáticos desde la carpeta 'public'
app.use(express.static(path.join(__dirname, 'public')));

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

const io = socketIO(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

// Almacén de sitios hospedados
let hostedSites = new Map(); // { siteName: { userDir, watcher, sockets } }

// Funciones utilitarias
function loadUsers() {
  try {
    const data = fs.readFileSync(USERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error("Error al cargar usuarios:", err);
    return { users: [] };
  }
}

function saveUsers(usersData) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(usersData, null, 2), 'utf8');
  } catch (err) {
    console.error("Error al guardar usuarios:", err);
  }
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function sanitizeCommand(command, userSessionDir) {
  const dangerousCommands = [
    'rm -rf /', 'mkfs', 'dd if=', 'chmod 777 /',
    'chown root', 'sudo su', 'su root'
  ];
  for (const dangerous of dangerousCommands) {
    if (command.includes(dangerous)) {
      return null;
    }
  }

  if (command.trim().startsWith('cd ')) {
    const targetDir = command.trim().substring(3).trim();
    if (targetDir === '~' || targetDir === '' || targetDir === './') {
      return `cd "${userSessionDir}"`;
    }
    if (path.isAbsolute(targetDir)) {
      return `cd "${userSessionDir}"`;
    }
    const resolvedPath = path.resolve(userSessionDir, targetDir);
    if (!resolvedPath.startsWith(userSessionDir)) {
      return `cd "${userSessionDir}"`;
    }
  }
  return command;
}

function sanitizeSiteName(name) {
  return name.replace(/[^a-zA-Z0-9-_]/g, '').toLowerCase();
}

function watchSiteFiles(siteName, userDir) {
  const watcher = chokidar.watch(userDir, {
    ignored: /node_modules/,
    persistent: true,
    ignoreInitial: true
  });
  watcher.on('change', (filePath) => {
    const siteData = hostedSites.get(siteName);
    if (siteData && siteData.sockets) {
      siteData.sockets.forEach(socket => {
        if (socket.connected) {
          socket.emit('file-changed', {
            siteName,
            filePath: path.relative(userDir, filePath)
          });
        }
      });
    }
  });
  return watcher;
}

// APIs y Rutas
// Estado del servidor
app.get('/status', (req, res) => {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const uptime = os.uptime();
  const load = os.loadavg();
  const cpus = os.cpus();
  const estado = load[0] > cpus.length * 1.5 ? '⚠️ Alta carga' : '✅ Todo OK';

  const status = {
    sistema: {
      plataforma: os.platform(),
      arquitectura: os.arch(),
      uptime: `${Math.floor(uptime / 60)} minutos`,
      estado
    },
    memoria: {
      total: `${(totalMem / 1024 / 1024).toFixed(2)} MB`,
      usada: `${(usedMem / 1024 / 1024).toFixed(2)} MB`,
      libre: `${(freeMem / 1024 / 1024).toFixed(2)} MB`,
      usoPorcentaje: `${((usedMem / totalMem) * 100).toFixed(2)}%`
    },
    cpu: {
      nucleos: cpus.length,
      modelo: cpus[0].model,
      velocidadMHz: cpus[0].speed,
      cargaPromedio: load.map(l => l.toFixed(2))
    },
    sitiosHospedados: Array.from(hostedSites.keys())
  };
  res.json(status);
});

// Ruta para servir sitios hospedados
app.get('/pages/:siteName/*?', (req, res) => {
  const siteName = req.params.siteName;
  const filePath = req.params[0] || 'index.html';
  const siteData = hostedSites.get(siteName);

  if (!siteData) {
    return res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
  }

  const fullPath = path.join(siteData.userDir, filePath);
  if (!fullPath.startsWith(siteData.userDir)) {
    return res.status(403).send('Acceso denegado');
  }

  res.sendFile(fullPath, (err) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
      } else {
        res.status(500).send('Error del servidor');
      }
    }
  });
});

// APIs para listar sitios hospedados
app.get('/api/hosted-sites', (req, res) => {
  const sites = Array.from(hostedSites.entries()).map(([name, data]) => ({
    name,
    url: `/pages/${name}`,
    directory: path.relative(SESSIONS_DIR, data.userDir)
  }));
  res.json({ sites });
});

// APIs de autenticación y registro
app.post("/api/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Nombre de usuario y contraseña son requeridos" });
  }
  const usersData = loadUsers();
  if (usersData.users.some(user => user.username === username)) {
    return res.status(409).json({ error: "El nombre de usuario ya está en uso" });
  }
  const hashedPassword = hashPassword(password);
  const token = generateToken();
  const sessionId = `${username}/shell`;
  const sessionDir = path.join(SESSIONS_DIR, sessionId);
  if (!fs.existsSync(sessionDir)) {
    fs.mkdirSync(sessionDir, { recursive: true });
  }
  usersData.users.push({
    username,
    password: hashedPassword,
    token,
    sessionId,
    role: "user",
    createdAt: new Date().toISOString()
  });
  saveUsers(usersData);
  res.status(201).json({ username, token, sessionId, role: "user" });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Nombre de usuario y contraseña son requeridos" });
  }
  const usersData = loadUsers();
  const user = usersData.users.find(u => u.username === username && u.password === hashPassword(password));
  if (!user) {
    return res.status(401).json({ error: "Credenciales incorrectas" });
  }
  const token = generateToken();
  user.token = token;
  user.lastLogin = new Date().toISOString();
  saveUsers(usersData);
  const sessionDir = path.join(SESSIONS_DIR, user.sessionId);
  if (!fs.existsSync(sessionDir)) {
    fs.mkdirSync(sessionDir, { recursive: true });
  }
  res.json({ username: user.username, token, sessionId: user.sessionId, role: user.role || "user" });
});

// APIs de administración (Se mantienen igual)
function authenticateAdmin(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: "Token requerido" });
  const usersData = loadUsers();
  const user = usersData.users.find(u => u.token === token);
  if (!user || (user.role !== "admin" && user.role !== "owner")) {
    return res.status(403).json({ error: "Acceso denegado. Se requieren permisos de administrador" });
  }
  req.user = user;
  next();
}

function authenticateOwner(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: "Token requerido" });
  const usersData = loadUsers();
  const user = usersData.users.find(u => u.token === token);
  if (!user || user.role !== "owner") {
    return res.status(403).json({ error: "Acceso denegado. Se requieren permisos de owner" });
  }
  req.user = user;
  next();
}

app.post("/api/admin/users", authenticateAdmin, (req, res) => {
  const usersData = loadUsers();
  const users = usersData.users.map(user => ({ username: user.username, email: user.email, role: user.role, createdAt: user.createdAt, lastLogin: user.lastLogin }));
  res.json({ users });
});
app.delete("/api/admin/users/:username", authenticateAdmin, (req, res) => {
  const { username } = req.params;
  const currentUser = req.user;
  if (username === OWNER_USERNAME) return res.status(403).json({ error: "No se puede eliminar al owner" });
  const usersData = loadUsers();
  const userIndex = usersData.users.findIndex(u => u.username === username);
  if (userIndex === -1) return res.status(404).json({ error: "Usuario no encontrado" });
  const userToDelete = usersData.users[userIndex];
  if (userToDelete.role === "admin" && currentUser.role !== "owner") return res.status(403).json({ error: "Solo el owner puede eliminar administradores" });

  const sessionDir = path.join(SESSIONS_DIR, userToDelete.sessionId);
  hostedSites.forEach((siteData, siteName) => {
    if (siteData.userDir.startsWith(sessionDir)) {
      if (siteData.watcher) siteData.watcher.close();
      hostedSites.delete(siteName);
    }
  });

  if (fs.existsSync(sessionDir)) {
    fs.rmSync(sessionDir, { recursive: true, force: true });
  }
  usersData.users.splice(userIndex, 1);
  saveUsers(usersData);
  res.json({ message: `Usuario ${username} eliminado correctamente` });
});
app.post("/api/admin/promote/:username", authenticateOwner, (req, res) => {
  const { username } = req.params;
  const usersData = loadUsers();
  const user = usersData.users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
  if (user.role === "owner") return res.status(400).json({ error: "El usuario ya es owner" });
  user.role = "admin";
  saveUsers(usersData);
  res.json({ message: `Usuario ${username} promovido a administrador` });
});
app.post("/api/admin/demote/:username", authenticateOwner, (req, res) => {
  const { username } = req.params;
  if (username === OWNER_USERNAME) return res.status(403).json({ error: "No se puede degradar al owner" });
  const usersData = loadUsers();
  const user = usersData.users.find(u => u.username === userToDemote);
  if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
  user.role = "user";
  saveUsers(usersData);
  res.json({ message: `Usuario ${username} degradado a usuario normal` });
});

// Autenticación de Socket.IO
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error("Autenticación requerida"));
  const usersData = loadUsers();
  const user = usersData.users.find(u => u.token === token);
  if (!user) return next(new Error("Token inválido"));
  socket.user = user;
  next();
});

// Gestión de conexiones Socket.IO
io.on("connection", (socket) => {
  const user = socket.user;
  const sessionDir = path.join(SESSIONS_DIR, user.sessionId);
  console.log(`Usuario conectado: ${user.username} (${user.role}) - ${user.sessionId}`);

  hostedSites.forEach((siteData, siteName) => {
    if (siteData.userDir.startsWith(sessionDir)) {
      if (!siteData.sockets) {
        siteData.sockets = new Set();
      }
      siteData.sockets.add(socket);
    }
  });

  let welcomeMessage = `\nBienvenido a TermiHost, ${user.username}\n`;
  if (user.role === "owner" || user.role === "admin") {
    welcomeMessage += `\n[ADMIN] Permisos de administrador activos.\n`;
  }
  welcomeMessage += `\nEscribe 'help' para ver los comandos disponibles.`;
  welcomeMessage += `\nUsa 'termihost-host <nombre>' para hospedar un sitio web`;
  welcomeMessage += `\nUsa 'termihost-sites' para ver tus sitios hospedados\n`;
  socket.emit("output", welcomeMessage);

  const pty = spawn("bash", [], {
    cwd: sessionDir,
    env: { ...process.env, TERM: "xterm-color" }
  });

  socket.on("command", (cmd) => {
    if (cmd.startsWith("termihost-host ")) {
      handleHostCommand(cmd, socket, user, sessionDir);
      return;
    }
    if (cmd.startsWith("termihost-unhost ")) {
      handleUnhostCommand(cmd, socket, user);
      return;
    }
    if (cmd.trim() === "termihost-sites") {
      handleSitesCommand(socket, user, sessionDir);
      return;
    }
    if (cmd.startsWith("termihost-admin ") && (user.role === "owner" || user.role === "admin")) {
      handleAdminCommand(cmd, socket, user);
      return;
    }

    let processedCmd = cmd;
    if (user.role === "user") {
      processedCmd = sanitizeCommand(cmd, sessionDir);
      if (processedCmd === null) {
        socket.emit("output", "\nComando bloqueado por seguridad.\n");
        return;
      }
    }
    if ((user.role === "owner" || user.role === "admin") && cmd.startsWith("termihost-system ")) {
      const systemCmd = cmd.replace("termihost-system ", "");
      pty.stdin.write(systemCmd + "\n");
      return;
    }
    pty.stdin.write(processedCmd + "\n");
  });

  pty.stdout.on("data", (data) => {
    socket.emit("output", data.toString());
  });
  pty.stderr.on("data", (data) => {
    socket.emit("output", data.toString());
  });
  socket.on("disconnect", () => {
    console.log(`Usuario desconectado: ${user.username}`);
    hostedSites.forEach((siteData) => {
      if (siteData.sockets) siteData.sockets.delete(socket);
    });
    pty.kill();
  });
});

// Funciones de comandos (Se mantienen casi iguales, solo cambian los nombres de los comandos)
function handleHostCommand(cmd, socket, user, sessionDir) {
  const args = cmd.split(" ").slice(1);
  if (args.length === 0) {
    socket.emit("output", "\nUso: termihost-host <nombre-del-sitio>\n");
    return;
  }
  const siteName = sanitizeSiteName(args[0]);
  if (!siteName) {
    socket.emit("output", "\nError: Nombre de sitio inválido. Use solo letras, números, guiones y guiones bajos.\n");
    return;
  }
  if (hostedSites.has(siteName)) {
    socket.emit("output", `\nError: Ya existe un sitio con el nombre '${siteName}'.\n`);
    return;
  }
  const indexPath = path.join(sessionDir, 'index.html');
  if (!fs.existsSync(indexPath)) {
    socket.emit("output", "\nError: No se encontró index.html en el directorio actual.\n");
    socket.emit("output", "Cree un archivo index.html en este directorio antes de hospedar el sitio.\n");
    return;
  }
  const watcher = watchSiteFiles(siteName, sessionDir);
  hostedSites.set(siteName, { userDir: sessionDir, watcher: watcher, sockets: new Set([socket]) });
  const siteUrl = `/pages/${siteName}`;
  socket.emit("output", `\n✅ Sitio '${siteName}' hospedado exitosamente!
🌐 URL: http://localhost:${process.env.PORT || 3000}${siteUrl}
📁 Directorio: ${path.relative(SESSIONS_DIR, sessionDir)}
🔄 Monitoreo de cambios: ACTIVO\n`);
}

function handleUnhostCommand(cmd, socket, user) {
  const args = cmd.split(" ").slice(1);
  if (args.length === 0) {
    socket.emit("output", "\nUso: termihost-unhost <nombre-del-sitio>\n");
    return;
  }
  const siteName = sanitizeSiteName(args[0]);
  const siteData = hostedSites.get(siteName);
  if (!siteData) {
    socket.emit("output", `\nError: No se encontró el sitio '${siteName}'.\n`);
    return;
  }
  if (siteData.watcher) siteData.watcher.close();
  hostedSites.delete(siteName);
  socket.emit("output", `\n✅ Sitio '${siteName}' eliminado del hospedaje.\n`);
}

function handleSitesCommand(socket, user, sessionDir) {
  const userSites = Array.from(hostedSites.entries())
    .filter(([_, siteData]) => siteData.userDir.startsWith(sessionDir))
    .map(([name, siteData]) => ({ name, url: `/pages/${name}`, directory: path.relative(sessionDir, siteData.userDir) }));
  if (userSites.length === 0) {
    socket.emit("output", "\nNo tienes sitios hospedados actualmente.\n");
    socket.emit("output", "Use 'termihost-host <nombre>' para hospedar un sitio.\n");
    return;
  }
  let output = "\n🌐 TUS SITIOS HOSPEDADOS:\n================================\n";
  userSites.forEach(site => {
    output += `📦 ${site.name}\n   🔗 http://localhost:${process.env.PORT || 3000}${site.url}\n   📁 ${site.directory || 'Directorio actual'}\n\n`;
  });
  socket.emit("output", output);
}

function handleAdminCommand(cmd, socket, user) {
  const args = cmd.split(" ").slice(1);
  const command = args[0];
  switch (command) {
    case "help":
      socket.emit("output", `\nCOMANDOS DE ADMINISTRACIÓN TERMIHOST:
termihost-admin users          - Listar todos los usuarios
termihost-admin delete <user>  - Eliminar usuario
termihost-admin promote <user> - Promover usuario a admin (solo owner)
termihost-admin demote <user>  - Degradar admin a usuario (solo owner)
termihost-admin sites          - Ver todos los sitios hospedados
termihost-system <comando>     - Ejecutar comando en el sistema`);
      break;
    case "users":
      const usersData = loadUsers();
      let output = "\nUSUARIOS REGISTRADOS:\n========================\n";
      usersData.users.forEach(u => {
        output += `${u.username} (${u.role}) - ${u.email || 'Sin email'}\n`;
      });
      output += "\n";
      socket.emit("output", output);
      break;
    case "sites":
      if (hostedSites.size === 0) {
        socket.emit("output", "\nNo hay sitios hospedados actualmente.\n");
        return;
      }
      let sitesOutput = "\n🌐 TODOS LOS SITIOS HOSPEDADOS:\n====================================\n";
      hostedSites.forEach((siteData, siteName) => {
        const userDir = path.relative(SESSIONS_DIR, siteData.userDir);
        sitesOutput += `📦 ${siteName}\n   🔗 http://localhost:${process.env.PORT || 3000}/pages/${siteName}\n   📁 ${userDir}\n   👥 Conexiones activas: ${siteData.sockets ? siteData.sockets.size : 0}\n\n`;
      });
      socket.emit("output", sitesOutput);
      break;
    case "delete":
      if (args.length < 2) {
        socket.emit("output", "\nUso: termihost-admin delete <username>\n");
        return;
      }
      const userToDelete = args[1];
      if (userToDelete === OWNER_USERNAME) {
        socket.emit("output", "\nError: No se puede eliminar al owner\n");
        return;
      }
      const usersData2 = loadUsers();
      const userIndex = usersData2.users.findIndex(u => u.username === userToDelete);
      if (userIndex === -1) {
        socket.emit("output", `\nError: Usuario '${userToDelete}' no encontrado\n`);
        return;
      }
      const targetUser = usersData2.users[userIndex];
      if (targetUser.role === "admin" && user.role !== "owner") {
        socket.emit("output", "\nError: Solo el owner puede eliminar administradores\n");
        return;
      }
      const targetSessionDir = path.join(SESSIONS_DIR, targetUser.sessionId);
      const sitesToDelete = [];
      hostedSites.forEach((siteData, siteName) => {
        if (siteData.userDir.startsWith(targetSessionDir)) {
          sitesToDelete.push(siteName);
        }
      });
      sitesToDelete.forEach(siteName => {
        const siteData = hostedSites.get(siteName);
        if (siteData.watcher) siteData.watcher.close();
        hostedSites.delete(siteName);
      });
      if (fs.existsSync(targetSessionDir)) {
        fs.rmSync(targetSessionDir, { recursive: true, force: true });
      }
      usersData2.users.splice(userIndex, 1);
      saveUsers(usersData2);
      socket.emit("output", `\nUsuario '${userToDelete}' eliminado correctamente\n`);
      if (sitesToDelete.length > 0) socket.emit("output", `Sitios eliminados: ${sitesToDelete.join(', ')}\n`);
      break;
    case "promote":
      if (user.role !== "owner") {
        socket.emit("output", "\nError: Solo el owner puede promover usuarios\n");
        return;
      }
      if (args.length < 2) {
        socket.emit("output", "\nUso: termihost-admin promote <username>\n");
        return;
      }
      const userToPromote = args[1];
      const usersData3 = loadUsers();
      const targetUser2 = usersData3.users.find(u => u.username === userToPromote);
      if (!targetUser2) {
        socket.emit("output", `\nError: Usuario '${userToPromote}' no encontrado\n`);
        return;
      }
      if (targetUser2.role === "owner") {
        socket.emit("output", "\nError: El usuario ya es owner\n");
        return;
      }
      targetUser2.role = "admin";
      saveUsers(usersData3);
      socket.emit("output", `\nUsuario '${userToPromote}' promovido a administrador\n`);
      break;
    case "demote":
      if (user.role !== "owner") {
        socket.emit("output", "\nError: Solo el owner puede degradar usuarios\n");
        return;
      }
      if (args.length < 2) {
        socket.emit("output", "\nUso: termihost-admin demote <username>\n");
        return;
      }
      const userToDemote = args[1];
      if (userToDemote === OWNER_USERNAME) {
        socket.emit("output", "\nError: No se puede degradar al owner\n");
        return;
      }
      const usersData4 = loadUsers();
      const targetUser3 = usersData4.users.find(u => u.username === userToDemote);
      if (!targetUser3) {
        socket.emit("output", `\nError: Usuario '${userToDemote}' no encontrado\n`);
        return;
      }
      targetUser3.role = "user";
      saveUsers(usersData4);
      socket.emit("output", `\nUsuario '${userToDemote}' degradado a usuario normal\n`);
      break;
    default:
      socket.emit("output", "\nComando de administración no reconocido. Use 'termihost-admin help'\n");
  }
}

// 404 Not Found
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

// Limpiar recursos al cerrar el servidor
process.on('SIGINT', () => {
  console.log('\nCerrando servidor TermiHost...');
  hostedSites.forEach((siteData) => {
    if (siteData.watcher) siteData.watcher.close();
  });
  process.exit(0);
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Servidor TermiHost en http://localhost:${PORT}`);
  console.log(`Directorio de sesiones: ${SESSIONS_DIR}`);
  console.log(`Owner: ${OWNER_USERNAME} (${OWNER_EMAIL})`);
  console.log("\nRutas disponibles:");
  console.log("- GET  /           - Página principal");
  console.log("- GET  /terminal   - Terminal web");
  console.log("- GET  /admin      - Panel de administración");
  console.log("- GET  /archivos   - Gestor de archivos");
  console.log("- GET  /pages/:name - Sitios hospedados");
  console.log("- POST /api/login  - Iniciar sesión");
  console.log("- POST /api/register - Registrar usuario");
  console.log("\nComandos de hosting:");
  console.log("- termihost-host <nombre>   - Hospedar sitio web");
  console.log("- termihost-unhost <nombre> - Detener hospedaje");
  console.log("- termihost-sites           - Ver sitios hospedados");
});
