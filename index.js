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

// Configuración
const SESSIONS_DIR = path.join(__dirname, "sessions");
const USERS_FILE = path.join(__dirname, "users.json");
const OWNER_EMAIL = "soymaycol.cn@gmail.com";
const OWNER_USERNAME = "SoyMaycol";

// Almacén de sitios hospedados
let hostedSites = new Map(); // { siteName: { userDir, watcher, sockets } }

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

function isValidPath(userSessionDir, targetPath) {
  const resolvedPath = path.resolve(userSessionDir, targetPath);
  return resolvedPath.startsWith(userSessionDir);
}

function sanitizeCommand(command, userSessionDir) {
  // Lista de comandos peligrosos para usuarios normales
  const dangerousCommands = [
    'rm -rf /', 'mkfs', 'dd if=', 'chmod 777 /', 
    'chown root', 'sudo su', 'su root'
  ];
  
  // Verificar comandos peligrosos
  for (const dangerous of dangerousCommands) {
    if (command.includes(dangerous)) {
      return null;
    }
  }
  
  // Interceptar comando cd para mantener dentro del directorio de sesión
  if (command.trim().startsWith('cd ')) {
    const targetDir = command.trim().substring(3).trim() || userSessionDir;
    
    if (targetDir === '~' || targetDir === '' || targetDir === './') {
      return `cd "${userSessionDir}"`;
    }
    
    // Si es ruta absoluta, redirigir al directorio de sesión
    if (path.isAbsolute(targetDir)) {
      return `cd "${userSessionDir}"`;
    }
    
    // Para rutas relativas, verificar que estén dentro del directorio permitido
    const resolvedPath = path.resolve(userSessionDir, targetDir);
    if (!resolvedPath.startsWith(userSessionDir)) {
      return `cd "${userSessionDir}"`;
    }
  }
  
  return command;
}

// Función para limpiar nombre de sitio
function sanitizeSiteName(name) {
  return name.replace(/[^a-zA-Z0-9-_]/g, '').toLowerCase();
}

// Función para monitorear cambios en archivos
function watchSiteFiles(siteName, userDir) {
  const watcher = chokidar.watch(userDir, {
    ignored: /node_modules/,
    persistent: true,
    ignoreInitial: true
  });

  watcher.on('change', (filePath) => {
    const siteData = hostedSites.get(siteName);
    if (siteData && siteData.sockets) {
      // Notificar a todos los sockets conectados de este usuario sobre el cambio
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

//Estado del servidor
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
    return res.status(404).send(`
      <h1>Sitio no encontrado</h1>
      <p>El sitio '${siteName}' no está siendo hospedado actualmente.</p>
      <p>Sitios disponibles: ${Array.from(hostedSites.keys()).join(', ') || 'Ninguno'}</p>
    `);
  }

  const fullPath = path.join(siteData.userDir, filePath);
  
  // Verificar que el archivo esté dentro del directorio del usuario
  if (!fullPath.startsWith(siteData.userDir)) {
    return res.status(403).send('Acceso denegado');
  }

  // Servir el archivo
  res.sendFile(fullPath, (err) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.status(404).send(`
          <h1>Archivo no encontrado</h1>
          <p>El archivo '${filePath}' no existe en el sitio '${siteName}'.</p>
          <a href="/pages/${siteName}">Volver al inicio</a>
        `);
      } else {
        res.status(500).send('Error del servidor');
      }
    }
  });
});

// API para listar sitios hospedados
app.get('/api/hosted-sites', (req, res) => {
  const sites = Array.from(hostedSites.entries()).map(([name, data]) => ({
    name,
    url: `/pages/${name}`,
    directory: path.relative(SESSIONS_DIR, data.userDir)
  }));
  res.json({ sites });
});

// API de registro
app.post("/api/register", (req, res) => {
  const { username, password, email } = req.body;
  
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
    email: email || null,
    password: hashedPassword,
    token,
    sessionId,
    role: "user",
    createdAt: new Date().toISOString()
  });
  
  saveUsers(usersData);
  
  res.status(201).json({ 
    username, 
    token,
    sessionId,
    role: "user"
  });
});

// API de login
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: "Nombre de usuario y contraseña son requeridos" });
  }
  
  const usersData = loadUsers();
  const user = usersData.users.find(u => 
    u.username === username && 
    u.password === hashPassword(password)
  );
  
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
  
  res.json({ 
    username: user.username, 
    token,
    sessionId: user.sessionId,
    role: user.role || "user"
  });
});

// APIs de administración
app.post("/api/admin/users", authenticateAdmin, (req, res) => {
  const usersData = loadUsers();
  const users = usersData.users.map(user => ({
    username: user.username,
    email: user.email,
    role: user.role,
    createdAt: user.createdAt,
    lastLogin: user.lastLogin
  }));
  res.json({ users });
});

app.delete("/api/admin/users/:username", authenticateAdmin, (req, res) => {
  const { username } = req.params;
  const currentUser = req.user;
  
  if (username === OWNER_USERNAME) {
    return res.status(403).json({ error: "No se puede eliminar al owner" });
  }
  
  const usersData = loadUsers();
  const userIndex = usersData.users.findIndex(u => u.username === username);
  
  if (userIndex === -1) {
    return res.status(404).json({ error: "Usuario no encontrado" });
  }
  
  const userToDelete = usersData.users[userIndex];
  
  // Solo owner puede eliminar admins
  if (userToDelete.role === "admin" && currentUser.role !== "owner") {
    return res.status(403).json({ error: "Solo el owner puede eliminar administradores" });
  }
  
  // Eliminar sitios hospedados del usuario
  const sessionDir = path.join(SESSIONS_DIR, userToDelete.sessionId);
  hostedSites.forEach((siteData, siteName) => {
    if (siteData.userDir.startsWith(sessionDir)) {
      if (siteData.watcher) {
        siteData.watcher.close();
      }
      hostedSites.delete(siteName);
    }
  });
  
  // Eliminar directorio de sesión
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
  
  if (!user) {
    return res.status(404).json({ error: "Usuario no encontrado" });
  }
  
  if (user.role === "owner") {
    return res.status(400).json({ error: "El usuario ya es owner" });
  }
  
  user.role = "admin";
  saveUsers(usersData);
  
  res.json({ message: `Usuario ${username} promovido a administrador` });
});

app.post("/api/admin/demote/:username", authenticateOwner, (req, res) => {
  const { username } = req.params;
  
  if (username === OWNER_USERNAME) {
    return res.status(403).json({ error: "No se puede degradar al owner" });
  }
  
  const usersData = loadUsers();
  const user = usersData.users.find(u => u.username === username);
  
  if (!user) {
    return res.status(404).json({ error: "Usuario no encontrado" });
  }
  
  user.role = "user";
  saveUsers(usersData);
  
  res.json({ message: `Usuario ${username} degradado a usuario normal` });
});

// Middleware de autenticación
function authenticateAdmin(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: "Token requerido" });
  }
  
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
  
  if (!token) {
    return res.status(401).json({ error: "Token requerido" });
  }
  
  const usersData = loadUsers();
  const user = usersData.users.find(u => u.token === token);
  
  if (!user || user.role !== "owner") {
    return res.status(403).json({ error: "Acceso denegado. Se requieren permisos de owner" });
  }
  
  req.user = user;
  next();
}

// Rutas estáticas
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/terminal", (req, res) => res.sendFile(path.join(__dirname, "public", "terminal.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));
app.get("/archivos", (req, res) => res.sendFile(path.join(__dirname, "public", "file_manager.html")));

// Autenticación de Socket.IO
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  
  if (!token) {
    return next(new Error("Autenticación requerida"));
  }
  
  const usersData = loadUsers();
  const user = usersData.users.find(u => u.token === token);
  
  if (!user) {
    return next(new Error("Token inválido"));
  }
  
  socket.user = user;
  next();
});

// Gestión de conexiones Socket.IO
io.on("connection", (socket) => {
  const user = socket.user;
  const sessionDir = path.join(SESSIONS_DIR, user.sessionId);
  
  console.log(`Usuario conectado: ${user.username} (${user.role}) - ${user.sessionId}`);

  // Agregar socket a los sitios hospedados del usuario
  hostedSites.forEach((siteData, siteName) => {
    if (siteData.userDir.startsWith(sessionDir)) {
      if (!siteData.sockets) {
        siteData.sockets = new Set();
      }
      siteData.sockets.add(socket);
    }
  });

  // Mensaje de bienvenida personalizado según el rol
  let welcomeMessage = `
╔════════════════╗
║ TermiHost
╚════════════════

`;

  if (user.role === "owner" || user.role === "admin") {
    welcomeMessage += `
PERMISOS DE ADMINISTRADOR ACTIVOS
- Use 'mayshell-admin help' para comandos de administración
- Use 'mayshell-system <comando>' para comandos del sistema
`;
  }

  welcomeMessage += `
¡Nuevos Comandos! ♥:
- Use 'mayshell-host <nombre>' para hospedar un sitio web
- Use 'mayshell-unhost <nombre>' para detener el hospedaje
- Use 'mayshell-sites' para ver sitios hospedados

> Hecho por SoyMaycol <3
`;
  
  socket.emit("output", welcomeMessage);

  // Configurar PTY según el rol
  let ptyOptions = {
    cwd: sessionDir,
    env: { ...process.env, TERM: "xterm-color" }
  };

  // Para admins/owner, permitir acceso al sistema completo con comando especial
  if (user.role === "owner" || user.role === "admin") {
    ptyOptions.env.MAYSHELL_USER = user.username;
    ptyOptions.env.MAYSHELL_ROLE = user.role;
    ptyOptions.env.MAYSHELL_SESSION_DIR = sessionDir;
  }

  const pty = spawn("bash", [], ptyOptions);

  // Enviar comandos al terminal
  socket.on("command", (cmd) => {
    let processedCmd = cmd;

    // Comandos especiales de hosting
    if (cmd.startsWith("mayshell-host ")) {
      handleHostCommand(cmd, socket, user, sessionDir);
      return;
    }

    if (cmd.startsWith("mayshell-unhost ")) {
      handleUnhostCommand(cmd, socket, user);
      return;
    }

    if (cmd.trim() === "mayshell-sites") {
      handleSitesCommand(socket, user, sessionDir);
      return;
    }

    // Comandos especiales de administración
    if (cmd.startsWith("mayshell-admin ") && (user.role === "owner" || user.role === "admin")) {
      handleAdminCommand(cmd, socket, user);
      return;
    }

    // Para usuarios normales, sanitizar comandos
    if (user.role === "user") {
      processedCmd = sanitizeCommand(cmd, sessionDir);
      if (processedCmd === null) {
        socket.emit("output", "\nComando bloqueado por seguridad.\n");
        return;
      }
    }

    // Para admins/owner, permitir comandos del sistema con prefijo especial
    if ((user.role === "owner" || user.role === "admin") && cmd.startsWith("mayshell-system ")) {
      const systemCmd = cmd.replace("mayshell-system ", "");
      pty.stdin.write(systemCmd + "\n");
      return;
    }

    pty.stdin.write(processedCmd + "\n");
  });

  // Recibir salida del terminal
  pty.stdout.on("data", (data) => {
    socket.emit("output", data.toString());
  });

  pty.stderr.on("data", (data) => {
    socket.emit("output", data.toString());
  });

  // Manejar desconexión
  socket.on("disconnect", () => {
    console.log(`Usuario desconectado: ${user.username}`);
    
    // Remover socket de sitios hospedados
    hostedSites.forEach((siteData) => {
      if (siteData.sockets) {
        siteData.sockets.delete(socket);
      }
    });
    
    pty.kill();
  });
});

// Función para manejar comando mayshell-host
function handleHostCommand(cmd, socket, user, sessionDir) {
  const args = cmd.split(" ").slice(1);
  if (args.length === 0) {
    socket.emit("output", "\nUso: mayshell-host <nombre-del-sitio>\n");
    return;
  }

  const siteName = sanitizeSiteName(args[0]);
  if (!siteName) {
    socket.emit("output", "\nError: Nombre de sitio inválido. Use solo letras, números, guiones y guiones bajos.\n");
    return;
  }

  // Verificar si ya existe un sitio con ese nombre
  if (hostedSites.has(siteName)) {
    socket.emit("output", `\nError: Ya existe un sitio con el nombre '${siteName}'.\n`);
    return;
  }

  // Verificar si existe index.html en el directorio actual
  const indexPath = path.join(sessionDir, 'index.html');
  if (!fs.existsSync(indexPath)) {
    socket.emit("output", "\nError: No se encontró index.html en el directorio actual.\n");
    socket.emit("output", "Cree un archivo index.html en este directorio antes de hospedar el sitio.\n");
    return;
  }

  // Obtener el directorio de trabajo actual del usuario
  const currentDir = process.cwd();
  let userCurrentDir = sessionDir;

  // Intentar obtener el directorio actual del PTY (esto es una aproximación)
  try {
    const ptyWorkingDir = sessionDir; // Por defecto, usar sessionDir
    userCurrentDir = ptyWorkingDir;
  } catch (err) {
    // Usar sessionDir como fallback
  }

  // Crear el watcher para monitorear cambios
  const watcher = watchSiteFiles(siteName, userCurrentDir);

  // Registrar el sitio
  hostedSites.set(siteName, {
    userDir: userCurrentDir,
    watcher: watcher,
    sockets: new Set([socket])
  });

  const siteUrl = `/pages/${siteName}`;
  socket.emit("output", `
✅ Sitio '${siteName}' hospedado exitosamente!

🌐 URL: http://localhost:${process.env.PORT || 3000}${siteUrl}
📁 Directorio: ${path.relative(SESSIONS_DIR, userCurrentDir)}
🔄 Monitoreo de cambios: ACTIVO

Los cambios en los archivos se reflejarán automáticamente en el sitio web.

`);
}

// Función para manejar comando mayshell-unhost
function handleUnhostCommand(cmd, socket, user) {
  const args = cmd.split(" ").slice(1);
  if (args.length === 0) {
    socket.emit("output", "\nUso: mayshell-unhost <nombre-del-sitio>\n");
    return;
  }

  const siteName = sanitizeSiteName(args[0]);
  const siteData = hostedSites.get(siteName);

  if (!siteData) {
    socket.emit("output", `\nError: No se encontró el sitio '${siteName}'.\n`);
    return;
  }

  // Cerrar el watcher
  if (siteData.watcher) {
    siteData.watcher.close();
  }

  // Eliminar el sitio
  hostedSites.delete(siteName);

  socket.emit("output", `\n✅ Sitio '${siteName}' eliminado del hospedaje.\n`);
}

// Función para manejar comando mayshell-sites
function handleSitesCommand(socket, user, sessionDir) {
  const userSites = Array.from(hostedSites.entries())
    .filter(([_, siteData]) => siteData.userDir.startsWith(sessionDir))
    .map(([name, siteData]) => ({
      name,
      url: `/pages/${name}`,
      directory: path.relative(sessionDir, siteData.userDir)
    }));

  if (userSites.length === 0) {
    socket.emit("output", "\nNo tienes sitios hospedados actualmente.\n");
    socket.emit("output", "Use 'mayshell-host <nombre>' para hospedar un sitio.\n");
    return;
  }

  let output = "\n🌐 TUS SITIOS HOSPEDADOS:\n";
  output += "================================\n";
  
  userSites.forEach(site => {
    output += `📦 ${site.name}\n`;
    output += `   🔗 http://localhost:${process.env.PORT || 3000}${site.url}\n`;
    output += `   📁 ${site.directory || 'Directorio actual'}\n\n`;
  });

  socket.emit("output", output);
}

// Función para manejar comandos de administración
function handleAdminCommand(cmd, socket, user) {
  const args = cmd.split(" ").slice(1);
  const command = args[0];

  switch (command) {
    case "help":
      socket.emit("output", `
COMANDOS DE ADMINISTRACIÓN MAYSHELL:

mayshell-admin users          - Listar todos los usuarios
mayshell-admin delete <user>  - Eliminar usuario
mayshell-admin promote <user> - Promover usuario a admin (solo owner)
mayshell-admin demote <user>  - Degradar admin a usuario (solo owner)
mayshell-admin sites          - Ver todos los sitios hospedados
mayshell-system <comando>     - Ejecutar comando en el sistema

Ejemplos:
mayshell-admin users
mayshell-admin delete usuario1
mayshell-admin sites
mayshell-system ls /root
mayshell-system ps aux

`);
      break;

    case "users":
      const usersData = loadUsers();
      let output = "\nUSUARIOS REGISTRADOS:\n";
      output += "========================\n";
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

      let sitesOutput = "\n🌐 TODOS LOS SITIOS HOSPEDADOS:\n";
      sitesOutput += "====================================\n";
      
      hostedSites.forEach((siteData, siteName) => {
        const userDir = path.relative(SESSIONS_DIR, siteData.userDir);
        sitesOutput += `📦 ${siteName}\n`;
        sitesOutput += `   🔗 http://localhost:${process.env.PORT || 3000}/pages/${siteName}\n`;
        sitesOutput += `   📁 ${userDir}\n`;
        sitesOutput += `   👥 Conexiones activas: ${siteData.sockets ? siteData.sockets.size : 0}\n\n`;
      });

      socket.emit("output", sitesOutput);
      break;

    case "delete":
      if (args.length < 2) {
        socket.emit("output", "\nUso: mayshell-admin delete <username>\n");
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

      // Eliminar sitios hospedados del usuario
      const targetSessionDir = path.join(SESSIONS_DIR, targetUser.sessionId);
      const sitesToDelete = [];
      hostedSites.forEach((siteData, siteName) => {
        if (siteData.userDir.startsWith(targetSessionDir)) {
          sitesToDelete.push(siteName);
        }
      });

      sitesToDelete.forEach(siteName => {
        const siteData = hostedSites.get(siteName);
        if (siteData.watcher) {
          siteData.watcher.close();
        }
        hostedSites.delete(siteName);
      });

      // Eliminar directorio de sesión
      if (fs.existsSync(targetSessionDir)) {
        fs.rmSync(targetSessionDir, { recursive: true, force: true });
      }

      usersData2.users.splice(userIndex, 1);
      saveUsers(usersData2);
      
      socket.emit("output", `\nUsuario '${userToDelete}' eliminado correctamente\n`);
      if (sitesToDelete.length > 0) {
        socket.emit("output", `Sitios eliminados: ${sitesToDelete.join(', ')}\n`);
      }
      break;

    case "promote":
      if (user.role !== "owner") {
        socket.emit("output", "\nError: Solo el owner puede promover usuarios\n");
        return;
      }
      
      if (args.length < 2) {
        socket.emit("output", "\nUso: mayshell-admin promote <username>\n");
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
        socket.emit("output", "\nUso: mayshell-admin demote <username>\n");
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
      socket.emit("output", "\nComando de administración no reconocido. Use 'mayshell-admin help'\n");
  }
}

// Archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// 404 Not Found 
/*app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});*/

// Limpiar recursos al cerrar el servidor
process.on('SIGINT', () => {
  console.log('\nCerrando servidor MayShell...');
  
  // Cerrar todos los watchers
  hostedSites.forEach((siteData) => {
    if (siteData.watcher) {
      siteData.watcher.close();
    }
  });
  
  process.exit(0);
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Servidor MayShell en http://localhost:${PORT}`);
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
  console.log("- mayshell-host <nombre>   - Hospedar sitio web");
  console.log("- mayshell-unhost <nombre> - Detener hospedaje");
  console.log("- mayshell-sites           - Ver sitios hospedados");
});
