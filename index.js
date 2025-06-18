const express = require("express");
const http = require("http");
const socketIO = require("socket.io");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const cors = require("cors");

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
      password: hashPassword("admin123"), // Cambiar por contraseña segura
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
  
  // Eliminar directorio de sesión
  const sessionDir = path.join(SESSIONS_DIR, userToDelete.sessionId);
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

  // Mensaje de bienvenida personalizado según el rol
  let welcomeMessage = `
╔════════════════╗
║ ♥️             ♥️ ║
║      MayShell     ║
║    SoyMaycol <3   ║
║ ♥️             ♥️ ║
╚════════════════╝

--> GitHub: https://github.com/SoySapo6/
--> Licence: MIT

Usuario: ${user.username}
Rol: ${user.role.toUpperCase()}
Directorio de trabajo: ${sessionDir}
`;

  if (user.role === "owner" || user.role === "admin") {
    welcomeMessage += `
PERMISOS DE ADMINISTRADOR ACTIVOS
- Use 'mayshell-admin help' para comandos de administración
`;
  }

  welcomeMessage += "\n\n";
  
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
    pty.kill();
  });
});

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
mayshell-system <comando>     - Ejecutar comando en el sistema

Ejemplos:
mayshell-admin users
mayshell-admin delete usuario1
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

      // Eliminar directorio de sesión
      const sessionDir = path.join(SESSIONS_DIR, targetUser.sessionId);
      if (fs.existsSync(sessionDir)) {
        fs.rmSync(sessionDir, { recursive: true, force: true });
      }

      usersData2.users.splice(userIndex, 1);
      saveUsers(usersData2);
      
      socket.emit("output", `\nUsuario '${userToDelete}' eliminado correctamente\n`);
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
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
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
  console.log("- POST /api/login  - Iniciar sesión");
  console.log("- POST /api/register - Registrar usuario");
});
