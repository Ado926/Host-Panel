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
  origin: '*',  // Puedes reemplazar '*' por tu dominio específico si quieres más seguridad
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));


// Middleware para procesar
app.use(express.json());

const io = socketIO(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

// Directorio base para todas las sesiones
const SESSIONS_DIR = path.join(__dirname, "sessions");
// Archivo para almacenar usuarios
const USERS_FILE = path.join(__dirname, "users.json");

// Crear directorio de sesiones si no existe
if (!fs.existsSync(SESSIONS_DIR)) {
  fs.mkdirSync(SESSIONS_DIR, { recursive: true });
}

// Inicializar archivo de usuarios si no existe
if (!fs.existsSync(USERS_FILE)) {
  fs.writeFileSync(USERS_FILE, JSON.stringify({ users: [] }), 'utf8');
}

// Cargar usuarios
function loadUsers() {
  try {
    const data = fs.readFileSync(USERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error("Error al cargar usuarios:", err);
    return { users: [] };
  }
}

// Guardar usuarios
function saveUsers(usersData) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(usersData, null, 2), 'utf8');
  } catch (err) {
    console.error("Error al guardar usuarios:", err);
  }
}

// Hash de contraseña
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// Generar token de autenticación
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// API de registro
app.post("/api/register", (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: "Nombre de usuario y contraseña son requeridos" });
  }
  
  const usersData = loadUsers();
  
  // Verificar si el usuario ya existe
  if (usersData.users.some(user => user.username === username)) {
    return res.status(409).json({ error: "El nombre de usuario ya está en uso" });
  }
  
  // Crear nuevo usuario
  const hashedPassword = hashPassword(password);
  const token = generateToken();
  const property = `shell`;
  const sessionId = `${username}/${property}`;
  
  // Crear el directorio de la sesión si no existe
  const sessionDir = path.join(SESSIONS_DIR, sessionId);
  if (!fs.existsSync(sessionDir)) {
    fs.mkdirSync(sessionDir, { recursive: true });
  }
  
  // Guardar usuario
  usersData.users.push({
    username,
    password: hashedPassword,
    token,
    sessionId
  });
  
  saveUsers(usersData);
  
  res.status(201).json({ 
    username, 
    token,
    sessionId
  });
});

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.get("/terminal", (req, res) => res.sendFile(path.join(__dirname, "public", "terminal.html")));

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
  
  // Generar nuevo token
  const token = generateToken();
  user.token = token;
  saveUsers(usersData);
  
  // Asegurarse de que existe el directorio de sesión
  const sessionDir = path.join(SESSIONS_DIR, user.sessionId);
  if (!fs.existsSync(sessionDir)) {
    fs.mkdirSync(sessionDir, { recursive: true });
  }
  
  res.json({ 
    username: user.username, 
    token,
    sessionId: user.sessionId
  });
});

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
  
  // Adjuntar información del usuario al socket
  socket.user = user;
  next();
});

// Gestión de conexiones Socket.IO
io.on("connection", (socket) => {
  const user = socket.user;
  const sessionDir = path.join(SESSIONS_DIR, user.sessionId);
  
  console.log(`Usuario conectado: ${user.username} (${user.sessionId})`);

  // Enviar información de la sesión al cliente
  socket.emit("output", `
╔════════════════╗
║ ♥️             ♥️ ║
║      MayShell     ║
║    SoyMaycol <3   ║
║ ♥️             ♥️ ║
╚════════════════╝

--> GitHub: https://github.com/SoySapo6/
--> Licence: MIT






`);

  // Iniciar bash en el directorio de la sesión
  const pty = spawn("bash", [], {
    cwd: sessionDir,
    env: { ...process.env, TERM: "xterm-color" }
  });

  // Enviar comandos al terminal
  socket.on("command", (cmd) => {
    pty.stdin.write(cmd + "\n");
  });

  // Recibir salida del terminal y enviarla al frontend
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

//archivos estaticos
app.use(express.static(path.join(__dirname, 'public')));

//404 Not Found 
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

const PORT = process.env.PORT || 3000;  // fuerza puerto 3000 si no hay variable
server.listen(PORT, () => {
  console.log(`Servidor Socket.io en http://localhost:${PORT}`);
  console.log(`Directorio de sesiones: ${SESSIONS_DIR}`);
});
