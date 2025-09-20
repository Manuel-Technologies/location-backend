require('dotenv').config();
const express = require('express');
const fs = require('fs');
const http = require('http');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);

// Load environment variables
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "7d";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
const USERS_FILE = './users.json';

// Setup middleware
app.use(cors({ origin: CORS_ORIGIN }));
app.use(express.json());

// Load users data from file
let users = [];
if (fs.existsSync(USERS_FILE)) {
  users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}

// Helper: Save users to file
function saveUsers() {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// 🔑 Generate JWT token
function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

// Middleware to protect routes
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ✅ Health check route
app.get('/api/health', (req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    message: "Backend running successfully 🚀"
  });
});

// ✅ Register route
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });

  if (users.find(u => u.username === username)) {
    return res.status(409).json({ error: "User already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: Date.now().toString(), username, password: hashedPassword };
  users.push(newUser);
  saveUsers();

  res.status(201).json({ message: "User registered", token: generateToken(newUser) });
});

// ✅ Login route
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });

  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: "Invalid credentials" });

  res.json({ message: "Login successful", token: generateToken(user) });
});

// ✅ Protected route example
app.get('/api/me', authMiddleware, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });

  res.json({ id: user.id, username: user.username });
});

// ✅ Setup Socket.IO for realtime location sharing
const io = new Server(server, { cors: { origin: CORS_ORIGIN } });

let liveLocations = {}; // { userId: { lat, lng, lastUpdated } }

io.on('connection', (socket) => {
  console.log(`🔗 Client connected: ${socket.id}`);

  // Handle user joining with token
  socket.on('join', (token) => {
    try {
      const user = jwt.verify(token, JWT_SECRET);
      socket.user = user;
      liveLocations[user.id] = { lat: null, lng: null, lastUpdated: null };
      console.log(`✅ ${user.username} joined`);
    } catch {
      socket.emit('error', { error: "Invalid token" });
    }
  });

  // Handle location updates
  socket.on('locationUpdate', (data) => {
    if (!socket.user) return;
    liveLocations[socket.user.id] = { ...data, lastUpdated: Date.now() };
    io.emit('locations', liveLocations);
  });

  socket.on('disconnect', () => {
    if (socket.user) {
      delete liveLocations[socket.user.id];
      io.emit('locations', liveLocations);
      console.log(`❌ ${socket.user.username} disconnected`);
    }
  });
});

// Start server
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});