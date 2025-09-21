import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import fs from "fs";
import http from "http";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { Server } from "socket.io";

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: process.env.CORS_ORIGIN || "*" } });

// ====== ENV CONFIG ======
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "7d";
const USERS_FILE = "./users.json";

// ====== STATE ======
let users = [];
let liveLocations = {}; // { userId: { lat, lng, lastUpdated } }

// ====== UTILS ======
function loadUsers() {
  if (fs.existsSync(USERS_FILE)) {
    try {
      users = JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
    } catch (e) {
      console.error("❌ Failed to parse users.json. Resetting file.");
      users = [];
      saveUsers();
    }
  }
}

function saveUsers() {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Authorization token missing" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ====== MIDDLEWARE ======
app.use(cors({ origin: process.env.CORS_ORIGIN || "*" }));
app.use(express.json());

// ====== ROUTES ======
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    message: "Backend running successfully 🚀"
  });
});

app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password required" });

    if (users.find((u) => u.username === username)) {
      return res.status(409).json({ error: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = { id: Date.now().toString(), username, password: hashedPassword };

    users.push(newUser);
    saveUsers();

    res.status(201).json({ message: "User registered successfully", token: generateToken(newUser) });
  } catch (err) {
    console.error("❌ Registration error:", err);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password required" });

    const user = users.find((u) => u.username === username);
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    res.json({ message: "Login successful", token: generateToken(user) });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/me", authMiddleware, (req, res) => {
  const user = users.find((u) => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });

  res.json({ id: user.id, username: user.username });
});

// ====== SOCKET.IO ======
io.on("connection", (socket) => {
  console.log(`🔗 Client connected: ${socket.id}`);

  socket.on("join", (token) => {
    try {
      const user = jwt.verify(token, JWT_SECRET);
      socket.user = user;
      liveLocations[user.id] = { lat: null, lng: null, lastUpdated: null };
      console.log(`✅ ${user.username} joined`);
      io.emit("locations", liveLocations);
    } catch {
      socket.emit("error", { error: "Invalid token" });
    }
  });

  socket.on("locationUpdate", (data) => {
    if (!socket.user) return;
    liveLocations[socket.user.id] = { ...data, lastUpdated: Date.now() };
    io.emit("locations", liveLocations);
  });

  socket.on("disconnect", () => {
    if (socket.user) {
      delete liveLocations[socket.user.id];
      io.emit("locations", liveLocations);
      console.log(`❌ ${socket.user.username} disconnected`);
    }
  });
});

// ====== SERVER START ======
loadUsers();
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));