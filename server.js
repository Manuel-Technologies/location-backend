/**
 * server.js
 * Single-file, robust, production-minded realtime location backend.
 *
 * Features:
 * - Express REST endpoints: /health, /auth/register, /auth/login, /api/me, /api/recent
 * - Socket.IO realtime hub: snapshot, userMoved, userLeft
 * - File-backed persistence (users.json at root) with atomic writes
 * - bcrypt password hashing, JWT auth, basic rate limiting, input validation
 * - Caps persisted locations to avoid file growth
 *
 * Run:
 *   1) copy .env.example -> .env and edit
 *   2) npm install
 *   3) node server.js
 */

const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const helmet = require('helmet');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

dotenv.config();

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const USERS_FILE = path.resolve(process.cwd(), 'users.json');
const MAX_PERSISTED_LOCATIONS = Number(process.env.MAX_PERSISTED_LOCATIONS) || 5000;
const PORTION_PERSIST_EVERY = Number(process.env.PORTION_PERSIST_EVERY) || 5;

// --- Utility: ensure users.json exists ---
async function ensureUsersFile() {
  try {
    if (!fsSync.existsSync(USERS_FILE)) {
      const initial = { users: [], locations: [] };
      await fs.writeFile(USERS_FILE, JSON.stringify(initial, null, 2), 'utf8');
      console.log('Created users.json');
    }
  } catch (err) {
    console.error('Failed to ensure users.json:', err);
    process.exit(1);
  }
}

// --- Atomic read/write helpers with a simple in-process mutex ---
let writeLock = Promise.resolve();

async function readStore() {
  await ensureUsersFile();
  const raw = await fs.readFile(USERS_FILE, 'utf8');
  return JSON.parse(raw);
}

function atomicWrite(obj) {
  // ensure writes are serialized
  writeLock = writeLock.then(async () => {
    const tmp = USERS_FILE + '.tmp';
    await fs.writeFile(tmp, JSON.stringify(obj, null, 2), 'utf8');
    await fs.rename(tmp, USERS_FILE);
  }).catch(err => {
    console.error('atomicWrite error', err);
  });
  return writeLock;
}

// --- simple id generator ---
function makeId(prefix = '') {
  return prefix + Math.random().toString(36).slice(2, 10);
}

// --- validation helpers ---
function validEmail(email) {
  if (!email || typeof email !== 'string') return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function validLatLng(lat, lng) {
  if (!isFinite(lat) || !isFinite(lng)) return false;
  if (lat < -90 || lat > 90) return false;
  if (lng < -180 || lng > 180) return false;
  return true;
}

// --- express setup ---
const app = express();
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));

// Rate limiter for auth endpoints to reduce abuse
const authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10,
  message: { error: 'Too many requests, slow down' }
});

// --- Auth helpers ---
function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email, name: user.name || null }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}
function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}
async function getUserByEmail(email) {
  const store = await readStore();
  return store.users.find(u => u.email === email) || null;
}

// --- routes ---
app.get('/health', (req, res) => {
  res.json({ ok: true, uptime: process.uptime(), time: Date.now() });
});

app.post('/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, password, name } = req.body || {};
    if (!validEmail(email) || !password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ error: 'Invalid email or password (min 6 chars)' });
    }
    const normalized = email.trim().toLowerCase();

    const store = await readStore();
    if (store.users.some(u => u.email === normalized)) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const hash = await bcrypt.hash(password, 10);
    const user = { id: makeId('u_'), email: normalized, password_hash: hash, name: name ? String(name).trim() : null, created_at: new Date().toISOString() };
    store.users.push(user);
    await atomicWrite(store);

    const token = signToken(user);
    return res.json({ ok: true, token, user: { id: user.id, email: user.email, name: user.name } });
  } catch (err) {
    console.error('register error', err);
    return res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!validEmail(email) || !password) return res.status(400).json({ error: 'Invalid email or password' });

    const normalized = email.trim().toLowerCase();
    const store = await readStore();
    const user = store.users.find(u => u.email === normalized);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signToken(user);
    res.json({ ok: true, token, user: { id: user.id, email: user.email, name: user.name } });
  } catch (err) {
    console.error('login error', err);
    return res.status(500).json({ error: 'Login failed' });
  }
});

// simple auth middleware for REST
async function requireAuth(req, res, next) {
  try {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'Missing Authorization header' });
    const parts = auth.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization header' });
    const payload = verifyToken(parts[1]);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const store = await readStore();
    const user = store.users.find(u => u.id === req.user.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });
    return res.json({ ok: true, user: { id: user.id, email: user.email, name: user.name } });
  } catch (err) {
    console.error('api/me error', err);
    return res.status(500).json({ error: 'Failed to fetch user' });
  }
});

app.get('/api/recent', async (req, res) => {
  try {
    const limit = Math.min(1000, Math.max(1, Number(req.query.limit) || 200));
    const store = await readStore();
    const data = (store.locations || []).slice(-limit).reverse();
    return res.json({ ok: true, count: data.length, data });
  } catch (err) {
    console.error('api/recent error', err);
    return res.status(500).json({ error: 'Failed to fetch recent locations' });
  }
});

// --- HTTP + Socket.IO server ---
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: process.env.CORS_ORIGIN || '*' } });

const active = new Map(); // socketId => { userId, lat, lng, accuracy, ts, persistCount }

// socket auth via handshake.auth.token (optional)
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth && socket.handshake.auth.token;
    if (!token) return next();
    const payload = verifyToken(token);
    socket.user = { id: payload.sub, email: payload.email, name: payload.name || null };
    return next();
  } catch (err) {
    console.warn('Socket auth verify failed', err && err.message);
    return next(); // allow anonymous sockets too
  }
});

io.on('connection', (socket) => {
  console.log('socket connected', socket.id, 'user:', socket.user ? socket.user.id : 'anon');

  // send snapshot
  const snapshot = {};
  for (const [sid, val] of active.entries()) snapshot[sid] = val;
  socket.emit('snapshot', snapshot);

  socket.on('updateLocation', async (payload) => {
    try {
      if (!payload) return;
      const lat = Number(payload.lat);
      const lng = Number(payload.lng);
      const accuracy = payload.accuracy ? Number(payload.accuracy) : null;

      if (!validLatLng(lat, lng)) return; // ignore invalid

      const entry = {
        userId: socket.user ? socket.user.id : null,
        lat,
        lng,
        accuracy,
        ts: new Date().toISOString()
      };

      const storeEntry = { socketId: socket.id, ...entry };

      // keep in active map
      const prev = active.get(socket.id) || { persistCount: 0 };
      prev.lat = lat; prev.lng = lng; prev.accuracy = accuracy; prev.ts = entry.ts;
      prev.userId = entry.userId;
      prev.persistCount = (prev.persistCount || 0) + 1;
      active.set(socket.id, prev);

      // broadcast to others
      socket.broadcast.emit('userMoved', storeEntry);

      // persist periodically (reduce writes)
      if (prev.persistCount >= PORTION_PERSIST_EVERY) {
        prev.persistCount = 0;
        try {
          const store = await readStore();
          store.locations = store.locations || [];
          store.locations.push({ id: makeId('l_'), socketId: socket.id, ...entry });
          if (store.locations.length > MAX_PERSISTED_LOCATIONS) {
            store.locations = store.locations.slice(-MAX_PERSISTED_LOCATIONS);
          }
          await atomicWrite(store);
        } catch (err) {
          console.error('persist location error', err);
        }
      }
    } catch (err) {
      console.error('updateLocation handler error', err);
    }
  });

  socket.on('disconnect', () => {
    active.delete(socket.id);
    io.emit('userLeft', socket.id);
    console.log('socket disconnected', socket.id);
  });
});

// graceful shutdown
async function shutdown() {
  console.log('Shutdown initiated');
  try {
    io.close();
    server.close(() => {
      console.log('HTTP server closed');
      process.exit(0);
    });
    // if still pending writes, wait a moment
    await writeLock;
  } catch (err) {
    console.error('Shutdown error', err);
    process.exit(1);
  }
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// start
(async () => {
  await ensureUsersFile();
  server.listen(PORT, () => {
    console.log(`🚀 Location server listening on port ${PORT}`);
    console.log(`Users file: ${USERS_FILE}`);
  });
})();