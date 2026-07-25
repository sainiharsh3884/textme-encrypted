// server.js
require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(express.static('../public'));

// --- In‑memory stores ---
const users = loadUsers();
const sessions = new Map();
const roomClients = new Map();
const prekeyStore = new Map();
const refreshTokens = new Map();

function loadUsers() {
  try {
    const data = fs.readFileSync('./users.json', 'utf8');
    return JSON.parse(data);
  } catch { return {}; }
}
function saveUsers() {
  fs.writeFileSync('./users.json', JSON.stringify(users, null, 2));
}

function generateAccessToken(username) {
  return jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '5m' });
}
function generateRefreshToken(username) {
  const token = jwt.sign({ username }, process.env.REFRESH_SECRET, { expiresIn: '7d' });
  refreshTokens.set(username, token);
  return token;
}
function verifyAccessToken(token) {
  try { return jwt.verify(token, process.env.JWT_SECRET); } catch { return null; }
}
function verifyRefreshToken(token) {
  try { return jwt.verify(token, process.env.REFRESH_SECRET); } catch { return null; }
}

function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  const token = auth.split(' ')[1];
  const payload = verifyAccessToken(token);
  if (!payload) return res.status(401).json({ error: 'Invalid token' });
  req.user = payload;
  next();
}

// --- Auth Routes ---
app.post('/api/signup', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  if (users[username]) return res.status(400).json({ error: 'User exists' });
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  users[username] = { username, passwordHash: `${salt}:${hash}`, createdAt: Date.now() };
  saveUsers();
  const accessToken = generateAccessToken(username);
  const refreshToken = generateRefreshToken(username);
  res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 7*24*3600*1000 });
  res.json({ token: accessToken, username });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = users[username];
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const [salt, hash] = user.passwordHash.split(':');
  const computed = crypto.scryptSync(password, salt, 64).toString('hex');
  if (computed !== hash) return res.status(401).json({ error: 'Invalid credentials' });
  const accessToken = generateAccessToken(username);
  const refreshToken = generateRefreshToken(username);
  res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 7*24*3600*1000 });
  res.json({ token: accessToken, username });
});

app.post('/api/refresh', (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ error: 'No refresh token' });
  const payload = verifyRefreshToken(token);
  if (!payload) return res.status(401).json({ error: 'Invalid refresh token' });
  if (refreshTokens.get(payload.username) !== token) {
    return res.status(401).json({ error: 'Token revoked' });
  }
  const newAccess = generateAccessToken(payload.username);
  res.json({ token: newAccess });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('refreshToken');
  res.json({ ok: true });
});

app.get('/api/me', authenticate, (req, res) => {
  res.json({ username: req.user.username });
});

// --- Prekey Endpoints (Signal Protocol) ---
app.post('/api/keys', authenticate, (req, res) => {
  const { identityKey, signedPreKey, oneTimePreKeys } = req.body;
  if (!identityKey || !signedPreKey || !Array.isArray(oneTimePreKeys)) {
    return res.status(400).json({ error: 'Invalid bundle' });
  }
  prekeyStore.set(req.user.username, {
    identityKey,
    signedPreKey,
    oneTimePreKeys: oneTimePreKeys.slice(),
  });
  res.json({ ok: true });
});

app.get('/api/keys/:username', (req, res) => {
  const bundle = prekeyStore.get(req.params.username);
  if (!bundle) return res.status(404).json({ error: 'User not found' });
  const oneTime = bundle.oneTimePreKeys.pop();
  res.json({
    identityKey: bundle.identityKey,
    signedPreKey: bundle.signedPreKey,
    oneTimePreKey: oneTime || null,
  });
});

// --- User Search ---
app.get('/api/users/search', authenticate, (req, res) => {
  const q = req.query.q || '';
  const matches = Object.keys(users).filter(u => u.toLowerCase().includes(q.toLowerCase()));
  res.json({ users: matches });
});

// --- WebSocket ---
wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const token = url.searchParams.get('token');
  const room = url.searchParams.get('room');
  if (!token) { ws.close(); return; }
  const payload = verifyAccessToken(token);
  if (!payload) { ws.close(); return; }
  const username = payload.username;
  ws.username = username;
  ws.room = room;

  sessions.set(username, ws);
  if (!roomClients.has(room)) roomClients.set(room, new Set());
  roomClients.get(room).add(ws);

  const usersInRoom = Array.from(roomClients.get(room)).map(c => c.username).filter(Boolean);
  ws.send(JSON.stringify({ type: 'joined', users: usersInRoom, room }));
  broadcastToRoom(room, { type: 'presence', users: usersInRoom }, ws);

  ws.on('message', (data) => {
    let msg;
    try { msg = JSON.parse(data); } catch { return; }
    // Relay all messages – we never decrypt
    broadcastToRoom(room, { ...msg, sender: username }, ws);
  });

  ws.on('close', () => {
    sessions.delete(username);
    if (roomClients.has(room)) {
      roomClients.get(room).delete(ws);
      if (roomClients.get(room).size === 0) roomClients.delete(room);
    }
    const remaining = roomClients.get(room);
    if (remaining) {
      const usersLeft = Array.from(remaining).map(c => c.username).filter(Boolean);
      broadcastToRoom(room, { type: 'presence', users: usersLeft }, null);
    }
  });
});

function broadcastToRoom(room, msg, exclude) {
  const clients = roomClients.get(room);
  if (!clients) return;
  const payload = JSON.stringify(msg);
  clients.forEach(client => {
    if (client !== exclude && client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  });
}

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});