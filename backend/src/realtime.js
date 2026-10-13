const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const { isUuid } = require('./config/db');
const { accessLevelById } = require('./lib/projectAccess');

// Minimal cookie header parser (avoids pulling an extra dependency).
function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i === -1) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

const roomOf = (projectId) => `project:${projectId}`;
// Every socket also sits in a per-user room, so a session revocation can reach
// all of that user's open connections at once.
const userRoom = (userId) => `user:${userId}`;

// Profile bits shown in presence (color + avatar presence), without the bytes.
const loadProfile = (id) =>
  User.findByPk(id, { attributes: ['id', 'email', 'role', 'color', 'updatedAt', 'avatarType', 'tokenVersion'] });

const profileOf = (u) => ({
  id: u.id,
  email: u.email,
  role: u.role, // server-side only (presence never sends it)
  color: u.color || null,
  hasAvatar: !!u.avatarType,
  avatarVersion: u.updatedAt ? new Date(u.updatedAt).getTime() : 0,
});

// Broadcast the live list of users present in a room (with what they focus).
function emitPresence(io, room) {
  const ids = io.sockets.adapter.rooms.get(room);
  const users = [];
  if (ids) {
    for (const id of ids) {
      const s = io.sockets.sockets.get(id);
      if (s && s.data.user) {
        users.push({
          socketId: id,
          id: s.data.user.id,
          email: s.data.user.email,
          color: s.data.user.color || null,
          hasAvatar: !!s.data.user.hasAvatar,
          avatarVersion: s.data.user.avatarVersion || 0,
          focus: s.data.focus || null,
        });
      }
    }
  }
  io.to(room).emit('presence', users);
}

// Take a socket out of its project room and refresh that room's presence.
function leaveRoom(io, socket) {
  const prev = socket.data.room;
  if (!prev) return;
  socket.leave(prev);
  socket.data.room = null;
  socket.data.focus = null;
  emitPresence(io, prev);
}

// Attach Socket.IO to the HTTP server. Returns the io instance so REST routes
// can broadcast data changes (see app.set('io', io)).
function initRealtime(server) {
  const io = new Server(server, { path: '/socket.io' });

  // Reject cross-origin WebSocket handshakes (cross-site WebSocket hijacking is
  // a cookie-borne sibling of CSRF). Browsers always send Origin on a WS upgrade;
  // a non-browser client without Origin is allowed through to the auth check.
  io.use((socket, next) => {
    const origin = socket.handshake.headers.origin;
    if (!origin) return next();
    try {
      if (new URL(origin).host === socket.handshake.headers.host) return next();
    } catch (_) { /* malformed Origin — fall through to reject */ }
    next(new Error('forbidden origin'));
  });

  // Authenticate every socket from the signed JWT cookie (same as REST).
  io.use(async (socket, next) => {
    try {
      const cookies = parseCookies(socket.handshake.headers.cookie);
      const payload = jwt.verify(cookies.token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
      // Reject sessions revoked by a password change or logout (same check as REST).
      const u = await loadProfile(payload.id);
      if (!u || (u.tokenVersion || 0) !== (payload.tv || 0)) return next(new Error('unauthorized'));
      socket.data.user = profileOf(u);
      socket.data.tv = payload.tv || 0;
      socket.data.exp = payload.exp;
      next();
    } catch (_) {
      next(new Error('unauthorized'));
    }
  });

  // Re-check that the session behind a socket is still valid (account exists,
  // token version unchanged) and refresh its role/profile. Disconnects and
  // returns false otherwise.
  async function revalidate(socket) {
    try {
      const u = await loadProfile(socket.data.user.id);
      if (u && (u.tokenVersion || 0) === socket.data.tv) {
        socket.data.user = profileOf(u);
        return true;
      }
    } catch (_) { /* treat as revoked */ }
    socket.disconnect(true);
    return false;
  }

  io.on('connection', (socket) => {
    socket.data.room = null;
    socket.data.seq = 0;
    socket.join(userRoom(socket.data.user.id));

    // The connection must not outlive the session token it was opened with.
    const ttl = socket.data.exp ? socket.data.exp * 1000 - Date.now() : 0;
    const expiry = ttl > 0 ? setTimeout(() => socket.disconnect(true), Math.min(ttl, 2 ** 31 - 1)) : null;

    // Join a project room — only for the project's owner, its invited
    // collaborators, or an admin (same rule as the REST API). The session is
    // re-validated first, so a socket opened before a revocation cannot
    // subscribe to anything new.
    socket.on('join', async (projectId) => {
      if (!isUuid(projectId)) return;
      // Checks are async: only the latest join/leave may take effect.
      const seq = ++socket.data.seq;
      if (!(await revalidate(socket))) return;
      let level = null;
      try { level = await accessLevelById(socket.data.user, projectId); } catch (_) { /* deny */ }
      if (seq !== socket.data.seq) return;
      if (socket.data.room) leaveRoom(io, socket);
      if (!level) {
        socket.emit('project:revoked', { projectId: String(projectId) });
        return;
      }
      socket.data.room = roomOf(projectId);
      socket.data.focus = null;
      socket.join(socket.data.room);
      emitPresence(io, socket.data.room);
    });

    socket.on('leave', () => { socket.data.seq += 1; leaveRoom(io, socket); });

    // What the user is currently editing, e.g. "item:<id>" or "variables".
    socket.on('focus', (field) => {
      socket.data.focus = typeof field === 'string' ? field.slice(0, 64) : null;
      if (socket.data.room) emitPresence(io, socket.data.room);
    });

    // The user changed their profile (color / avatar) — refresh presence live.
    // The new values are re-read from the database (already validated by
    // PATCH /api/auth/me), never taken from the client message.
    socket.on('profile', async () => {
      if (!(await revalidate(socket))) return;
      if (socket.data.room) emitPresence(io, socket.data.room);
    });

    socket.on('disconnect', () => {
      if (expiry) clearTimeout(expiry);
      if (socket.data.room) emitPresence(io, socket.data.room);
    });
  });

  return io;
}

// Helper used by REST routes to push a change to everyone on a project.
function broadcast(app, projectId, event, payload, originSocketId) {
  const io = app.get('io');
  if (!io) return;
  io.to(roomOf(projectId)).emit(event, { projectId: String(projectId), ...payload, originSocketId: originSocketId || null });
}

// Close every open connection of a user. Called whenever their sessions are
// revoked (logout, password change/reset, role change, account deletion) so
// the live feed stops at once instead of when the tab is closed. A client
// whose cookie is still valid reconnects on its own.
function disconnectUser(app, userId) {
  const io = app.get('io');
  if (io && userId) io.in(userRoom(userId)).disconnectSockets(true);
}

// Remove a user's sockets from one project room (access withdrawn) and tell
// them, so their open view closes.
function evictFromProject(app, projectId, userId) {
  const io = app.get('io');
  if (!io) return;
  const room = roomOf(projectId);
  for (const s of io.sockets.sockets.values()) {
    if (s.data.user && s.data.user.id === userId && s.data.room === room) {
      leaveRoom(io, s);
      s.emit('project:revoked', { projectId: String(projectId) });
    }
  }
}

// Empty a project's room (project deleted).
function closeProjectRoom(app, projectId) {
  const io = app.get('io');
  if (!io) return;
  const room = roomOf(projectId);
  for (const s of io.sockets.sockets.values()) {
    if (s.data.room === room) { s.leave(room); s.data.room = null; s.data.focus = null; }
  }
}

module.exports = { initRealtime, broadcast, disconnectUser, evictFromProject, closeProjectRoom };
