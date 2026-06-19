const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const User = require('./models/User');

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
      const payload = jwt.verify(cookies.token, process.env.JWT_SECRET);
      // Load profile bits (color + avatar presence) without the avatar bytes.
      const u = await User.findByPk(payload.id, { attributes: ['color', 'updatedAt', 'avatarType', 'tokenVersion'] });
      // Reject sessions revoked by a password change (same check as REST).
      if (!u || (u.tokenVersion || 0) !== (payload.tv || 0)) return next(new Error('unauthorized'));
      socket.data.user = {
        id: payload.id,
        email: payload.email,
        color: (u && u.color) || null,
        hasAvatar: !!(u && u.avatarType),
        avatarVersion: u && u.updatedAt ? new Date(u.updatedAt).getTime() : 0,
      };
      next();
    } catch (_) {
      next(new Error('unauthorized'));
    }
  });

  io.on('connection', (socket) => {
    let room = null;

    socket.on('join', (projectId) => {
      if (!projectId) return;
      if (room) { socket.leave(room); emitPresence(io, room); }
      room = roomOf(projectId);
      socket.data.focus = null;
      socket.join(room);
      emitPresence(io, room);
    });

    socket.on('leave', () => {
      if (!room) return;
      const prev = room;
      socket.leave(room);
      socket.data.focus = null;
      room = null;
      emitPresence(io, prev);
    });

    // What the user is currently editing, e.g. "item:<id>" or "variables".
    socket.on('focus', (field) => {
      socket.data.focus = field || null;
      if (room) emitPresence(io, room);
    });

    // The user changed their profile (color / avatar) — refresh presence live.
    socket.on('profile', (p) => {
      if (p && typeof p === 'object') {
        if (typeof p.color === 'string' || p.color === null) socket.data.user.color = p.color || null;
        socket.data.user.hasAvatar = !!p.hasAvatar;
        socket.data.user.avatarVersion = Date.now();
      }
      if (room) emitPresence(io, room);
    });

    socket.on('disconnect', () => {
      if (room) emitPresence(io, room);
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

module.exports = { initRealtime, broadcast };
