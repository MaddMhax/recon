const http = require('http');
const https = require('https');
const dns = require('dns');
const net = require('net');

// Outbound HTTP for admin-configured URLs (SSO endpoints). Those URLs are
// fetched by the server, so without limits an admin account — or whoever
// steals one — could make the app probe the internal network (database,
// cloud metadata at 169.254.169.254, services on localhost) and read back
// status codes and errors.
//
// Rules:
//   - https only;
//   - the destination must be a public address. The check runs on the address
//     actually connected to (custom DNS lookup), so DNS rebinding cannot slip
//     an internal IP in after validation;
//   - redirects are never followed (a public URL cannot bounce inward);
//   - bounded time and response size.
// Self-hosted providers on a private network (e.g. Keycloak on the LAN) are
// allowed explicitly via SSO_ALLOWED_HOSTS (comma-separated host names, or
// host:port); for those, plain http and private addresses are accepted.

const TIMEOUT_MS = 6000;
const MAX_BODY_BYTES = 1024 * 1024;

const blocked = new net.BlockList();
for (const [net4, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
]) blocked.addSubnet(net4, prefix, 'ipv4');
for (const [net6, prefix] of [
  ['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
  ['64:ff9b::', 96], ['2001:db8::', 32],
]) blocked.addSubnet(net6, prefix, 'ipv6');

function isBlockedAddress(address) {
  const family = net.isIP(address);
  if (family === 4) return blocked.check(address, 'ipv4');
  if (family === 6) {
    // IPv4-mapped IPv6 (::ffff:10.0.0.1) is the IPv4 address in disguise.
    const mapped = address.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    if (mapped) return blocked.check(mapped[1], 'ipv4');
    return blocked.check(address, 'ipv6');
  }
  return true;
}

function allowedHosts() {
  return (process.env.SSO_ALLOWED_HOSTS || '')
    .split(',').map((h) => h.trim().toLowerCase()).filter(Boolean);
}

// Is this URL's host explicitly allow-listed (by name or name:port)?
function isAllowListed(u) {
  const list = allowedHosts();
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  return list.includes(host) || list.includes(u.host.toLowerCase());
}

// Static validation (no network). Returns an error message, or null if the
// URL may be requested. Also used to reject bad values when saving the config.
function urlProblem(raw) {
  let u;
  try { u = new URL(String(raw)); } catch (_) { return 'URL invalide'; }
  if (u.username || u.password) return 'URL invalide (identifiants dans l\'URL)';
  const listed = isAllowListed(u);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && listed)) {
    return 'HTTPS requis (ou hôte autorisé via SSO_ALLOWED_HOSTS)';
  }
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (!listed && net.isIP(host) && isBlockedAddress(host)) return 'adresse interne interdite';
  if (!listed && /^(localhost|.*\.localhost|.*\.internal|.*\.local)$/i.test(host)) return 'adresse interne interdite';
  return null;
}

class SafeRequestError extends Error {}

// Request `url`; resolves to { status, ok, headers, text(), json() }.
// Rejects with SafeRequestError (policy) or a network error.
function safeRequest(url, { method = 'GET', headers = {}, body } = {}) {
  const problem = urlProblem(url);
  if (problem) return Promise.reject(new SafeRequestError(problem));
  const u = new URL(url);
  const listed = isAllowListed(u);
  const lib = u.protocol === 'https:' ? https : http;

  // Resolve, then refuse if any candidate address is internal (unless listed).
  const lookup = (hostname, opts, cb) => {
    dns.lookup(hostname, { all: true, family: opts && opts.family }, (err, addrs) => {
      if (err) return cb(err);
      if (!listed && addrs.some((a) => isBlockedAddress(a.address))) {
        return cb(new SafeRequestError('adresse interne interdite'));
      }
      if (opts && opts.all) return cb(null, addrs);
      return cb(null, addrs[0].address, addrs[0].family);
    });
  };

  const payload = body === undefined ? null : Buffer.from(typeof body === 'string' ? body : body.toString());
  const allHeaders = payload ? { ...headers, 'Content-Length': String(payload.length) } : headers;

  return new Promise((resolve, reject) => {
    const req = lib.request(u, { method, headers: allHeaders, lookup, timeout: TIMEOUT_MS }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > MAX_BODY_BYTES) { req.destroy(new SafeRequestError('réponse trop volumineuse')); return; }
        chunks.push(c);
      });
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        resolve({
          status: res.statusCode,
          ok: res.statusCode >= 200 && res.statusCode < 300,
          headers: res.headers,
          text: async () => buf.toString('utf8'),
          json: async () => JSON.parse(buf.toString('utf8')),
        });
      });
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new SafeRequestError('délai dépassé')));
    req.on('error', reject);
    req.end(payload || undefined);
  });
}

module.exports = { safeRequest, urlProblem, SafeRequestError };
