// Express 4 does not catch rejected promises from async handlers: the request
// hangs and Node (>= 15) treats the unhandled rejection as fatal, so a single
// request that makes a DB call throw (e.g. a malformed value) could crash the
// whole server. Route every handler's rejection to next(err) instead, so the
// central error handler answers 500 and the process keeps running.
//
// Same approach as the `express-async-errors` package, without the dependency.
// Must be required before any router is created.
const Layer = require('express/lib/router/layer');

Layer.prototype.handle_request = function handleRequest(req, res, next) {
  const fn = this.handle;
  if (fn.length > 3) return next(); // error-handling middleware: skipped here
  try {
    const ret = fn(req, res, next);
    if (ret && typeof ret.catch === 'function') ret.catch(next);
  } catch (err) {
    next(err);
  }
  return undefined;
};
