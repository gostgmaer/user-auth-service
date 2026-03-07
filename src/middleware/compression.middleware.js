// src/middleware/compression.middleware.js
const compression = require('compression');

const compressionMiddleware = compression({
  threshold: 1024,
  level: 6,
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    const ct = res.getHeader('Content-Type');
    if (ct) {
      const skip = ['image/', 'video/', 'audio/', 'application/zip', 'application/gzip'];
      if (skip.some((t) => String(ct).includes(t))) return false;
    }
    return compression.filter(req, res);
  },
  memLevel: 8,
});

module.exports = compressionMiddleware;
