// src/middleware/sanitization.js
/**
 * XSS + NoSQL injection sanitization.
 * Strips HTML tags and removes MongoDB operator keys ($ and .)
 * from body/query/params recursively.
 */

const sanitizeString = (input) => {
  if (typeof input !== 'string') return input;
  return input
    .trim()
    .replace(/[<>]/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '');
};

const removeMongoOperators = (obj) => {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return obj;
  if (Array.isArray(obj))    return obj.map(removeMongoOperators);
  if (typeof obj === 'object') {
    return Object.keys(obj).reduce((acc, key) => {
      if (key.startsWith('$') || key.includes('.')) return acc; // strip NoSQL operators
      acc[key] = removeMongoOperators(obj[key]);
      return acc;
    }, {});
  }
  return obj;
};

const sanitizeObject = (obj) => {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return sanitizeString(obj);
  if (Array.isArray(obj))     return obj.map(sanitizeObject);
  if (typeof obj === 'object') {
    return Object.fromEntries(
      Object.entries(obj).map(([k, v]) => [k, sanitizeObject(v)])
    );
  }
  return obj;
};

const sanitizeInput = (req, res, next) => {
  // Apply both NoSQL stripping and XSS sanitization
  if (req.body   && typeof req.body   === 'object') req.body   = removeMongoOperators(sanitizeObject(req.body));
  if (req.query  && typeof req.query  === 'object') req.query  = removeMongoOperators(sanitizeObject(req.query));
  if (req.params && typeof req.params === 'object') req.params = removeMongoOperators(sanitizeObject(req.params));
  next();
};

module.exports = { sanitizeInput };
