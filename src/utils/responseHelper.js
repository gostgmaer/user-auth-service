// src/utils/responseHelper.js
const { HTTP_STATUS, ERROR_CODES } = require('./appError');

/**
 * Recursively transform response data:
 *  - Renames `_id` → `id` (as string)
 *  - Removes `__v`
 * Handles Mongoose documents (via toJSON), plain objects, and arrays.
 */
const serialize = (val) => {
  if (val === null || val === undefined) return val;
  if (typeof val !== 'object') return val;
  if (val instanceof Date) return val;
  if (Buffer.isBuffer(val)) return val;
  if (Array.isArray(val)) return val.map(serialize);

  // Let Mongoose docs/subdocs serialize via toJSON (respects schema virtuals)
  const src = typeof val.toJSON === 'function' ? val.toJSON() : val;
  // If toJSON returned a primitive (e.g. ObjectId → hex string), return as-is
  if (typeof src !== 'object' || src === null) return src;

  const out = {};
  for (const key of Object.keys(src)) {
    if (key === '__v' || key === '_id' || key === 'id') continue; // handled below
    out[key] = serialize(src[key]);
  }
  // Set `id`: prefer existing string virtual, else stringify _id
  const rawId = src.id !== undefined ? src.id : src._id;
  if (rawId !== undefined) out.id = String(rawId);

  return out;
};

const sendSuccess = (res, message = 'Success', data = null, statusCode = HTTP_STATUS.OK) => {
  const response = { success: true, message };
  if (data !== null && data !== undefined) response.data = serialize(data);
  return res.status(statusCode).json(response);
};

const sendCreated = (res, message = 'Created successfully', data = null) =>
  sendSuccess(res, message, data, HTTP_STATUS.CREATED);

const sendError = (res, message = 'Internal server error', statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR, code = ERROR_CODES.INTERNAL_ERROR, details = null, hint = null) => {
  const err = { code };
  if (details) err.details = details;
  if (hint) err.hint = hint;
  return res.status(statusCode).json({ success: false, message, error: err });
};

const sendPaginated = (res, message = 'Data retrieved successfully', data = null, total = 0, page = 1, limit = 20) => {
  const totalPages = Math.ceil(total / limit);
  const response = {
    success: true,
    message,
    pagination: { page, pageSize: limit, totalRecords: total, totalPages, hasNext: page < totalPages, hasPrev: page > 1 },
  };
  if (data !== null && data !== undefined) response.data = serialize(data);
  return res.status(HTTP_STATUS.OK).json(response);
};

const sendNoContent = (res) => res.status(HTTP_STATUS.NO_CONTENT).send();

module.exports = {
  sendSuccess, sendCreated, sendError, sendPaginated, sendNoContent,
  HTTP_STATUS, ERROR_CODES, serialize,
};
