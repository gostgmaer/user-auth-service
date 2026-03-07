// src/utils/responseHelper.js
const { HTTP_STATUS, ERROR_CODES } = require('./appError');

const sendSuccess = (res, message = 'Success', data = null, statusCode = HTTP_STATUS.OK, meta = null) => {
  const response = { success: true, statusCode, message };
  if (data !== null) response.data = data;
  if (meta !== null) response.meta = meta;
  return res.status(statusCode).json(response);
};

const sendCreated = (res, message = 'Created successfully', data = null) =>
  sendSuccess(res, message, data, HTTP_STATUS.CREATED);

const sendError = (res, message = 'Internal server error', statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR, code = ERROR_CODES.INTERNAL_ERROR, errors = null) => {
  const response = { success: false, statusCode, message, error: { code } };
  if (errors) response.error.errors = errors;
  return res.status(statusCode).json(response);
};

const sendPaginated = (res, message = 'Data retrieved successfully', data = null, total = 0, page = 1, limit = 20) => {
  const totalPages = Math.ceil(total / limit);
  return sendSuccess(res, message, data, HTTP_STATUS.OK, { page, limit, total, totalPages });
};

const sendNoContent = (res) => res.status(HTTP_STATUS.NO_CONTENT).send();

module.exports = {
  sendSuccess, sendCreated, sendError, sendPaginated, sendNoContent,
  HTTP_STATUS, ERROR_CODES,
};
