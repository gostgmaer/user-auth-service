// src/config/db.js
const mongoose = require('mongoose');
const logger = require('../utils/logger');
const env    = require('./env');

const TENANCY_MODE = env.TENANCY_MODE;
const connections = new Map();

// ─── Shared mode ──────────────────────────────────────────────────────────────
const connectDB = async () => {
  const uri = env.MONGO_URI;
  const maxRetries = 5;
  let attempt = 0;

  while (attempt < maxRetries) {
    try {
      await mongoose.connect(uri, {
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS:          45000,
        connectTimeoutMS:         10000,
        maxPoolSize:              20,
        minPoolSize:              2,
      });
      logger.info('MongoDB connected (shared mode)');
      return;
    } catch (err) {
      attempt++;
      logger.warn(`MongoDB connection attempt ${attempt}/${maxRetries} failed: ${err.message}`);
      if (attempt < maxRetries) {
        await new Promise((resolve) => setTimeout(resolve, 2000 * attempt));
      } else {
        logger.error('MongoDB connection failed after max retries');
        throw err;
      }
    }
  }
};

const disconnectDB = async () => {
  if (TENANCY_MODE === 'per-db') {
    for (const [, conn] of connections) {
      await conn.close().catch(() => {});
    }
    connections.clear();
  } else {
    await mongoose.disconnect();
  }
  logger.info('MongoDB disconnected');
};

// ─── Per-DB mode ───────────────────────────────────────────────────────────────
const getTenantConnection = async (tenantId) => {
  if (connections.has(tenantId)) return connections.get(tenantId);
  const uri = env.MONGO_URI.replace('{tenant}', tenantId);
  const conn = await mongoose.createConnection(uri, {
    serverSelectionTimeoutMS: 5000,
  }).asPromise();
  connections.set(tenantId, conn);
  logger.info(`MongoDB per-tenant connection established for: ${tenantId}`);
  return conn;
};

const isConnected = () => {
  if (TENANCY_MODE === 'per-db') return connections.size > 0;
  return mongoose.connection.readyState === 1;
};

module.exports = { connectDB, disconnectDB, getTenantConnection, isConnected };
