// src/config/db.js
const mongoose = require('mongoose');
const logger = require('../utils/logger');
const env    = require('./env');

const TENANCY_MODE = env.TENANCY_MODE;
const connections = new Map();

// ─── Mongoose global settings ─────────────────────────────────────────────────
// In production, disable auto-index creation — indexes should be pre-created via migrations.
// bufferCommands: false makes commands fail immediately if the connection is down
// instead of queuing indefinitely (prevents memory leaks under heavy load).
mongoose.set('autoIndex',    !env.IS_PROD);
mongoose.set('bufferCommands', false);

// ─── Connection options (shared across all connections) ───────────────────────
const CONNECTION_OPTIONS = {
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS:          45000,
  connectTimeoutMS:         10000,
  maxPoolSize:              env.IS_PROD ? 50 : 20,  // Higher pool in production clusters
  minPoolSize:              env.IS_PROD ? 5  : 2,
  waitQueueTimeoutMS:       10000,
  heartbeatFrequencyMS:     10000,
  // Write concern: majority ensures the write is acknowledged by the replica set primary + majority of secondaries
  writeConcern: {
    w: env.IS_PROD ? 'majority' : 1,
    j: true,               // journaled writes only
    wtimeoutMS: 5000,
  },
};

// ─── Shared mode ──────────────────────────────────────────────────────────────
const connectDB = async () => {
  const uri = env.MONGO_URI;
  const maxRetries = 5;
  let attempt = 0;

  while (attempt < maxRetries) {
    try {
      await mongoose.connect(uri, CONNECTION_OPTIONS);

      // ── Connection event monitoring ─────────────────────────────────────────
      mongoose.connection.on('disconnected', () =>
        logger.warn('MongoDB disconnected — driver will attempt reconnect'));
      mongoose.connection.on('reconnected', () =>
        logger.info('MongoDB reconnected'));
      mongoose.connection.on('error', (err) =>
        logger.error('MongoDB connection error', { error: err.message }));

      logger.info('MongoDB connected (shared mode)', {
        host: mongoose.connection.host,
        port: mongoose.connection.port,
        name: mongoose.connection.name,
      });
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
