// src/routes/healthRoutes.js
'use strict';

const express = require('express');
const mongoose = require('mongoose');
const { isRedisReady } = require('../config/redis');
const env = require('../config/env');

const router = express.Router();

const startedAt = new Date();

router.get('/', (req, res) => {
  res.status(200).json({
    status:  'ok',
    service: 'user-auth-service',
    version: process.env.npm_package_version || '1.0.0',
    uptime:  Math.floor(process.uptime()),
    startedAt,
  });
});

// Kubernetes liveness probe
router.get('/live', (req, res) => {
  res.status(200).json({ status: 'alive' });
});

// Kubernetes readiness probe
router.get('/ready', async (req, res) => {
  const mongoState = mongoose.connection.readyState; // 0=disconnected,1=connected,2=connecting,3=disconnecting
  const mongoOk   = mongoState === 1;
  const redisOk   = await isRedisReady();

  const checks = {
    mongo: mongoOk ? 'ok' : 'unavailable',
    redis: env.TOKEN_REVOCATION_STORE === 'redis'
      ? (redisOk ? 'ok' : 'unavailable')
      : 'not_required',
  };

  const isReady = mongoOk && (env.TOKEN_REVOCATION_STORE !== 'redis' || redisOk);
  return res.status(isReady ? 200 : 503).json({
    status: isReady ? 'ready' : 'not_ready',
    checks,
    uptime: Math.floor(process.uptime()),
  });
});

module.exports = router;
