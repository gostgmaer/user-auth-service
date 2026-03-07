// src/routes/socialAuthRoutes.js
'use strict';

const express = require('express');
const ctrl    = require('../controllers/socialAuthController');
const asyncHandler = require('../utils/asyncHandler');
const { authMiddleware } = require('../middleware/auth');
const { loginLimiter }   = require('../middleware/rateLimit');

const router = express.Router();

// Public — social login/register (single endpoint)
router.post('/login', loginLimiter, asyncHandler(ctrl.socialLogin));

// Protected — manage linked accounts
router.use(authMiddleware);
router.get('/accounts',          asyncHandler(ctrl.listSocialAccounts));
router.post('/link',             asyncHandler(ctrl.linkSocialAccount));
router.delete('/unlink/:provider', asyncHandler(ctrl.unlinkSocialAccount));

module.exports = router;
