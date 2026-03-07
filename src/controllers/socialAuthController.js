// src/controllers/socialAuthController.js
'use strict';

const { v4: uuidv4 }    = require('uuid');
const User               = require('../models/User');
const Role               = require('../models/Role');
const { generateTokens, setCookiesOnHeader, expiryToSeconds } = require('../services/tokenService');
const { SUPPORTED_PROVIDERS, isSupportedProvider } = require('../services/socialProvider');
const DeviceDetector     = require('../services/deviceDetector');
const activityLog        = require('../services/activityLogService');
const emailNotifier      = require('../services/emailNotifier');
const emailPayloads      = require('../email/emailPayloads');
const AppError           = require('../utils/appError');
const { sendSuccess, sendCreated } = require('../utils/responseHelper');
const { sanitizeUser }   = require('../utils/helper');
const { hashToken }      = require('../utils/security');
const jwtConfig          = require('../config/jwt');
const axios              = require('axios');

const expiryToMs = (expiry) => expiryToSeconds(expiry) * 1000;

// ─── Provider token verifiers ──────────────────────────────────────────────────

const VERIFIERS = {
  google: async (accessToken) => {
    const { data } = await axios.get('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    return {
      providerId:    data.sub,
      email:         data.email,
      emailVerified: data.email_verified,
      name:          data.name,
      firstName:     data.given_name,
      lastName:      data.family_name,
      profilePicture: data.picture,
    };
  },

  facebook: async (accessToken) => {
    const { data } = await axios.get('https://graph.facebook.com/me', {
      params: { fields: 'id,name,email,picture,first_name,last_name', access_token: accessToken },
    });
    return {
      providerId:     data.id,
      email:          data.email || null,
      emailVerified:  !!data.email,
      name:           data.name,
      firstName:      data.first_name,
      lastName:       data.last_name,
      profilePicture: data.picture?.data?.url || null,
    };
  },

  github: async (accessToken) => {
    const [{ data: profile }, { data: emails }] = await Promise.all([
      axios.get('https://api.github.com/user', { headers: { Authorization: `Bearer ${accessToken}` } }),
      axios.get('https://api.github.com/user/emails', { headers: { Authorization: `Bearer ${accessToken}` } }),
    ]);
    const primaryEmail = emails.find((e) => e.primary && e.verified)?.email || profile.email;
    const [firstName, ...lastParts] = (profile.name || profile.login).split(' ');
    return {
      providerId:    String(profile.id),
      email:         primaryEmail,
      emailVerified: true,
      name:          profile.name || profile.login,
      firstName,
      lastName:      lastParts.join(' ') || null,
      profilePicture: profile.avatar_url,
    };
  },

  discord: async (accessToken) => {
    const { data } = await axios.get('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const avatar = data.avatar
      ? `https://cdn.discordapp.com/avatars/${data.id}/${data.avatar}.png`
      : null;
    const [firstName, ...lastParts] = (data.global_name || data.username).split(' ');
    return {
      providerId:     data.id,
      email:          data.email || null,
      emailVerified:  data.verified || false,
      name:           data.global_name || data.username,
      firstName,
      lastName:       lastParts.join(' ') || null,
      profilePicture: avatar,
    };
  },

  microsoft: async (accessToken) => {
    const { data } = await axios.get('https://graph.microsoft.com/v1.0/me', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    return {
      providerId:    data.id,
      email:         data.mail || data.userPrincipalName,
      emailVerified: true,
      name:          data.displayName,
      firstName:     data.givenName,
      lastName:      data.surname,
      profilePicture: null,
    };
  },

  linkedin: async (accessToken) => {
    const [{ data: profile }, { data: emailData }] = await Promise.all([
      axios.get('https://api.linkedin.com/v2/userinfo', { headers: { Authorization: `Bearer ${accessToken}` } }).catch(() => ({ data: {} })),
      axios.get('https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))', {
        headers: { Authorization: `Bearer ${accessToken}` },
      }).catch(() => ({ data: { elements: [] } })),
    ]);
    const email = profile.email || emailData.elements?.[0]?.['handle~']?.emailAddress;
    return {
      providerId:     profile.sub || profile.id,
      email,
      emailVerified:  true,
      name:           profile.name,
      firstName:      profile.given_name,
      lastName:       profile.family_name,
      profilePicture: profile.picture || null,
    };
  },

  apple: async (accessToken) => {
    // Apple Sign In: validate id_token against Apple's public keys for full security.
    // SECURITY NOTE: Full RS256 signature verification requires fetching Apple's JWKS from
    // https://appleid.apple.com/auth/keys and verifying with jsonwebtoken.
    // The current implementation validates issuer and structure but NOT the signature.
    // For production, add: npm install jwks-rsa and verify signature using Apple's public key.
    const parts = accessToken.split('.');
    if (parts.length !== 3) throw new Error('Invalid Apple identity token');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (payload.iss !== 'https://appleid.apple.com')
      throw new Error('Invalid Apple identity token issuer');
    if (payload.exp < Math.floor(Date.now() / 1000))
      throw new Error('Apple identity token has expired');
    return {
      providerId:    payload.sub,
      email:         payload.email || null,
      emailVerified: !!payload.email_verified,
      name:          null,
      firstName:     null,
      lastName:      null,
      profilePicture: null,
    };
  },

  twitter: async (accessToken) => {
    // OAuth2 user context
    const { data } = await axios.get('https://api.twitter.com/2/users/me?user.fields=name,profile_image_url', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const [firstName, ...lastParts] = (data.data.name || data.data.username).split(' ');
    return {
      providerId:     data.data.id,
      email:          null, // Twitter doesn't return email in basic OAuth2
      emailVerified:  false,
      name:           data.data.name,
      firstName,
      lastName:       lastParts.join(' ') || null,
      profilePicture: data.data.profile_image_url,
    };
  },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

const buildSession = (deviceInfo) => ({
  sessionId:    uuidv4(),
  deviceId:     deviceInfo.deviceId || uuidv4(),
  deviceInfo: {
    browser: deviceInfo.browser?.name,
    os:      deviceInfo.os?.name,
    type:    deviceInfo.device?.type || 'desktop',
    ip:      deviceInfo.ipAddress,
  },
  createdAt:    new Date(),
  lastActivity: new Date(),
  expiresAt:    new Date(Date.now() + expiryToMs(jwtConfig.refreshExpiry)),
  ipAddress:    deviceInfo.ipAddress,
  userAgent:    deviceInfo.userAgent,
  isActive:     true,
});

const verifyProviderToken = async (provider, accessToken) => {
  const verifier = VERIFIERS[provider];
  if (!verifier) throw AppError.badRequest(`Unsupported provider: ${provider}`);
  try {
    return await verifier(accessToken);
  } catch (err) {
    if (err instanceof AppError) throw err;
    throw AppError.unauthorized(`Failed to verify ${provider} token: ${err.message}`);
  }
};

// ─── Social Login / Register ──────────────────────────────────────────────────

exports.socialLogin = async (req, res, next) => {
  const { provider, accessToken } = req.body;
  const tenantId = req.tenantId;
  if (!provider || !accessToken) return next(AppError.badRequest('provider and accessToken are required'));
  if (!isSupportedProvider(provider)) return next(AppError.badRequest(`Unsupported provider: ${provider}`));

  const deviceInfo  = DeviceDetector.detectDevice(req);
  let providerUser;
  try {
    providerUser = await verifyProviderToken(provider, accessToken);
  } catch (err) {
    return next(err);
  }

  if (!providerUser.providerId) return next(AppError.unauthorized('Could not retrieve profile from provider'));

  // Look up by social account first
  let user = await User.findOne({
    tenantId,
    socialAccounts: { $elemMatch: { provider, providerId: providerUser.providerId } },
  });

  const isNewUser = !user;

  if (!user && providerUser.email) {
    // Try to link to existing account with same email
    user = await User.findOne({ tenantId, email: providerUser.email.toLowerCase() });
    if (user) {
      // Link social account to existing user
      user.socialAccounts.push({
        provider,
        providerId:  providerUser.providerId,
        displayName: providerUser.name,
        email:       providerUser.email,
        avatar:      providerUser.profilePicture || null,
        connectedAt: new Date(),
      });
    }
  }

  if (!user) {
    // Create new user from social profile
    const baseUsername = (providerUser.name || providerUser.email || provider)
      .toLowerCase().replace(/[^a-z0-9]/g, '_').slice(0, 30);
    let username = baseUsername;
    let attempt = 0;
    while (await User.findOne({ tenantId, username })) {
      username = `${baseUsername}_${++attempt}`;
    }

    const defaultRole = await Role.findOne({ tenantId, name: 'user', isActive: true, isDeleted: false });

    user = new User({
      tenantId,
      email:         providerUser.email?.toLowerCase() || null,
      username,
      firstName:     providerUser.firstName,
      lastName:      providerUser.lastName,
      profilePicture: { url: providerUser.profilePicture || null },
      emailVerified: providerUser.emailVerified,
      isVerified:    providerUser.emailVerified,
      status:        providerUser.emailVerified ? 'active' : 'pending',
      isActive:      true,
      hash_password: null, // social-only accounts have no password
      role:          defaultRole?._id || null,
      socialAccounts: [{
        provider,
        providerId:  providerUser.providerId,
        displayName: providerUser.name,
        email:       providerUser.email,
        avatar:      providerUser.profilePicture || null,
        connectedAt: new Date(),
      }],
    });
    activityLog.logRegistration(user, req);
    if (providerUser.email) {
      emailNotifier.send(emailPayloads.emailVerified(user));
    }
  } else {
    // Update social account access token
    const existingAccount = user.socialAccounts.find(
      (a) => a.provider === provider && a.providerId === providerUser.providerId
    );
    if (existingAccount) {
      existingAccount.accessToken = accessToken;
      existingAccount.lastUsed    = new Date();
    }
  }

  // Account status checks
  if (user.isDeleted || !user.isActive || user.status === 'banned')
    return next(AppError.unauthorized('Account is not accessible'));
  if (user.status === 'suspended')
    return next(AppError.forbidden('Account has been suspended'));

  // Issue tokens
  const session = buildSession(deviceInfo);
  user.activeSessions.push(session);

  // Populate role for token generation (may not be populated on newly created user)
  if (user.role && !user.role.name) await user.populate('role');

  const { accessToken: jwt, refreshJti, refreshToken, idToken } = generateTokens(user, session.sessionId);
  user.refreshTokens.push({
    jti: hashToken(refreshJti), createdAt: new Date(), expiresAt: session.expiresAt,
    userAgent: deviceInfo.userAgent, ipAddress: deviceInfo.ipAddress, isActive: true,
  });
  await user.save();

  setCookiesOnHeader(res, jwt, refreshToken, idToken);
  activityLog.logLogin(user, req, session.sessionId, provider);

  const status = isNewUser ? 201 : 200;
  return res.status(status).json({
    success: true,
    message: isNewUser ? 'Account created via social login' : 'Login successful',
    data: { accessToken: jwt, user: sanitizeUser(user), isNewUser },
  });
};

// ─── Link Social Account ──────────────────────────────────────────────────────

exports.linkSocialAccount = async (req, res, next) => {
  const { provider, accessToken } = req.body;
  const tenantId = req.tenantId;
  if (!provider || !accessToken) return next(AppError.badRequest('provider and accessToken are required'));
  if (!isSupportedProvider(provider)) return next(AppError.badRequest(`Unsupported provider: ${provider}`));

  let providerUser;
  try {
    providerUser = await verifyProviderToken(provider, accessToken);
  } catch (err) {
    return next(err);
  }

  // Check not already linked to another account
  const existingLink = await User.findOne({
    tenantId,
    socialAccounts: { $elemMatch: { provider, providerId: providerUser.providerId } },
  });
  if (existingLink && existingLink._id.toString() !== req.user._id.toString()) {
    return next(AppError.conflict(`This ${provider} account is already linked to another user`));
  }

  const user = await User.findOne({ _id: req.user._id, tenantId });
  if (!user) return next(AppError.notFound('User not found'));

  const alreadyLinked = user.socialAccounts.find((a) => a.provider === provider && a.isActive);
  if (alreadyLinked) return next(AppError.conflict(`A ${provider} account is already linked. Unlink it first.`));

  user.socialAccounts.push({
    provider,
    providerId:  providerUser.providerId,
    displayName: providerUser.name,
    email:       providerUser.email,
    avatar:      providerUser.profilePicture || null,
    connectedAt: new Date(),
  });
  await user.save();
  emailNotifier.send(emailPayloads.socialLoginConnected(user, provider));
  return sendSuccess(res, `${provider} account linked`);
};

// ─── Unlink Social Account ────────────────────────────────────────────────────

exports.unlinkSocialAccount = async (req, res, next) => {
  const { provider } = req.params;
  const tenantId     = req.tenantId;

  const user = await User.findOne({ _id: req.user._id, tenantId });
  if (!user) return next(AppError.notFound('User not found'));

  // Ensure user can still log in after unlinking
  const hasPassword = !!user.hash_password;
  const linkedCount = user.socialAccounts.filter((a) => a.isActive).length;
  if (!hasPassword && linkedCount <= 1) {
    return next(AppError.badRequest('Cannot unlink the only login method. Set a password first.'));
  }

  const account = user.socialAccounts.find((a) => a.provider === provider && a.isActive);
  if (!account) return next(AppError.notFound(`No linked ${provider} account found`));

  account.isActive  = false;
  account.revokedAt = new Date();
  await user.save();
  emailNotifier.send(emailPayloads.socialLoginDisconnected(user, provider));
  return sendSuccess(res, `${provider} account unlinked`);
};

// ─── List Social Accounts ─────────────────────────────────────────────────────

exports.listSocialAccounts = async (req, res, next) => {
  const user = await User.findOne({ _id: req.user._id, tenantId: req.tenantId });
  const accounts = (user?.socialAccounts || [])
    .filter((a) => !a.revokedAt)
    .map(({ provider, displayName, email, avatar, connectedAt }) => ({
      provider, displayName, email, avatar, connectedAt,
    }));
  return sendSuccess(res, 'Linked social accounts', accounts);
};
