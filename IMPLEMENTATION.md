# User Auth Service — Implementation Documentation

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Project Structure](#3-project-structure)
4. [Getting Started](#4-getting-started)
5. [Environment Variables](#5-environment-variables)
6. [API Reference](#6-api-reference)
7. [Authentication Flows](#7-authentication-flows)
8. [Multi-Tenancy](#8-multi-tenancy)
9. [Token Strategy](#9-token-strategy)
10. [Token Revocation](#10-token-revocation)
11. [Security Controls](#11-security-controls)
12. [OTP / MFA](#12-otp--mfa)
13. [Social Authentication](#13-social-authentication)
14. [Email Notifications](#14-email-notifications)
15. [Middleware Stack](#15-middleware-stack)
16. [Configuration Management](#16-configuration-management)
17. [Deployment](#17-deployment)
18. [Integration with dashboard-backend](#18-integration-with-dashboard-backend)
19. [Health Checks](#19-health-checks)
20. [Testing with Postman](#20-testing-with-postman)

---

## 1. Overview

`user-auth-service` is a self-contained Node.js/Express microservice that owns all identity and authentication concerns for the platform. It was extracted from the `dashboard-backend` monolith to:

- Be the **single issuer and validator** of JWTs for the platform
- Support **multi-tenant isolation** (one deployment serves many tenants)
- Be independently deployable, scalable, and testable
- Offload all email delivery to an external email microservice

**Runtime:** Node.js ≥ 20  
**Framework:** Express 5.x  
**Database:** MongoDB via Mongoose 8.x (Azure CosmosDB compatible)  
**Default port:** `4002`

---

## 2. Architecture

```
                    ┌──────────────────────────────────────────────┐
  Browser / App ───► API Gateway (injects X-Tenant-Id header)      │
                    └─────────────┬────────────────────────────────┘
                                  │
                    ┌─────────────▼────────────────────────────────┐
                    │          dashboard-backend                    │
                    │  authServiceProxy → /api/auth/*               │
                    │  axiosTokenVerify → GET /api/auth/token/verify│
                    └─────────────┬────────────────────────────────┘
                                  │ HTTP (port 4002)
                    ┌─────────────▼────────────────────────────────┐
                    │         user-auth-service                     │
                    │                                               │
                    │  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
                    │  │ Auth     │  │ Social   │  │  Admin    │  │
                    │  │ Routes   │  │ Auth     │  │  Routes   │  │
                    │  └────┬─────┘  └────┬─────┘  └─────┬─────┘  │
                    │       └────────────┬┘               │        │
                    │               Controllers            │        │
                    │       ┌────────────┴──────────────┐ │        │
                    │       │     authController         │ │        │
                    │       │     socialAuthController   │ │        │
                    │       │     adminAuthController    │ │        │
                    │       └────────────┬───────────────┘ │        │
                    │               Services                │        │
                    │  ┌──────────┐  ┌──────────┐  ┌────┐  │        │
                    │  │tokenSvc  │  │otpService│  │email│  │        │
                    │  │revokeScv │  │activityLog│  │Notif│  │        │
                    │  └──────────┘  └──────────┘  └────┘  │        │
                    └───────────────────┬──────────────────┘
                                        │
                       ┌────────────────┴──────────────┐
                       │                               │
              ┌────────▼──────┐             ┌─────────▼──────┐
              │   MongoDB      │             │  Redis (opt.)   │
              │ auth_service_db│             │ Token Blacklist  │
              └───────────────┘             └────────────────┘
                                                        │
                                             ┌──────────▼──────────┐
                                             │  Email Microservice  │
                                             │  POST /send-email    │
                                             └─────────────────────┘
```

---

## 3. Project Structure

```
user-auth-service/
├── server.js                     # Entry point — HTTP server + graceful shutdown
├── app.js                        # Express factory — middleware stack + route mounting
├── package.json
├── Dockerfile                    # Multi-stage, non-root alpine image
├── docker-compose.yml            # Service + MongoDB + Redis
├── .env.example                  # Reference env file
├── postman/
│   └── user-auth-service.postman_collection.json
└── src/
    ├── config/
    │   ├── validateEnv.js        # Joi schema — validates all env vars at startup (runs FIRST)
    │   ├── env.js                # Central config module — single source of truth for all vars
    │   ├── db.js                 # Mongoose connect/disconnect with exponential-backoff retry
    │   ├── jwt.js                # Re-exports env.jwt — consumed by tokenService
    │   └── redis.js              # Optional ioredis client (used when TOKEN_REVOCATION_STORE=redis)
    ├── models/
    │   ├── User.js               # Complete user model: sessions, devices, TOTP, social accounts
    │   ├── Role.js               # Role model for RBAC
    │   ├── Permission.js         # Granular resource+action permission model
    │   ├── LogEntry.js           # Auth event audit log
    │   └── TokenBlacklist.js     # Revoked JTIs with TTL auto-expiry index
    ├── services/
    │   ├── tokenService.js       # generateTokens(), setCookiesOnHeader(), verifyAccessToken()
    │   ├── tokenRevocationService.js  # revokeToken(), isTokenRevoked() — DB or Redis adapter
    │   ├── otpService.js         # TOTP/email/SMS OTP — generate, send, verify
    │   ├── activityLogService.js # logLogin(), logLogout(), logRegistration()
    │   ├── deviceDetector.js     # Browser/OS fingerprinting, suspicious-activity detection
    │   ├── socialProvider.js     # OAuth token validation per provider
    │   └── emailNotifier.js      # Fire-and-forget axios POST to email microservice
    ├── email/
    │   └── emailPayloads.js      # Payload builder functions for each auth email template
    ├── controllers/
    │   ├── authController.js     # All auth flows: register, login, password, MFA, GDPR
    │   ├── socialAuthController.js  # Social login/link/unlink
    │   └── adminAuthController.js   # Admin operations: users, sessions, logs, analytics
    ├── middleware/
    │   ├── tenant.js             # Extracts X-Tenant-Id → req.tenantId; validates format
    │   ├── auth.js               # JWT verification + blacklist check → req.user
    │   ├── rateLimit.js          # Named limiters: loginLimiter, registerLimiter, etc.
    │   ├── errorHandler.js       # Global error handler — AppError-aware, no stack in prod
    │   ├── authorize.js          # Permission-based authorization (resource + action)
    │   ├── roleCheck.js          # RBAC role check middleware factory
    │   ├── permission.js         # Granular permission checker
    │   ├── otpMiddleware.js      # Require OTP verification for sensitive operations
    │   ├── sanitization.js       # XSS strip + NoSQL operator removal
    │   ├── activityLogger.js     # Per-request activity logging
    │   ├── loggerMiddleware.js   # Structured HTTP logger with geolocation enrichment
    │   └── compression.middleware.js  # gzip (level 6) with bypass header support
    ├── routes/
    │   ├── authRoutes.js         # All /api/auth/* routes
    │   ├── socialAuthRoutes.js   # /api/auth/social/* routes
    │   ├── adminRoutes.js        # /api/admin/* routes
    │   └── healthRoutes.js       # /health, /health/live, /health/ready
    ├── validators/
    │   └── auth.js               # express-validator chains: register, login, password, profile
    └── utils/
        ├── appError.js           # AppError class + factory methods (unauthorized, forbidden…)
        ├── responseHelper.js     # sendSuccess(), sendCreated(), sendError()
        ├── helper.js             # decodeToken(), pagination helpers
        ├── security.js           # hashPassword(), verifyPassword(), hashToken(), timingSafeEqual()
        ├── asyncHandler.js       # Wraps async controllers — forwards errors to next()
        └── logger.js             # Winston logger (JSON in prod, colorized pretty in dev)
```

---

## 4. Getting Started

### Prerequisites

- Node.js ≥ 20
- npm ≥ 10
- MongoDB (local, Docker, or Azure CosmosDB)
- Redis (optional — only needed for `TOKEN_REVOCATION_STORE=redis`)

### Local Setup

```bash
# 1. Navigate to the service
cd c:\workSpace\Projects\Application\user-auth-service

# 2. Install dependencies
npm install

# 3. Configure environment
copy .env.example .env
# Edit .env with your values (see Environment Variables section)

# 4. Start in development mode (hot-reload via nodemon)
npm run dev

# 5. Verify the service is healthy
curl http://localhost:4002/health
```

### Docker (all-in-one)

```bash
docker compose up --build
```

This starts the auth service, MongoDB (port 27019), and Redis (port 6380).

---

## 5. Environment Variables

All variables are validated at startup by `src/config/validateEnv.js` using Joi. The service **refuses to start** if required variables are missing or invalid.

### Required

| Variable | Example | Description |
|---|---|---|
| `MONGO_URI` | `mongodb://localhost:27017/auth_service_db` | MongoDB connection string |
| `JWT_ACCESS_SECRET` | *(min 32 chars)* | HMAC secret for access tokens |
| `JWT_REFRESH_SECRET` | *(min 32 chars)* | HMAC secret for refresh tokens |
| `JWT_ID_SECRET` | *(min 32 chars)* | HMAC secret for ID tokens |
| `JWT_ISSUER` | `user-auth-service` | `iss` claim in every JWT |
| `JWT_AUDIENCE` | `dashboard-platform` | `aud` claim in every JWT |
| `TOTP_ISSUER` | `MyApp` | Displayed in authenticator app |
| `EMAIL_SERVICE_URL` | `http://localhost:4010` | Base URL of the email microservice |
| `CORS_ORIGIN` | `http://localhost:3000` | Allowed CORS origins (comma-separated) |

### Optional (with defaults)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `4002` | HTTP server port |
| `NODE_ENV` | `development` | `development` \| `production` \| `test` |
| `TENANCY_MODE` | `shared` | `shared` \| `per-db` |
| `BCRYPT_ROUNDS` | `12` | bcrypt cost factor (10–14) |
| `MAX_LOGIN_ATTEMPTS` | `5` | Failed logins before account lockout |
| `LOCK_WINDOW_MINUTES` | `15` | Lockout duration in minutes |
| `JWT_ACCESS_EXPIRY` | `1d` | Access token TTL |
| `JWT_REFRESH_EXPIRY` | `7d` | Refresh token TTL |
| `JWT_ID_EXPIRY` | `30d` | ID token TTL |
| `OTP_METHOD` | `email` | Default OTP delivery: `totp` \| `email` \| `sms` |
| `OTP_EXPIRY_MINUTES` | `10` | OTP validity window |
| `OTP_LENGTH` | `6` | OTP digit count |
| `EMAIL_VERIFY_EXPIRY_HOURS` | `24` | Email verification link lifetime |
| `PASSWORD_RESET_EXPIRY_HOURS` | `1` | Password reset link lifetime |
| `TOKEN_REVOCATION_STORE` | `db` | `db` \| `redis` |
| `REDIS_URL` | — | Required when `TOKEN_REVOCATION_STORE=redis` |
| `LOGIN_RATE_LIMIT` | `10` | Max login attempts per window |
| `LOGIN_RATE_WINDOW_MS` | `900000` | Login rate limit window (ms) |
| `REGISTER_RATE_LIMIT` | `5` | Max registrations per window |
| `REGISTER_RATE_WINDOW_MS` | `3600000` | Registration rate limit window (ms) |
| `OTP_RATE_LIMIT` | `5` | Max OTP requests per window |
| `RESET_RATE_LIMIT` | `3` | Max password resets per window |
| `LOG_LEVEL` | `info` | Winston log level |
| `LOG_FORMAT` | `json` | `json` \| `pretty` |
| `FRONTEND_URL` | — | Used to build verification/reset links |

### Social OAuth (all optional)

`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `FACEBOOK_APP_ID`, `FACEBOOK_APP_SECRET`, `TWITTER_CLIENT_ID`, `TWITTER_CLIENT_SECRET`, `APPLE_CLIENT_ID`, `APPLE_KEY_ID`, `APPLE_TEAM_ID`, `APPLE_PRIVATE_KEY`

---

## 6. API Reference

Base URL: `http://localhost:4002`  
All `/api/*` endpoints require the `X-Tenant-Id` header.

### Health (no tenant required)

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Service status + uptime |
| GET | `/health/live` | Liveness probe — always 200 |
| GET | `/health/ready` | Readiness probe — 503 if DB unreachable |

### Auth — Public

| Method | Path | Rate Limit | Description |
|---|---|---|---|
| POST | `/api/auth/register` | 5/hr | New user registration |
| POST | `/api/auth/login` | 10/15 min | Email + password login |
| POST | `/api/auth/login/mfa` | 10/15 min | Complete MFA challenge |
| POST | `/api/auth/logout` | — | Invalidate session + clear cookies |
| POST | `/api/auth/token/refresh` | — | Exchange refresh token |
| GET | `/api/auth/token/verify` | — | Validate Bearer token (used by other services) |
| POST | `/api/auth/email/verify` | — | Confirm email address |
| POST | `/api/auth/email/resend` | 5/hr | Resend verification email |
| POST | `/api/auth/password/forgot` | 3/hr | Request password reset |
| POST | `/api/auth/password/reset` | 3/hr | Reset password via token |
| POST | `/api/auth/otp/verify` | 5/hr | Verify OTP code |
| POST | `/api/auth/otp/resend` | 5/hr | Resend OTP |
| POST | `/api/auth/account/unlock/request` | 3/hr | Request self-service account unlock email |
| POST | `/api/auth/account/unlock/confirm` | — | Confirm account unlock via token from email |

### Auth — Protected (JWT required)

| Method | Path | Description |
|---|---|---|
| GET | `/api/auth/me` | Get current user profile |
| PATCH | `/api/auth/me` | Update profile fields |
| DELETE | `/api/auth/me` | GDPR account deletion |
| GET | `/api/auth/me/export` | GDPR data export |
| POST | `/api/auth/password/change` | Change password |
| GET | `/api/auth/sessions` | List active sessions |
| DELETE | `/api/auth/sessions/:sessionId` | Revoke session |
| DELETE | `/api/auth/sessions` | Revoke all other sessions |
| GET | `/api/auth/devices` | List trusted devices |
| PATCH | `/api/auth/devices/:deviceId/trust` | Mark / unmark device as trusted |
| DELETE | `/api/auth/devices/:deviceId` | Remove device |
| POST | `/api/auth/mfa/totp/setup` | Start TOTP enrollment |
| POST | `/api/auth/mfa/totp/verify` | Confirm TOTP enrollment |
| DELETE | `/api/auth/mfa/totp` | Disable TOTP |
| GET | `/api/auth/mfa/backup-codes` | List backup codes |
| POST | `/api/auth/mfa/backup-codes/regenerate` | New backup codes |
| PATCH | `/api/auth/otp/settings` | Update OTP preferences (method, login requirement) |
| POST | `/api/auth/phone/verify` | Verify phone via SMS OTP |
| POST | `/api/auth/phone/resend` | Resend phone OTP |
| GET | `/api/auth/me/security-events` | View own security event log (paginated) |

### Social Auth

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/social/login` | — | Login via provider token |
| POST | `/api/auth/social/link` | JWT | Link new provider |
| DELETE | `/api/auth/social/unlink/:provider` | JWT | Unlink provider |
| GET | `/api/auth/social/accounts` | JWT | List linked providers |

### Admin (role: admin or super_admin)

These are **auth-intrinsic only** — operations that directly modify or read data
owned exclusively by this service (locks, sessions, token blacklist, audit logs).
User-management operations (list users, suspend, reinstate, delete, meta) belong
in the separate `user-management-service`.

| Method | Path | Description |
|---|---|---|
| POST | `/api/admin/users/:id/unlock` | Unlock locked account (clears loginAttempts / isLocked) |
| GET | `/api/admin/sessions` | All active sessions in tenant |
| DELETE | `/api/admin/sessions/:sessionId` | Force-revoke any session |
| GET | `/api/admin/logs` | Paginated auth audit logs |
| GET | `/api/admin/analytics` | Login stats, MFA adoption, trends |

> **Moved to `user-management-service`:** `GET /users`, `GET /users/:id`,
> `PATCH /users/:id/suspend`, `PATCH /users/:id/reinstate`, `PATCH /users/:id/meta`,
> `DELETE /users/:id`

---

## 7. Authentication Flows

### Registration

```
Client  →  POST /api/auth/register
           { firstName, lastName, email, password, [role] }

tenantMiddleware     Validate X-Tenant-Id
registerLimiter      5 registrations/hr per IP
validateRegister     express-validator chain
authController       hashPassword(bcryptRounds)
                     User.create({ tenantId, ...fields })
                     generateSecureToken(32) → hashToken() → stored as emailVerificationToken
                     logRegistration(user, req)        ← fire-and-forget
                     emailNotifier.send(welcome(...))  ← fire-and-forget

Response 201 { user: { id, email, username, status: 'pending_verification' } }
```

### Login

```
Client  →  POST /api/auth/login  { email, password }

tenantMiddleware     Validate X-Tenant-Id
loginLimiter         10 attempts/15 min per IP
authController
  ├── User.findOne({ email, tenantId })
  ├── Check account status (active/suspended/locked)
  ├── bcrypt.compare(password, user.passwordHash)
  │     failure → increment loginAttempts
  │               lockout if >= MAX_LOGIN_ATTEMPTS
  │               send ACCOUNT_LOCKED email (fire-and-forget)
  ├── If MFA enabled:
  │     generate short-lived mfaToken (JWT, 5 min)
  │     return 202 { mfaRequired: true, mfaToken }
  └── Issue tokens:
        generateTokens(user, session) → { accessToken, refreshToken, idToken }
        setCookiesOnHeader(res, ...)   → HttpOnly Secure SameSite=Strict cookies
        logLogin(user, req)            ← fire-and-forget
        deviceDetector.detect(req)
          new device? → emailNotifier.send(newDeviceLogin) ← fire-and-forget
        return 200 { accessToken, user: { id, email, role, tenantId } }
```

### Token Refresh

```
Client  →  POST /api/auth/token/refresh
           Cookie: refreshToken=<token>  OR  body: { refreshToken }

authController
  ├── Extract refresh token from cookie or body
  ├── jwt.verify(token, refreshSecret)
  ├── isTokenRevoked(jti, tenantId)  → 401 if true
  ├── User.findOne({ _id: sub, tenantId })
  ├── revokeToken(oldJti, ...)        ← blacklist old refresh token
  ├── generateTokens(user, session)   ← new pair
  └── setCookiesOnHeader(res, ...)
      return 200 { accessToken }

Reuse of rotated token → revokeAllUserTokens(user) → 401 REFRESH_TOKEN_REUSED
```

### Password Reset

```
POST /api/auth/password/forgot  { email }
  → Generate reset token (crypto.randomBytes(32))
  → Store hashToken(token) in user.passwordReset.token
  → emailNotifier.send(passwordResetRequested(..., resetLink))  ← fire-and-forget
  → 200 (always — never reveal account existence)

POST /api/auth/password/reset  { token, password, confirmPassword }
  → User.findOne({ tenantId, passwordReset.tokenExpiry: { $gt: now } })
  → timingSafeEqual(hashToken(token), stored hash)
  → hashPassword(newPassword) → user.passwordHash
  → revokeAllUserTokens(user)  ← invalidate all sessions
  → emailNotifier.send(passwordResetCompleted)
  → 200
```

### MFA TOTP Setup

```
POST /api/auth/mfa/totp/setup
  → authenticator.generateSecret()
  → Store secret (encrypted) in user.twoFactorAuth.tempSecret
  → QRCode.toDataURL(otpauth://totp/...) 
  → return { secret, qrCodeUrl }

POST /api/auth/mfa/totp/verify  { code }
  → authenticator.verify({ token: code, secret: tempSecret })
  → Move tempSecret → twoFactorAuth.secret
  → twoFactorAuth.enabled = true
  → Generate 10 single-use backup codes
  → return { backupCodes }
```

---

## 8. Multi-Tenancy

### How It Works

Every inbound request must carry `X-Tenant-Id` (e.g. `tenant-a`). The `tenantMiddleware` validates the header and sets `req.tenantId`. Every Mongoose query includes `tenantId` as a filter.

```
GET /api/auth/me
X-Tenant-Id: tenant-a
Authorization: Bearer <token>

→ auth middleware:   decoded.tenantId = 'tenant-a'
→ User.findById(...).where({ tenantId: 'tenant-a' })
→ A user from tenant-b with the same _id gets 404
```

### Tenant ID Format

Must match `^[a-z0-9_-]{3,64}$`. Any header that fails validation is rejected with `400`. This prevents header-injection attacks.

### TENANCY_MODE=shared (default)

One MongoDB database is shared. All collections have `tenantId: { type: String, required: true, index: true }`. Compound indexes enforce uniqueness per-tenant:

```js
UserSchema.index({ tenantId: 1, email: 1 }, { unique: true });
UserSchema.index({ tenantId: 1, username: 1 }, { unique: true, sparse: true });
UserSchema.index({ tenantId: 1, 'meta.department': 1 });
UserSchema.index({ tenantId: 1, 'meta.team': 1 });
UserSchema.index({ tenantId: 1, 'meta.tags': 1 });
LogEntrySchema.index({ tenantId: 1, userId: 1, createdAt: -1 });
```

### `meta` — Organisational & Classification Subdocument

A single `meta` key groups all organisational and classification attributes. Only admins can write to it; the field is returned in all profile responses.

| Field | Type | Description |
|---|---|---|
| `meta.department` | String | e.g. `"Engineering"` |
| `meta.division` | String | e.g. `"Product"` |
| `meta.branch` | String | Office / physical location |
| `meta.team` | String | e.g. `"Backend"` |
| `meta.jobTitle` | String | e.g. `"Senior Developer"` |
| `meta.employeeId` | String | HR system identifier |
| `meta.manager` | ObjectId → User | Reporting line |
| `meta.startDate` | Date | Hire / onboarding date |
| `meta.category` | String | e.g. `"full-time"`, `"contractor"`, `"partner"` |
| `meta.tags` | [String] | Admin-set labels for segmentation / filtering |
| `meta.customFields` | Mixed | Any tenant-specific key-value extensions |

**Update endpoint:** `PATCH /api/admin/users/:id/meta`

Request body — send only the fields you want to change:
```json
{
  "department": "Engineering",
  "team": "Backend",
  "jobTitle": "Senior Developer",
  "employeeId": "EMP-0042",
  "category": "full-time",
  "tags": ["beta-tester", "vip"],
  "customFields": { "costCenter": "CC-101" }
}
```

### TENANCY_MODE=per-db

Each tenant gets a dedicated MongoDB database. Connections are created lazily and cached in-memory. Set `MONGO_URI=mongodb://host/{tenant}_auth_db` — the `{tenant}` placeholder is substituted at connection time.

---

## 9. Token Strategy

### Three-Token Architecture

| Token | Expiry | Transport | Purpose |
|---|---|---|---|
| **Access Token** | `JWT_ACCESS_EXPIRY` (1d) | `Authorization: Bearer` header | Stateless API access — verified locally by any service |
| **Refresh Token** | `JWT_REFRESH_EXPIRY` (7d) | `refreshToken` HttpOnly cookie | Silent re-authentication |
| **ID Token** | `JWT_ID_EXPIRY` (30d) | `idToken` HttpOnly cookie | OpenID-style identity claims for frontend |

### Standard JWT Claims

Every token contains:

```
{
  sub:       "<userId>",
  tenantId:  "<tenantId>",
  role:      "user",
  sessionId: "<uuid>",
  jti:       "<uuid v4>",    ← unique per token, used for revocation
  iat, exp, iss, aud
}
```

The ID token additionally carries `email`, `firstName`, `lastName`, `username`, `picture`, `phoneNumber`, `emailVerified`.

### Algorithm

Default: **HS256** (symmetric, shared secret — simplest for same-team services).  
RS256: Configure `JWT_ALGORITHM=RS256` with `JWT_PRIVATE_KEY_PATH` / `JWT_PUBLIC_KEY_PATH` if other services need to verify tokens without calling this service.

### Cookie Security

All HttpOnly cookies are set with:
```
HttpOnly; Secure; SameSite=Strict; Path=/
```
`Secure` is only meaningful behind HTTPS (enforced at the load balancer in production).

---

## 10. Token Revocation

### DB Adapter (default, `TOKEN_REVOCATION_STORE=db`)

Revoked JTIs are stored in the `TokenBlacklist` collection. A MongoDB TTL index (`expiresAt: 1`) automatically purges documents when the original token expires — no manual cleanup needed.

`authMiddleware` checks the blacklist on **every authenticated request**:
```js
const isRevoked = await TokenBlacklist.exists({ jti, tenantId });
if (isRevoked) → 401 Token has been revoked
```

### Redis Adapter (`TOKEN_REVOCATION_STORE=redis`)

For high-traffic deployments, switch to Redis to avoid DB round-trips:
```
SET revoked:<tenantId>:<jti> "1" EX <ttlSeconds>
GET revoked:<tenantId>:<jti>  → null = valid, "1" = revoked
```

Set `REDIS_URL=redis://localhost:6379` and `TOKEN_REVOCATION_STORE=redis`.

### Revocation Triggers

| Event | Tokens Revoked |
|---|---|
| Logout | Current session's access + refresh JTIs |
| Password change | All sessions for the user |
| Password reset | All sessions for the user |
| Revoke session | That session's refresh token |
| Revoke all sessions | All sessions except current |
| Admin suspend user | All user sessions |
| Refresh token rotation | Previous refresh JTI (reuse = revoke all) |

---

## 11. Security Controls

### Input Validation

- **`express-validator`** chains in `src/validators/auth.js` run before every controller.
- **`express-mongo-sanitize`** strips `$` and `.` from all request keys (NoSQL injection prevention).
- **`sanitization.js`** middleware recursively removes `<>` and dangerous characters from string values (XSS prevention).
- Body size is limited to **10 KB** via `express.json({ limit: '10kb' })`.

### Passwords

- Hashed with **bcrypt** (cost factor `BCRYPT_ROUNDS`, default 12).
- Minimum strength enforced: 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char.
- Plain-text passwords are **never logged or returned** in any response.

### Reset / Verification Tokens

- Generated with `crypto.randomBytes(32)` → 64-hex characters (256 bits of entropy).
- **Only the SHA-256 hash is stored** in the database — the plain token is only in the email link.
- Compared using `crypto.timingSafeEqual()` to prevent timing attacks.

### Account Lockout

After `MAX_LOGIN_ATTEMPTS` (default 5) consecutive failures:
1. Account status is set to `locked`.
2. `ACCOUNT_LOCKED` email is sent (fire-and-forget).
3. Subsequent login attempts return `423 Locked` until the window expires or an admin unlocks the account.

### Rate Limiting

All limiters use a per-IP key scoped by tenant (`${req.ip}:${req.tenantId}`):

| Endpoint | Limit | Window |
|---|---|---|
| Login | 10 requests | 15 minutes |
| Register | 5 requests | 1 hour |
| OTP / resend | 5 requests | 1 hour |
| Password reset | 3 requests | 1 hour |

### Security Headers

`helmet()` sets:
- `Strict-Transport-Security`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`

---

## 12. OTP / MFA

### Delivery Methods

| Method | Trigger condition |
|---|---|
| `totp` | User has TOTP enabled (`user.twoFactorAuth.enabled = true`) — highest priority |
| `email` | Default fallback — 6-digit code sent via email microservice |
| `sms` | Opt-in — requires `SMS_PROVIDER` env and verified phone number |

Priority order: TOTP > SMS (if preferred + phone verified) > email.

### TOTP Enrollment Flow

1. `POST /api/auth/mfa/totp/setup` — generates a secret and QR code URL.
2. User scans the QR code in their authenticator app (Google Authenticator, Authy).
3. `POST /api/auth/mfa/totp/verify` with the 6-digit code from the app — activates TOTP.
4. Ten single-use backup codes are issued.

### Email OTP

Stored as `SHA-256(otp)` in `user.otp.hash`. Expires after `OTP_EXPIRY_MINUTES` (default 10 min). Maximum `MAX_OTP_ATTEMPTS` (default 5) retries before invalidation.

---

## 13. Social Authentication

### How It Works

1. The **frontend** handles the OAuth redirect/popup with the provider.
2. The frontend receives the provider's ID token or access token.
3. The frontend posts it to `POST /api/auth/social/login`.
4. `socialProvider.js` validates the token against the provider's API.
5. On success, the service looks up the user by `{ tenantId, socialAccounts.provider, socialAccounts.providerId }`.
   - Found → issue JWT.
   - Not found → create user → issue JWT.

### Supported Providers

`google`, `facebook`, `github`, `twitter`, `apple`, `linkedin`, `microsoft`, `discord`

### Configuration

Each provider requires its own env vars (see [Environment Variables](#5-environment-variables)). Unconfigured providers return `400 Provider not configured`.

---

## 14. Email Notifications

This service **never sends email directly**. All emails are delegated to an external email microservice via HTTP POST.

### How It Works

```js
// Always fire-and-forget — never await
emailNotifier.send(emailPayloads.welcome(user, verifyLink));
```

`emailNotifier.send()` makes a non-blocking `axios.post` to `${EMAIL_SERVICE_URL}/send-email`. Failures are caught, logged as warnings, and **never propagate to the caller** — an email failure cannot break an auth flow.

### Email Events

| Event | `templateKey` | Variables |
|---|---|---|
| Registration | `USER_CREATED` | `name`, `verifyLink` |
| Email verified | `EMAIL_VERIFIED` | `name` |
| Password reset request | `PASSWORD_RESET_REQUESTED` | `name`, `resetLink`, `expiryHours` |
| Password reset complete | `PASSWORD_RESET_COMPLETED` | `name` |
| Password changed | `PASSWORD_CHANGED` | `name` |
| New device login | `NEW_DEVICE_LOGIN` | `name`, `device`, `location`, `ip`, `time` |
| Account locked | `ACCOUNT_LOCKED` | `name`, `maxAttempts` |
| Login failed | `LOGIN_FAILED` | `name`, `ip`, `time` |
| OTP delivery | `OTP_VERIFICATION` | `name`, `otp`, `expiryMinutes` |
| Account suspended | `USER_SUSPENDED` | `name`, `reason` |
| Account reinstated | `USER_REINSTATED` | `name` |
| Account unlock requested | `ACCOUNT_UNLOCK_REQUESTED` | `name`, `unlockLink`, `expiryHours` |
| Account unlocked | `ACCOUNT_UNLOCKED` | `name` |

---

## 15. Middleware Stack

The middleware executes in this fixed order (from `app.js`):

```
Request
  │
  ├─ 1. helmet()               Security headers
  ├─ 2. cors()                 CORS with credentials
  ├─ 3. compression            gzip (bypass: X-No-Compression header)
  ├─ 4. express.json()         Body parsing (10 KB limit)
  ├─ 5. express.urlencoded()   Form body parsing
  ├─ 6. cookieParser()         Cookie parsing
  ├─ 7. mongoSanitize()        NoSQL injection prevention
  ├─ 8. sanitizeInput          XSS sanitization
  ├─ 9. requestId              Attach crypto.randomUUID() to req
  ├─ 10. morgan + loggerMW     HTTP access logging
  ├─ (health routes — no tenant check)
  ├─ 11. tenantMiddleware      X-Tenant-Id → req.tenantId  [/api only]
  ├─ (route handlers)
  │     authMiddleware          JWT → req.user             [protected routes]
  │     roleCheck / authorize   RBAC                       [admin routes]
  │
  ├─ 12. 404 handler
  └─ 13. errorHandler          Global error handler (last)
```

---

## 16. Configuration Management

All configuration flows through a single centralized module:

```
process.env
    │
    ▼
src/config/validateEnv.js   (Joi validation + defaults — runs at startup)
    │
    ▼
src/config/env.js           (structured export — all other files import from here)
    │
    ├── env.NODE_ENV, env.IS_PROD, env.IS_DEV, env.PORT
    ├── env.MONGO_URI, env.TENANCY_MODE
    ├── env.REDIS_URL, env.TOKEN_REVOCATION_STORE
    ├── env.jwt.{ accessSecret, refreshSecret, idSecret, ... }
    ├── env.BCRYPT_ROUNDS, env.MAX_LOGIN_ATTEMPTS, env.LOCK_WINDOW_MS
    ├── env.OTP_EXPIRY_MS, env.OTP_LENGTH, env.TOTP_ISSUER
    ├── env.EMAIL_SERVICE_URL, env.FRONTEND_URL, env.CORS_ORIGIN
    ├── env.rateLimit.{ login, register, otp, reset }
    └── env.LOG_LEVEL, env.LOG_FORMAT
```

**No file reads `process.env` directly** except `validateEnv.js`. This eliminates scattered `process.env.FOO || 'default'` patterns and makes all configuration explicit and auditable.

---

## 17. Deployment

### Local (nodemon)

```bash
npm run dev
# Starts on port 4002 with hot-reload
```

### Production

```bash
npm start
# Starts node server.js directly (no nodemon overhead)
```

### Docker Compose

```bash
# Start all services (auth service + MongoDB + Redis)
docker compose up -d

# View logs
docker compose logs -f user-auth-service

# Stop
docker compose down
```

### Dockerfile Notes

- **Multi-stage build** — `deps` stage installs production dependencies; `production` stage copies only what's needed.
- Runs as **non-root user** (`appuser`) for security.
- Built-in `HEALTHCHECK` targets `/health/live`.
- Base image: `node:20-alpine` (minimal attack surface).

### Kubernetes

The `/health/live` and `/health/ready` endpoints are designed for Kubernetes probes:

```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 4002
  initialDelaySeconds: 15
  periodSeconds: 30

readinessProbe:
  httpGet:
    path: /health/ready
    port: 4002
  initialDelaySeconds: 10
  periodSeconds: 10
  failureThreshold: 3
```

---

## 18. Integration with dashboard-backend

### Step 1 — Proxy Auth Requests

In `dashboard-backend/src/proxies/authServiceProxy.js`:

```js
const { createProxyMiddleware } = require('http-proxy-middleware');
const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || 'http://localhost:4002';

const authServiceProxy = createProxyMiddleware({
  target: AUTH_SERVICE_URL,
  changeOrigin: true,
  on: {
    proxyReq: (proxyReq, req) => {
      if (req.tenantId) proxyReq.setHeader('X-Tenant-Id', req.tenantId);
    },
    error: (err, req, res) => {
      res.status(502).json({ success: false, message: 'Auth service unavailable' });
    },
  },
});
module.exports = { authServiceProxy };
```

Mount **before body-parser** in `app.js`:
```js
app.use('/api/auth', authServiceProxy);
```

### Step 2 — Delegate Token Verification

Replace local JWT verification in `dashboard-backend/src/middleware/auth.js`:

```js
const axios = require('axios');

const authMiddleware = async (req, res, next) => {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return next(AppError.unauthorized('No token'));
  try {
    const { data } = await axios.get(`${process.env.AUTH_SERVICE_URL}/api/auth/token/verify`, {
      headers: {
        Authorization: header,
        'X-Tenant-Id': req.headers['x-tenant-id'] || '',
      },
      timeout: 3000,
    });
    req.user = data.user;
    next();
  } catch {
    next(AppError.unauthorized('Invalid or expired token'));
  }
};
```

### Step 3 — Add Environment Variable

```env
# dashboard-backend/.env
AUTH_SERVICE_URL=http://localhost:4002
```

---

## 19. Health Checks

### `GET /health`

Returns the service identity and uptime:

```json
{
  "status": "ok",
  "service": "user-auth-service",
  "version": "1.0.0",
  "uptime": 142,
  "startedAt": "2026-03-07T10:00:00.000Z"
}
```

### `GET /health/live`

Always returns `200 { "status": "alive" }` if the Node.js process is running. Used by Kubernetes to decide whether to restart the pod.

### `GET /health/ready`

Checks MongoDB connectivity (and Redis if `TOKEN_REVOCATION_STORE=redis`):

```json
{
  "status": "ready",
  "checks": {
    "mongo": "ok",
    "redis": "not_required"
  },
  "uptime": 142
}
```

Returns `503` if any required dependency is unreachable. Used by Kubernetes to decide whether to send traffic to the pod.

> Health endpoints do **not** require `X-Tenant-Id`.

---

## 20. Testing with Postman

The collection is at `postman/user-auth-service.postman_collection.json`.

### Import

1. Open Postman → **Import** → select the collection file.
2. Open **Variables** for the collection and verify:
   - `baseUrl` = `http://localhost:4002`
   - `tenantId` = `tenant-a` (or any valid slug)

### Recommended Test Order

```
1. Health → Deep Health Check          (verify service is up)
2. Health → Readiness Probe            (verify DB is connected)
3. Auth - Public → Register            (creates user, auto-sets {{userId}})
4. Auth - Public → Login               (auto-sets {{accessToken}})
5. Auth - Protected → Get Profile      (verify JWT works)
6. Auth - Protected → Get Sessions     (auto-sets {{sessionId}})
7. Auth - Protected → Setup TOTP       (auto-sets {{totpSecret}})
8. Security Tests → (run all — verify controls)
9. Admin → (set {{adminAccessToken}} via separate admin login)
```

### Auto-Population via Test Scripts

The following requests automatically set collection variables on success:

| Request | Variables set |
|---|---|
| Register | `userId` |
| Login | `accessToken`, `userId`, `mfaToken` (if MFA) |
| Refresh Token | `accessToken` |
| Get Sessions | `sessionId` (first session) |
| Get Devices | `deviceId` (first device) |
| Setup TOTP | `totpSecret` |
| Social Login | `accessToken`, `userId` |
| Logout | Clears `accessToken`, `refreshToken` |

### Admin Token

Admin endpoints use `{{adminAccessToken}}` (separate from `{{accessToken}}`). To set it:

1. Create a user with `role: "admin"` (or use the database directly).
2. Login with that user via the Login request.
3. Copy the returned token to the `adminAccessToken` collection variable.
