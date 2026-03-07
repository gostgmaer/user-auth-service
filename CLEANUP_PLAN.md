# Database Cleanup & Token Validation — Implementation Plan

> **Status:** Implemented  
> **Date:** March 8, 2026  
> **Scope:** Automated stale-data cleanup + enhanced token-validation endpoint

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Cleanup Strategy Overview](#2-cleanup-strategy-overview)
3. [Layer 1 — MongoDB TTL Index (LogEntry)](#3-layer-1--mongodb-ttl-index-logentry)
4. [Layer 2 — Model Pre-Save Hook (User)](#4-layer-2--model-pre-save-hook-user)
5. [Layer 3 — Background Cron Jobs](#5-layer-3--background-cron-jobs)
6. [Token Validation Endpoint](#6-token-validation-endpoint)
7. [File Change Summary](#7-file-change-summary)
8. [Environment Variables Reference](#8-environment-variables-reference)
9. [Data Lifecycle Matrix](#9-data-lifecycle-matrix)

---

## 1. Problem Statement

Before this implementation the service had several categories of stale data that
accumulated indefinitely because there was no cleanup mechanism:

| Data | Location | Problem |
|---|---|---|
| Expired activity logs | `LogEntry` collection | `retentionPolicy` field existed but was never enforced — logs grew forever |
| Expired OTP / MFA sessions | `User.currentOTP` | Cleared only when re-used; abandoned ones lingered |
| Expired email-verification tokens | `User.emailVerificationToken` | Never cleared after expiry |
| Expired password-reset tokens | `User.passwordReset.token` | Never cleared after expiry |
| Expired account-unlock tokens | `User.unlockToken` | Never cleared after expiry |
| Expired account locks | `User.loginSecurity.lockedUntil` | Unlocking relied entirely on the virtual `isLocked`; the lock field was never nulled proactively |
| Inactive / expired sessions | `User.activeSessions[]` | Pre-save hook trimmed only when the document was saved; long-inactive users retained stale sessions |
| Inactive / expired refresh tokens | `User.refreshTokens[]` | Same as above |
| Unbounded security events | `User.securityEvents[]` | `logSecurityEvent()` capped at 100, but no guard elsewhere |

Additionally, the `GET/POST /api/auth/token/verify` endpoint returned only data
baked into the JWT claims at issuance time — not the **current** user state —
so downstream services could receive a stale role even after RBAC changes.

---

## 2. Cleanup Strategy Overview

Three complementary layers are used; each targets a different scenario:

```
Layer 1 — MongoDB TTL Index
   └─ Self-contained; MongoDB daemon thread deletes documents automatically.
   └─ Used for: LogEntry collection (separate documents, easy TTL target).

Layer 2 — Model Pre-Save Hook (User.js)
   └─ Runs on every User document write.
   └─ Best-effort: cleans transient fields and caps arrays on every save.
   └─ Ensures documents being actively used are always clean.

Layer 3 — Background Cron Jobs
   └─ Handles documents that are never re-saved (inactive / abandoned accounts).
   └─ Uses bulk MongoDB updateMany with $pull / $set / $unset — no document-level iteration.
   └─ Controlled by CLEANUP_ENABLED env var.
```

---

## 3. Layer 1 — MongoDB TTL Index (LogEntry)

**File:** [`src/models/LogEntry.js`](src/models/LogEntry.js)

### What was added

#### New field: `expiresAt`

```js
expiresAt: { type: Date, default: null }
```

Set automatically in the pre-save hook based on `retentionPolicy`.  
`null` means the document lives forever — MongoDB's TTL scanner **skips** documents
where the indexed field is `null` or missing.

#### TTL Index

```js
logEntrySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
```

`expireAfterSeconds: 0` tells MongoDB to delete the document exactly when
`expiresAt` is reached (MongoDB TTL thread runs approximately every 60 seconds).

#### Pre-save hook — retention policy mapping

```js
const RETENTION_MS = {
  '30d':  30  * 24 * 60 * 60 * 1000,   // 30 days
  '90d':  90  * 24 * 60 * 60 * 1000,   // 90 days
  '1y':   365 * 24 * 60 * 60 * 1000,   // 1 year
  // 'forever' → expiresAt stays null → document never deleted
};

logEntrySchema.pre('save', function (next) {
  if (!this.expiresAt && this.retentionPolicy !== 'forever') {
    const ms = RETENTION_MS[this.retentionPolicy];
    if (ms) this.expiresAt = new Date(Date.now() + ms);
  }
  next();
});
```

### Retention policy table

| `retentionPolicy` | `expiresAt` computed | Auto-deleted by MongoDB |
|---|---|---|
| `30d` | `createdAt + 30 days` | Yes |
| `90d` | `createdAt + 90 days` | Yes |
| `1y` (default) | `createdAt + 365 days` | Yes |
| `forever` | `null` | No — kept indefinitely |

### Important note for existing data

The TTL index and pre-save hook only apply to **new** documents.  
Existing `LogEntry` documents that were created before this change have
`expiresAt: null` and will **not** be automatically deleted.

To backfill existing documents, run this one-time admin script in the MongoDB
shell (adjust dates as needed):

```js
// Backfill existing LogEntry documents without an expiresAt
const now = new Date();
const policies = {
  '30d': 30  * 24 * 60 * 60 * 1000,
  '90d': 90  * 24 * 60 * 60 * 1000,
  '1y':  365 * 24 * 60 * 60 * 1000,
};
for (const [policy, ms] of Object.entries(policies)) {
  db.logentries.updateMany(
    { retentionPolicy: policy, expiresAt: null },
    [{ $set: { expiresAt: { $add: ['$createdAt', ms] } } }]
  );
}
```

---

## 4. Layer 2 — Model Pre-Save Hook (User)

**File:** [`src/models/User.js`](src/models/User.js)

The pre-save hook already capped the four subdocument arrays. It has been
extended to also clear stale transient fields every time the document is saved.

### Array caps (unchanged behaviour, same logic)

| Array | Cap | Filter applied |
|---|---|---|
| `activeSessions` | 50 | `isActive && expiresAt > now` |
| `refreshTokens` | 50 | `isActive && expiresAt > now` |
| `knownDevices` | 30 | `isActive` |
| `loginHistory` | 100 | none (slice only) |
| `securityEvents` | `MAX_SECURITY_EVENTS` env (default 200) | none (slice only) |

### New: stale field cleanup on every save

| Condition | Fields cleared |
|---|---|
| `emailVerificationTokenExpiry < now` | `emailVerificationToken = null`, `emailVerificationTokenExpiry = null` |
| `passwordReset.tokenExpiry < now` | `passwordReset.token = null`, `tokenExpiry = null`, `attempts = 0` |
| `unlockToken.tokenExpiry < now` | `unlockToken.token = null`, `unlockToken.tokenExpiry = null` |
| `loginSecurity.lockedUntil < now` | `lockedUntil = null`, `failedAttempts = 0` (auto-unlock) |
| `currentOTP.expiresAt < now` | `currentOTP = {}` (entire OTP object cleared) |

---

## 5. Layer 3 — Background Cron Jobs

### Architecture

```
server.js
  └─ cleanupManager.startAll()         (called after connectDB)
       ├─ ExpiredSessionCleaner         every 6 hours
       ├─ StaleUserFieldCleaner         every 30 minutes
       └─ SecurityEventsTrimmer         every Sunday 04:00 UTC
```

All jobs use **bulk `updateMany` operations** — no document-by-document
iteration. This makes them efficient even on large collections (100 k+ users).

---

### Job 1 — ExpiredSessionCleaner

**File:** [`src/jobs/expiredSessionCleaner.js`](src/jobs/expiredSessionCleaner.js)  
**Schedule:** `0 */6 * * *` (every 6 hours, UTC)  
**Target:** `User.activeSessions[]`, `User.refreshTokens[]`

```js
// Removes array entries where expiresAt < now OR isActive = false
User.updateMany(
  { 'activeSessions.0': { $exists: true } },
  { $pull: { activeSessions: { $or: [{ expiresAt: { $lt: now } }, { isActive: false }] } } }
)

User.updateMany(
  { 'refreshTokens.0': { $exists: true } },
  { $pull: { refreshTokens: { $or: [{ expiresAt: { $lt: now } }, { isActive: false }] } } }
)
```

**Why needed:** A user who logged in once and never returned will have a
session/token that the pre-save hook never cleaned because the document was
never saved again.

---

### Job 2 — StaleUserFieldCleaner

**File:** [`src/jobs/staleUserFieldCleaner.js`](src/jobs/staleUserFieldCleaner.js)  
**Schedule:** `*/30 * * * *` (every 30 minutes, UTC)  
**Target:** Five distinct field groups on `User`

| Step | Query filter | Operation |
|---|---|---|
| 1 — Expired OTPs | `currentOTP.expiresAt < now` | `$unset: { currentOTP: '' }` |
| 2 — Email verify tokens | `emailVerificationTokenExpiry < now && token != null` | `$set token/expiry = null` |
| 3 — Password reset tokens | `passwordReset.tokenExpiry < now && token != null` | `$set token/expiry/attempts = null/0` |
| 4 — Unlock tokens | `unlockToken.tokenExpiry < now && token != null` | `$set token/expiry = null` |
| 5 — Expired locks | `loginSecurity.lockedUntil < now` | `$set lockedUntil = null, failedAttempts = 0` |

**Why every 30 minutes:** OTP expiry is as short as 5 minutes (MFA sessions).
Waiting 6 hours would leave a large window where expired OTPs clutter user
documents.

---

### Job 3 — SecurityEventsTrimmer

**File:** [`src/jobs/securityEventsTrimmer.js`](src/jobs/securityEventsTrimmer.js)  
**Schedule:** `0 4 * * 0` (every Sunday at 04:00 UTC)  
**Target:** `User.securityEvents[]`

Uses an aggregation pipeline update with `$slice` to trim arrays that exceed
the cap without fetching documents into application memory:

```js
User.updateMany(
  { [`securityEvents.${cap}`]: { $exists: true } },   // only over-length docs
  [{ $set: { securityEvents: { $slice: ['$securityEvents', -cap] } } }]
)
```

The query filter `securityEvents.<N>` efficiently selects only documents
where the array has more than `N` elements, so unchanged documents are
never written to.

---

### Cleanup Job Control

| Env var | Default | Effect |
|---|---|---|
| `CLEANUP_ENABLED` | `true` | Set to `false` to disable all cron jobs (e.g. in test environments) |
| `MAX_SECURITY_EVENTS` | `200` | Maximum `securityEvents[]` entries per user |

---

## 6. Token Validation Endpoint

**Route:** `GET /api/auth/token/verify` or `POST /api/auth/token/verify`  
**File:** [`src/controllers/authController.js`](src/controllers/authController.js)  
**Rate limit:** 120 requests / minute per IP  
**Auth header:** `Authorization: Bearer <access_token>`  
**Tenant header:** `x-tenant-id: <tenantId>` (optional but recommended for cross-tenant guard)

### Previous behaviour (before this change)

Returned only the claims baked into the JWT at issuance time:

```json
{
  "valid": true,
  "user": {
    "id": "...",
    "tenantId": "...",
    "email": "...",
    "role": "admin",
    "sessionId": "..."
  }
}
```

**Problem:** If a user's role or account status changed after the token was
issued, downstream services would see stale data until the token expired.

---

### New behaviour (after this change)

After JWT signature + revocation validation, the endpoint performs one DB
fetch to return the **live** user state:

```json
{
  "valid": true,
  "user": {
    "id":           "64a...",
    "tenantId":     "tenant_001",
    "email":        "alice@example.com",
    "firstName":    "Alice",
    "lastName":     "Smith",
    "role":         "admin",
    "permissions":  ["read:users", "write:profile", "manage:roles"],
    "status":       "active",
    "isActive":     true,
    "emailVerified": true,
    "isVerified":   true,
    "sessionId":    "3f8..."
  }
}
```

### Validation steps (in order)

```
1. Authorization header present and starts with "Bearer "
   → NO_TOKEN (401) if missing

2. verifyAccessToken(token)
   → TOKEN_EXPIRED (401) if expired
   → INVALID_TOKEN (401) if signature/issuer/audience fails

3. isTokenRevoked(jti, tenantId)
   → TOKEN_REVOKED (401) if blacklisted

4. Cross-tenant check: decoded.tenantId === req.tenantId (if header present)
   → TENANT_MISMATCH (403) if mismatch

5. DB fetch: User.findOne({ _id, tenantId, isDeleted: false })
             .populate({ role → permissions })
   → USER_NOT_FOUND (401) if not found

6. Account health: user.isActive && user.status === 'active'
   → ACCOUNT_INACTIVE (401) if suspended/banned/inactive

7. Session validation: activeSessions contains sessionId with isActive && expiresAt > now
   → SESSION_INVALID (401) if the session was force-revoked or expired
```

### Error response shape

All error cases return HTTP `200` with `valid: false` so that API gateways do
not need to parse different status codes when routing based on this response.
The only exceptions are `403 TENANT_MISMATCH` (always a configuration error)
and `401 NO_TOKEN`.

| `error` code | Meaning |
|---|---|
| `NO_TOKEN` | Authorization header missing or not a Bearer token |
| `TOKEN_EXPIRED` | JWT has passed its `exp` claim |
| `INVALID_TOKEN` | Signature, issuer, or audience check failed |
| `TOKEN_REVOKED` | Token JTI is in the revocation store |
| `TENANT_MISMATCH` | Token's tenant does not match the request tenant |
| `USER_NOT_FOUND` | User deleted from DB after token was issued |
| `ACCOUNT_INACTIVE` | User suspended, banned, or deactivated |
| `SESSION_INVALID` | Session was force-revoked or its expiry has passed |

### Usage example (service-to-service)

```http
GET /api/auth/token/verify
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
x-tenant-id: tenant_001
```

```js
// In another microservice (e.g. product-service)
const response = await axios.get('http://user-auth-service/api/auth/token/verify', {
  headers: {
    Authorization: `Bearer ${token}`,
    'x-tenant-id': tenantId,
  },
});

if (!response.data.valid) {
  throw new UnauthorizedError(response.data.error);
}

const { role, permissions } = response.data.user;
```

---

## 7. File Change Summary

| File | Type | What changed |
|---|---|---|
| [`src/models/LogEntry.js`](src/models/LogEntry.js) | **Modified** | Added `expiresAt` field, TTL index, pre-save hook |
| [`src/models/User.js`](src/models/User.js) | **Modified** | Extended pre-save hook: stale field cleanup + `securityEvents` cap |
| [`src/controllers/authController.js`](src/controllers/authController.js) | **Modified** | `verifyToken` — live DB fetch, role+permissions, session validation |
| [`src/jobs/cleanupManager.js`](src/jobs/cleanupManager.js) | **New** | Master cron scheduler |
| [`src/jobs/expiredSessionCleaner.js`](src/jobs/expiredSessionCleaner.js) | **New** | Bulk session + refresh token cleanup |
| [`src/jobs/staleUserFieldCleaner.js`](src/jobs/staleUserFieldCleaner.js) | **New** | Bulk OTP + token field + lock cleanup |
| [`src/jobs/securityEventsTrimmer.js`](src/jobs/securityEventsTrimmer.js) | **New** | Weekly security events trim |
| [`server.js`](server.js) | **Modified** | Calls `cleanupManager.startAll()` after DB connects |
| [`package.json`](package.json) | **Modified** | Added `node-cron ^3.0.3` dependency |

---

## 8. Environment Variables Reference

Add the following to your `.env` file:

```env
# ── Cleanup Jobs ──────────────────────────────────────────────────────────
# Set to false to disable all background cleanup cron jobs (useful for tests)
CLEANUP_ENABLED=true

# Maximum security events to retain per user (default: 200)
MAX_SECURITY_EVENTS=200
```

---

## 9. Data Lifecycle Matrix

This table shows the full lifecycle of every piece of time-sensitive data in
the service after this implementation:

| Data | Where stored | Expiry field | Cleaned by | Frequency |
|---|---|---|---|---|
| Access token blacklist | `TokenBlacklist` | `expiresAt` | MongoDB TTL index *(was already in place)* | ~60 s after expiry |
| Redis revocation keys | Redis | `EX` on SET | Redis TTL *(was already in place)* | Automatic |
| Activity logs (30d) | `LogEntry` | `expiresAt` | MongoDB TTL index *(new)* | ~60 s after expiry |
| Activity logs (90d) | `LogEntry` | `expiresAt` | MongoDB TTL index *(new)* | ~60 s after expiry |
| Activity logs (1y) | `LogEntry` | `expiresAt` | MongoDB TTL index *(new)* | ~60 s after expiry |
| Activity logs (forever) | `LogEntry` | `null` | Never | — |
| Expired OTP / MFA session | `User.currentOTP` | `expiresAt` | Pre-save hook + StaleUserFieldCleaner | On save + every 30 min |
| Email verification token | `User.emailVerificationToken` | `emailVerificationTokenExpiry` | Pre-save hook + StaleUserFieldCleaner | On save + every 30 min |
| Password reset token | `User.passwordReset.token` | `passwordReset.tokenExpiry` | Pre-save hook + StaleUserFieldCleaner | On save + every 30 min |
| Account unlock token | `User.unlockToken.token` | `unlockToken.tokenExpiry` | Pre-save hook + StaleUserFieldCleaner | On save + every 30 min |
| Account lock | `User.loginSecurity.lockedUntil` | `lockedUntil` | Pre-save hook + StaleUserFieldCleaner | On save + every 30 min |
| Expired sessions | `User.activeSessions[]` | `expiresAt` per entry | Pre-save hook (cap) + ExpiredSessionCleaner | On save + every 6 h |
| Expired refresh tokens | `User.refreshTokens[]` | `expiresAt` per entry | Pre-save hook (cap) + ExpiredSessionCleaner | On save + every 6 h |
| Security events overflow | `User.securityEvents[]` | length cap | Pre-save hook + SecurityEventsTrimmer | On save + every Sunday |
| Login history overflow | `User.loginHistory[]` | length cap (100) | Pre-save hook | On save |
| Known devices overflow | `User.knownDevices[]` | length cap (30) | Pre-save hook | On save |

---

*Document maintained in [`CLEANUP_PLAN.md`](CLEANUP_PLAN.md)*
