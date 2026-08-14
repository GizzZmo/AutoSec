# AutoSec Code Review — Security Audit & Improvements

**Reviewed:** 2026-08-14  
**Scope:** Full stack (backend, frontend, infra)  
**Severity scale:** 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low  

---

## Critical Issues Fixed

### 1. 🔴 Role Self-Escalation on Registration
**File:** `backend/src/controllers/authController.js:33`  
**Bug:** The `register` endpoint accepted `role` from user input. Any attacker could  
`POST /api/auth/register` with `{ "role": "admin" }` and gain full admin access.  
**Fix:** Role is now hardcoded to `'viewer'` on registration. Removed `role` from  
validation schema. Admin role assignment requires existing admin auth via user  
management endpoints.

### 2. 🔴 Sequelize Query Uses MongoDB `$or` Syntax  
**File:** `backend/src/controllers/authController.js:38,104`  
**Bug:** `User.findOne({ where: { $or: [...] } })` is MongoDB syntax. Sequelize  
ignores `$or` and performs no filtering — the query returns the **first user in  
the table** regardless of email/username. This means:  
- Registration: always reports "user exists" OR never detects duplicates  
- Login: authenticates as the wrong user (first in DB) when $or is ignored  
**Fix:** Replaced with `{ [Op.or]: [{ email }, { username }] }` using Sequelize's  
`Op` operators.

### 3. 🔴 JWT Secret Uses Hardcoded Fallback  
**Files:** `authController.js:8`, `middleware/auth.js:6`  
**Bug:** `process.env.JWT_SECRET || 'your-secret-key-change-in-production'` means  
any deployment without a `.env` file runs with a publicly-known signing key.  
Attackers can forge any JWT.  
**Fix:** Added startup validation — server **refuses to start** if `JWT_SECRET` is  
missing, shorter than 32 chars, or equals the placeholder string.

### 4. 🔴 XSS Sanitization Trivially Bypassed  
**File:** `middleware/security.js:231-248`  
**Bug:** The regex `/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi` only  
strips `<script>` tags. Attack vectors that bypass it:  
- `<img src=x onerror=alert(1)>`  
- `<svg onload=alert(1)>`  
- `<body onpageshow=alert(1)>`  
- `javascript:` URIs in any attribute  
**Fix:** Replaced with `/<[^>]*>/g` which strips ALL HTML tags, plus explicit  
stripping of `vbscript:`, `data:` (non-image), and `on*=` event handlers.  
Added note that CSP headers (helmet) are the primary defense.

---

## High Issues Fixed

### 5. 🟠 IP Whitelist Middleware Leaks Memory  
**File:** `middleware/security.js:202-228`  
**Bug:** `ipWhitelist(allowedIPs)` called `allowedIPs.push('127.0.0.1', ...)` on  
every request in development mode, growing the array without bound.  
**Fix:** Clone the array once at registration time (`[...allowedIPs]`), build  
per-request list without mutation.

### 6. 🟠 Frontend Has No Auth Token Management  
**File:** `frontend/src/services/api.js`  
**Bug:** The axios client has no JWT interceptor — no token is attached to  
requests, no refresh logic exists, no 401 handling. Every protected endpoint  
returns 401 and the UI does nothing.  
**Fix:** Added complete token lifecycle: localStorage storage, Authorization  
header injection on requests, 401 response interceptor with automatic refresh  
token rotation, concurrent request queue during refresh, and redirect to  
`/login` on terminal auth failure.

### 7. 🟠 Graceful Shutdown Only Closes PostgreSQL  
**File:** `backend/src/server.js:44-67`  
**Bug:** SIGTERM handler closes Sequelize but not MongoDB, RabbitMQ, or Redis.  
Zombie connections and orphaned consumers result.  
**Fix:** Shutdown now closes RabbitMQ (channel + connection), PostgreSQL, and  
MongoDB, with a 10s hard timeout to prevent hung exits.

### 8. 🟠 Duplicate Signal Handlers  
**Files:** `app.js:105-125` and `server.js:44-67`  
**Bug:** Both files register `SIGTERM`/`SIGINT`/`unhandledRejection`/  
`uncaughtException` handlers. The app.js handlers call `process.exit(0)`  
immediately — no connection cleanup.  
**Fix:** Removed handlers from `app.js`; all lifecycle management lives in  
`server.js`.

### 9. 🟠 RabbitMQ No Reconnection  
**File:** `config/rabbitmq.js`  
**Bug:** Connection failure causes `process.exit(1)` with no retry. A brief  
RabbitMQ restart kills the entire backend. Message consumer also ACKs messages  
before verifying they processed correctly.  
**Fix:** Added automatic reconnection with exponential backoff (5s → 60s max).  
Consumer now uses try/catch and `nack(msg, false, false)` on processing  
errors to avoid poison-pill loops. Added `prefetch(10)`.

---

## Medium Issues Fixed

### 10. 🟡 Double `module.exports`  
**File:** `middleware/auth.js:345-346`  
**Fix:** Removed duplicate `module.exports = exports;` line.

### 11. 🟡 Dockerfiles Use `npm install` (Non-Reproducible)  
**Files:** `backend/Dockerfile`, `frontend/Dockerfile`  
**Fix:** Changed to `npm ci` for reproducible builds. Backend now runs as  
non-root user (`appuser`). Frontend nginx now has a proper config  
(`frontend/nginx.conf`) with SPA routing, security headers, gzip, caching.

### 12. 🟡 Hardcoded Credentials in docker-compose.yml  
**File:** `docker-compose.yml`  
**Bug:** `autosec_password`, `guest/guest` for RabbitMQ, JWT secret placeholder  
committed in plaintext.  
**Fix:** All credentials now read from environment variables with `${VAR:?error}`  
RequiredVar syntax that fails fast if not set. New `.env.example` documents all  
required vars.

### 13. 🟡 No `.gitignore`  
**Fix:** Added `.gitignore` covering `node_modules/`, `.env`, `build/`, `logs/`,  
`uploads/`, GeoIP databases, IDE configs, and OS files.

### 14. 🟡 MongoDB `console.log` Instead of Winston  
**File:** `config/db.js:20-21`  
**Note:** MongoDB connection uses `console.log/error` instead of the project's  
Winston logger. Lower priority but should be aligned.

---

## Remaining Recommendations (Not Auto-Fixed)

### Security
- **Refresh token rotation** — Currently refresh tokens are stateless JWTs  
  with no family tracking. A stolen refresh token can be used indefinitely.  
  Implement Redis-backed token families or opaque refresh tokens with a  
  revocation table.
- **Audit log immutability** — Audit logs stored in MongoDB can be mutated.  
  For compliance, consider append-only logging with integrity hashes.
- **CORS origin validation** — The wildcard `origin` callback should validate  
  against an env-configured allowlist, not hardcoded `autosec.io` domains.

### Architecture  
- **The frontend build is minimal** — Only 3 pages (Dashboard, Blocklist,  
  Logs). No auth pages (login/register). No state management. The UI is a  
  starting skeleton that needs significant expansion.
- **Frontend has zero tests** — `__tests__/App.test.js` exists but  
  `@testing-library/react` is the only dep. Need meaningful test coverage.
- **Backend tests** — Only `api.test.js` exists. Core logic (behavior  
  analysis, RBAC, auth) has no test coverage.
- **Redis connection is declared but never initialized** — `redis` package  
  is a dependency with `REDIS_URL` in config, but no connection code exists  
  in `db.js` or `server.js`. Session management and caching rely on it but  
  it's just environment variable passthrough.
- **SSO framework** — `ssoService.js` exists but `passport-saml` or similar  
  SSO provider isn't in `package.json`. Dead code without a strategy.
- **Swagger docs** — Definitions exist inline in routes but `swagger-jsdoc`  
  scans `./src/routes/*.js`. The JSDoc annotations look correct but many  
  endpoints (geoip, behavior, enforcement) lack complete definitions.

### Operational
- **No persistent refresh token store** — Logout is a no-op (client-side  
  only). Stolen tokens remain valid until expiry.
- **No database migration tooling** — `package.json` references  
  `sequelize db:migrate` but there are no migration files. `sequelize.sync()`  
  in `server.js` is development-only (creates/alters tables, destructive in  
  production with `alter: true` if needed).
- **Rate limiting is per-IP** — Behind a reverse proxy/LB, all requests  
  share one IP unless `trust proxy` is configured correctly (it is set to  
  `1`, but this needs adjustment per deployment).

---

## Files Changed

| File | Changes |
|------|---------|
| `backend/src/controllers/authController.js` | Fixed `$or` → `Op.or`, removed role escalation, JWT_SECRET validation |
| `backend/src/middleware/auth.js` | Removed hardcoded JWT_SECRET fallback, added dotenv, fixed double exports |
| `backend/src/middleware/validation.js` | Removed `role` from registration validation |
| `backend/src/middleware/security.js` | Fixed XSS sanitization, ipWhitelist memory leak, clarified CSP |
| `backend/src/config/rabbitmq.js` | Added reconnection, error handling, nack on failure, clean shutdown |
| `backend/src/server.js` | Proper graceful shutdown (all connections), deduplicate handlers |
| `backend/src/app.js` | Removed duplicate signal handlers |
| `backend/Dockerfile` | npm ci, non-root user, healthcheck |
| `frontend/Dockerfile` | npm ci, custom nginx config |
| `frontend/nginx.conf` | **New** — security headers, gzip, SPA routing, asset caching |
| `frontend/src/services/api.js` | JWT token management, auto-refresh, auth interceptors |
| `.gitignore` | **New** |
| `.env.example` | **New** — compose-level env template |
| `docker-compose.yml` | Env-var-driven credentials, RequiredVar guards |