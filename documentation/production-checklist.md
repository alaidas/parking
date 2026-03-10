# Production Checklist

_Prepared for this repository on 2026-03-10_

This checklist is specific to the current codebase:
- backend in `src/server.js`
- frontend in `index.html`
- SQLite database in `data/parking.sqlite3`
- DB access key in `secrets/db-access.key`

## Release Blockers

These items should be completed before a production release.

- [ ] Replace in-memory sessions with production-safe auth.
  Current state: sessions are stored in a process-local `Map` in `src/server.js`.
  Required outcome: use expiring JWTs or persistent server-side sessions backed by SQLite or Redis.

- [ ] Add token/session expiration and logout invalidation.
  Current state: issued bearer tokens do not expire.
  Required outcome: enforce session lifetime, revocation, and forced logout after password reset or admin action.

- [ ] Rework Microsoft SSO validation to use a proper OpenID Connect library.
  Current state: the code decodes `id_token` claims manually and does not fully verify token signature, issuer, audience, and expiry.
  Required outcome: standards-based verification for Microsoft login.

- [ ] Add rate limiting to authentication-sensitive endpoints.
  Minimum endpoints:
  - `POST /api/login`
  - `POST /api/bootstrap`
  - `GET /api/auth/microsoft/start`
  - `GET /api/auth/microsoft/callback`
  - `POST /api/users/:id/reset-password`

- [ ] Add request validation for all write endpoints.
  Current state: validation is mostly ad hoc string trimming and basic checks.
  Required outcome: schema validation for request bodies, route params, and query params.

- [ ] Remove development fallback behavior for the database key.
  Current state: `cryptoKey()` can fall back to a hardcoded development key if the key file is absent.
  Required outcome: production startup must fail if the expected key is missing or invalid.

- [ ] Protect the bootstrap flow.
  Current state: first-run admin creation is exposed through `POST /api/bootstrap`.
  Required outcome: restrict bootstrap to install-time only and ensure it cannot be reused after initialization.

- [ ] Harden booking writes against race conditions.
  Current state: overlap checks are performed in application code before insert/update.
  Required outcome: transactional booking creation/release with concurrency-safe checks.

- [ ] Add backup and restore procedures.
  Required outcome: documented and tested backup of both:
  - `data/parking.sqlite3`
  - `secrets/db-access.key`

- [ ] Add automated test coverage for critical flows.
  Minimum coverage:
  - bootstrap and login
  - user management
  - floor and space CRUD
  - booking overlap rules
  - booking release and split behavior
  - SSO configuration and guard rails

## Strongly Recommended

- [ ] Split `src/server.js` into modules.
  Suggested separation:
  - auth
  - SSO
  - bookings
  - users/admin
  - DB setup and migrations
  - uploads/static hosting

- [ ] Replace console-only logging with structured logs.
  Required outcome: request context, error IDs, and operational events are searchable.

- [ ] Add error monitoring.
  Required outcome: unhandled exceptions and failed auth/SSO flows are visible outside local logs.

- [ ] Move runtime configuration to environment variables or a secret manager.
  Suggested config:
  - app base URL
  - port
  - token/session settings
  - SSO redirect URL
  - upload limits
  - log level

- [ ] Add HTTPS/TLS in front of the app.
  Required outcome: production traffic is served only through HTTPS, with the real domain reflected in redirect URIs.

- [ ] Add security headers.
  At minimum consider:
  - `Content-Security-Policy`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `X-Frame-Options` or equivalent frame policy

- [ ] Validate uploaded floor images by content, not only extension or declared MIME.
  Required outcome: size, type, and decode checks are enforced before writing files.

- [ ] Add audit logging for admin actions.
  Important events:
  - user create/update/delete
  - password resets
  - SSO configuration changes
  - floor and space changes
  - admin-created bookings and releases

- [ ] Add health and readiness endpoints with deployment meaning.
  Current state: `/api/health` is minimal.
  Required outcome: distinguish process-up vs app-ready, including DB availability checks.

- [ ] Add deployment and operations documentation.
  Include:
  - environment variables
  - backup/restore
  - update procedure
  - restart behavior
  - log locations
  - rollback steps

## Deployment Decisions To Make

- [ ] Confirm expected scale.
  If this will remain a small internal deployment, SQLite may be acceptable.
  If you need multiple app instances, higher concurrency, or managed failover, move to PostgreSQL.

- [ ] Confirm auth model.
  Choose one:
  - stateless JWTs with expiry and revocation strategy
  - server-side sessions with persistent store

- [ ] Confirm hosting model.
  Choose one:
  - single VM with reverse proxy
  - containerized deployment
  - platform service

- [ ] Confirm where uploads will live.
  Choose one:
  - local disk with backup policy
  - object storage

## Suggested Release Sequence

1. Refactor auth and session handling.
2. Replace manual SSO token handling with a proper OIDC implementation.
3. Add input validation and rate limiting.
4. Make booking writes transactional and concurrency-safe.
5. Add automated tests for the critical paths.
6. Move config to environment variables and remove unsafe defaults.
7. Add structured logging, health/readiness, and backup/restore procedures.
8. Deploy to staging behind HTTPS.
9. Verify restart behavior, restore procedure, login, SSO, booking, and admin flows in staging.
10. Release production.

## Minimum Acceptance Criteria For Production

Do not release until all of the following are true:

- [ ] Auth tokens or sessions expire.
- [ ] Login and SSO endpoints are rate-limited.
- [ ] Microsoft SSO tokens are fully verified.
- [ ] Bootstrap is locked down.
- [ ] Critical API flows have automated tests.
- [ ] Backup and restore have been tested successfully.
- [ ] Production config is externalized.
- [ ] HTTPS is enabled.
- [ ] Logs are sufficient to investigate incidents.
