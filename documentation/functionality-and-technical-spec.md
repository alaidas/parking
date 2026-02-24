# Parking System — Functionality and Technical Spec

_Last updated: 2026-02-24_

This document reflects the current implementation in `src/server.js`.

## 1. Implemented Functionality

## 1.1 Authentication & Users

Implemented:
- Login with username/password: `POST /api/login`
- First system run bootstrap: `POST /api/bootstrap` creates fixed username `admin`
- Roles: admin and simple user (`is_admin`)
- Admin can create/update/delete users:
  - `POST /api/users`
  - `PATCH /api/users/:id` (role update)
  - `DELETE /api/users/:id`
- Admin can reset any user password:
  - `POST /api/users/:id/reset-password`
  - Generates random 6-char simple password and returns once in response
- Simple user can change own password:
  - `POST /api/me/change-password`

Implemented constraints:
- Built-in `admin` username is created on bootstrap and protected:
  - cannot be deleted
  - role cannot be changed

## 1.2 Floors and Parking Spaces

Implemented:
- Admin floor CRUD:
  - `POST /api/floors`
  - `PATCH /api/floors/:id`
  - `DELETE /api/floors/:id`
- Admin parking space CRUD:
  - `POST /api/spaces`
  - `PATCH /api/spaces/:id`
  - `DELETE /api/spaces/:id`
- Space uniqueness guaranteed by DB constraint: `UNIQUE(floor_id, space_number)`
- Optional per-space map mini defaults stored:
  - `map_x`, `map_y`, `map_zoom`

## 1.3 Booking / Releasing

Implemented:
- Date-based availability for a floor:
  - `GET /api/availability?floorId=<id>&date=YYYY-MM-DD`
- Booking creation:
  - `POST /api/bookings`
- Releasing by date:
  - `POST /api/bookings/release`

Implemented rules:
- Admin can book on behalf of any user (optional `userId` in request).
- Simple user can book only for self.
- Space overlapping bookings are blocked.
- Simple user cannot hold overlapping bookings across spaces.
- Simple user can release only own booking at given date.
- Admin can release any booking at given date; optional `userId` check supported.

## 2. Technical Setup (Implemented)

## 2.1 Stack
- Node.js + Express
- SQLite via `better-sqlite3`
- Password hashing via `bcryptjs`

## 2.2 Source Structure
- `src/server.js` — API server and startup logic
- `documentation/functionality-and-technical-spec.md` — this doc
- `.gitignore` excludes secrets/database/runtime artifacts

## 2.3 Database & First Run

Implemented behavior:
- DB path: `data/parking.sqlite3`
- If DB file is missing:
  - creates DB and schema
  - generates strong random DB access key and stores in `secrets/db-access.key`
  - requires bootstrap of initial admin via `/api/bootstrap`
- If DB exists:
  - key file must exist and match stored hash in DB (`meta.db_key_hash`)
  - if mismatch/missing key, startup fails

Safety behavior:
- DB is never deleted/overwritten by application logic.
- If DB exists and access/authorization fails, service fails fast and does not recreate DB.
- If DB is missing but key exists, existing key is reused.

## 2.4 Security Notes
- No hardcoded passwords/tokens in source.
- Secrets and DB files are git-ignored:
  - `secrets/`
  - `data/`
  - `.env`
- Passwords are stored hashed (bcrypt), never plaintext.

## 3. API Summary

- `GET /api/health`
- `POST /api/bootstrap`
- `POST /api/login`
- `POST /api/users` (admin)
- `PATCH /api/users/:id` (admin)
- `DELETE /api/users/:id` (admin)
- `POST /api/users/:id/reset-password` (admin)
- `POST /api/me/change-password`
- `POST /api/floors` (admin)
- `PATCH /api/floors/:id` (admin)
- `DELETE /api/floors/:id` (admin)
- `POST /api/spaces` (admin)
- `PATCH /api/spaces/:id` (admin)
- `DELETE /api/spaces/:id` (admin)
- `GET /api/availability`
- `POST /api/bookings`
- `POST /api/bookings/release`

## 4. Notes
- Frontend mock (`index.html`) is still separate and not yet wired to API endpoints.
- Next step: connect mock UI actions to these APIs and replace in-memory data.
