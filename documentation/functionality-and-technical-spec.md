# Functionality and Technical Specification

_Last updated: 2026-02-24_

## Overview
This solution now includes:
- Backend API (`src/server.js`) with SQLite persistence
- Frontend (`index.html`) connected to API (no in-memory mock data)
- First-run bootstrap flow for admin creation

---

## Implemented Functional Scope

### 1) Login and users
Implemented:
- Two user types: admin and simple user.
- Admin can create/update/delete users.
- Admin can reset any user password (one-time returned 6-char password).
- Simple user can change only own password.
- Built-in `admin` user is created on first run, username fixed, protected from delete/role change.
- Optional Microsoft SSO login flow.
- Admin can enable/disable Microsoft SSO from Admin panel.
- When SSO user logs in first time, user is auto-created from token claims.

Frontend coverage:
- Login modal (user/password + Microsoft SSO button when enabled)
- Current user display near Login/Logout
- Admin Panel with user create/delete/role toggle/password reset
- Admin SSO toggle in Users tab

### 2) Floors and parking spaces
Implemented:
- No hardcoded runtime floors/spaces required.
- Admin can create/update/delete floors.
- Floor image path can be stored.
- Admin can create/update/delete spaces per floor.
- Unique `(floor_id, space_number)` enforced in DB.
- Space visual fields are stored (`x,y,w,h,dir`) and mini defaults (`map_x,map_y,map_zoom`).

Frontend coverage:
- Admin Panel floor management
- Admin Panel space creation with map coordinates/defaults
- Floor map rendering based on DB spaces

### 3) Booking and releasing
Implemented:
- Date-only filter drives current parking view.
- Admin can book for any user.
- Simple user books only for self.
- Admin can release any booking for selected date.
- Simple user can release only own booking.
- Overlap checks:
  - same space overlap blocked
  - simple user cannot hold overlapping bookings

Frontend coverage:
- Date filter in toolbar
- Book/Release button visibility by permissions
- Bookings table with short statuses: Active / Booked / Ended

---

## Technical Implementation

### Stack
- Node.js + Express
- SQLite (`better-sqlite3`)
- Password hashing (`bcryptjs`)

### Main files
- `src/server.js` — API + DB bootstrap/migrations + static hosting
- `index.html` — UI connected to API
- `resources/` — floor images
- `documentation/` — specs and install docs

### DB and startup rules
- DB file: `data/parking.sqlite3`
- DB key file: `secrets/db-access.key`
- First run (no DB):
  - DB is created
  - strong key generated and stored in secrets
  - admin must be created via bootstrap endpoint/UI
- Existing DB:
  - key hash is validated
  - if key mismatch/missing on existing DB: startup fails
  - DB is never recreated/overwritten in that case

### Security requirements implemented
- No hardcoded credentials in source.
- `data/`, `secrets/`, `.env` ignored by git.
- Passwords stored as bcrypt hashes.

---

## API Surface
- `GET /api/health`
- `POST /api/bootstrap`
- `POST /api/login`
- `GET /api/me`
- `GET /api/auth/sso/status`
- `GET /api/auth/microsoft/start`
- `GET /api/auth/microsoft/callback`
- `GET /api/admin/sso` (admin)
- `POST /api/admin/sso/toggle` (admin)
- `GET /api/users` (admin)
- `POST /api/users` (admin)
- `PATCH /api/users/:id` (admin)
- `DELETE /api/users/:id` (admin)
- `POST /api/users/:id/reset-password` (admin)
- `POST /api/me/change-password`
- `GET /api/floors`
- `POST /api/floors` (admin)
- `PATCH /api/floors/:id` (admin)
- `DELETE /api/floors/:id` (admin)
- `GET /api/spaces?floorId=<id>`
- `POST /api/spaces` (admin)
- `PATCH /api/spaces/:id` (admin)
- `DELETE /api/spaces/:id` (admin)
- `GET /api/bookings?floorId=<id>`
- `GET /api/availability?floorId=<id>&date=YYYY-MM-DD`
- `POST /api/bookings`
- `POST /api/bookings/release`
- `POST /api/seed-demo` (admin convenience endpoint)
