# Parking System — Draft Functionality & Technical Setup

_Last updated: 2026-02-24_

This document updates your draft with what is **already implemented in the current mock** (`index.html`) and what is still **planned/not yet implemented**.

## 1) Functionality

## 1.1 Login & Users

### Target behavior (draft)
- Two user types: **Admin** and **Simple user**.
- Admin can create/update/delete users and grant admin role.
- Simple user cannot create users or change roles.
- Simple user can only change own password.
- Admin can reset any password.
- Password reset: old password removed, random 6-char simple password generated and shown to admin once.

### Current mock status
Implemented in mock:
- Login modal with **User** + **Password** inputs.
- Current logged-in user is shown near Login button.
- Admin mode toggle exists in UI and affects release permissions in mock logic.

Not implemented yet:
- Real authentication backend.
- User persistence/storage.
- Role management (create/update/delete users).
- Password change/reset workflows.
- One-time password reset display.

---

## 1.2 Parking Places Creation

### Target behavior (draft)
- No parking places by default.
- Admin creates floors first.
- Floor can have uploaded map image.
- Admin creates spaces for a floor; required: space number.
- `floor + space number` must be unique.
- Optional: admin sets initial mapMiniView focus per space.
- User can drag mapMiniView, and refresh should reset to admin-defined position.

### Current mock status
Implemented in mock:
- Two floors are present in mock UI.
- Spaces are rendered on map and selectable.
- Floor images are loaded from local `resources/`.
- mapMiniView exists and is draggable.
- Space selection controls initial mapMiniView center.

Not implemented yet:
- Admin CRUD for floors/spaces.
- Start with empty DB (no default spaces).
- Real image upload.
- Persisted per-space admin-defined default viewport.
- Uniqueness validation via DB constraints.

---

## 1.3 Booking / Releasing

### Target behavior (draft)
- Show parking state according to selected **date** filter.
- Admin can book any space for any user.
- Admin can release any space.
- Simple user can book only for self.
- Simple user can release only own bookings.
- Simple user cannot book more than one place in same booking range.
- User/admin can release parking for a given date if a booking range exists.

### Current mock status
Implemented in mock:
- **Date filter** (date-only) controls spot status in map and booking table state.
- Booking modal uses date-only start + duration.
- Booking overlap is blocked for same space/range.
- Book button hidden when selected space is booked at selected date.
- Release button hidden unless current user can release (owner or admin mode).
- Admin mode allows releasing any booking in mock logic.

Not implemented yet:
- Enforcement that simple user books only for self.
- Enforcement that user cannot hold >1 place in overlapping range.
- Explicit release-by-date action over ranges (separate from current selected state).
- Admin booking on behalf of any system user with persisted user directory.

---

## 2) Technical Setup

### Target behavior (draft)
- No hardcoded tokens/passwords in source control.
- DB: SQLite.
- First run: if DB missing, initialize DB.
- First run requires creating initial `admin` user (username fixed, non-changeable).
- Admin user cannot be deleted.
- Admin password can be reset by another admin.
- DB access password must be strong, generated on first start, stored safely.
- If DB missing but password exists: reuse password.
- If DB file exists but access fails/auth fails/technical error: do not create or overwrite DB.

### Current mock status
Implemented in mock:
- None of the backend/DB requirements (current app is front-end mock only).

Not implemented yet:
- SQLite schema and migrations.
- First-run bootstrap flow.
- Secure secret generation/storage.
- DB-open failure protections and strict non-overwrite behavior.
- Real auth and authorization enforcement.

---

## 3) Proposed Implementation Notes (next step)

1. Introduce backend service (Node.js + SQLite).
2. Add schema with constraints:
   - `users`, `roles`, `floors`, `spaces`, `bookings`.
   - unique `(floor_id, space_number)`.
   - protect built-in `admin` username from rename/delete.
3. Add first-run initializer:
   - detect DB existence.
   - if missing: create DB + require admin password setup.
   - generate and securely store DB encryption/access secret.
4. Add authentication + session handling.
5. Replace mock arrays with API-backed data.
6. Persist per-space mapMini default viewport.
7. Enforce booking constraints at API + DB transaction level.

---

## 4) Security Notes

- Keep secrets out of repository and out of client code.
- Prefer environment/secret store for runtime credentials.
- Never auto-create a new DB on DB open/auth failure if file exists.
- Log bootstrap and DB access failures with clear actionable errors.

---

## 5) Scope Clarification

Current `index.html` remains a **UI/behavior prototype**. The production requirements above need backend implementation and persistent storage.
