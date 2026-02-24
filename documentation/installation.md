# Installation Guide (Any Machine)

For a fast setup, see: `documentation/quickstart.md`

## Requirements
- Node.js 20+ (recommended 22+)
- npm
- Linux/macOS/Windows

## 1) Get source
```bash
git clone https://github.com/alaidas/parking.git
cd parking
```

## 2) Install dependencies
```bash
npm install
```

## 3) Start application
```bash
npm start
```

Default URL:
- http://localhost:3000

The server hosts both API and `index.html`.

## 4) First run setup
On first start, DB is not present yet.

Open browser at `http://localhost:3000`:
- You will see bootstrap modal.
- Enter admin password (min 8 chars).
- Login with:
  - username: `admin`
  - password: your selected password

## 5) Runtime files
Created automatically (not committed to git):
- `data/parking.sqlite3` — SQLite DB
- `secrets/db-access.key` — generated DB access key

Important:
- Keep `secrets/db-access.key` safe.
- If DB exists and key is missing/mismatch, app fails intentionally.
- App does **not** recreate/overwrite existing DB on auth/open errors.

This creates sample floors/spaces/bookings.

## 6) Run in production style
```bash
NODE_ENV=production PORT=3000 npm start
```
Use reverse proxy (Nginx/Caddy) for TLS if internet-facing.

## 7) Backup
Backup both:
- `data/parking.sqlite3`
- `secrets/db-access.key`

Restoring only one of them is not enough.

## 8) Microsoft SSO setup (optional)

### Azure App Registration
1. In Microsoft Entra ID, create an **App registration**.
2. Add Web redirect URI:
   - `http://localhost:3000/api/auth/microsoft/callback`
3. Create a client secret.
4. Copy values:
   - Tenant ID
   - Client ID
   - Client Secret

### Local configuration
Create `.env` in project root (do not commit):

```env
MS_TENANT_ID=<tenant-id-or-common>
MS_CLIENT_ID=<client-id>
MS_CLIENT_SECRET=<client-secret>
MS_REDIRECT_URI=http://localhost:3000/api/auth/microsoft/callback
```

Then run app with env loaded (Linux/macOS):

```bash
set -a
source .env
set +a
npm start
```

### Enable in app
1. Login as admin.
2. Open **Admin Panel → Users**.
3. Click **Enable Microsoft SSO**.
4. In Login panel, use **Continue with Microsoft**.

Behavior:
- Password login remains available.
- If SSO user is new, user is auto-created in Parking DB.

## 9) Common troubleshooting
- `DB key missing while DB exists`:
  - restore `secrets/db-access.key` from backup.
- Port in use:
  - run with different port: `PORT=3001 npm start`.
- Native module install issue (`better-sqlite3`):
  - ensure supported Node version and build tools.
- SSO toggle disabled:
  - check `.env` values and restart app.
- Microsoft redirect error:
  - ensure Azure redirect URI exactly matches `MS_REDIRECT_URI`.
