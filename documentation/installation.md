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

### Microsoft tenant quick setup (short guide)
1. Go to Azure Portal: <https://portal.azure.com>
2. Open **Microsoft Entra ID**.
3. If you do not have a tenant yet:
   - click **Manage tenants** → **Create**
   - choose **Microsoft Entra ID**
   - provide Organization name + Initial domain + Region
   - create tenant and switch into it
4. Copy your **Tenant ID** from tenant **Overview**.

### Azure App Registration
1. In Microsoft Entra ID, open **App registrations** → **New registration**.
2. Add Web redirect URI:
   - `http://localhost:3000/api/auth/microsoft/callback`
3. Create a client secret.
4. Copy values:
   - Tenant ID
   - Client ID
   - Client Secret

### Configure in app (no `.env` needed)
1. Login as admin.
2. Open **Admin Panel → Settings**.
3. In **Microsoft SSO** section, set:
   - Tenant ID
   - Client ID
   - Client Secret
   - Redirect URI (must match Azure app exactly)
4. Enable **Microsoft SSO** checkbox.
5. Click **Save SSO settings**.
6. In Login panel, use **Continue with Microsoft**.

Behavior:
- Password login remains available.
- If SSO user is new, user is auto-created in Parking DB.
- Client secret is stored encrypted in DB.

## 9) Common troubleshooting
- `DB key missing while DB exists`:
  - restore `secrets/db-access.key` from backup.
- Port in use:
  - run with different port: `PORT=3001 npm start`.
- Native module install issue (`better-sqlite3`):
  - ensure supported Node version and build tools.
- SSO cannot be enabled:
  - check values in **Admin Panel → Settings** (tenant/client/secret/redirect).
  - ensure Client Secret is set.
- Microsoft redirect error:
  - ensure Azure redirect URI exactly matches the Redirect URI saved in **Admin Panel → Settings**.
