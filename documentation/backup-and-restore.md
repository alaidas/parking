# Backup and Restore

This application must back up both of these files together:

- `data/parking.sqlite3`
- `secrets/db-access.key`

If the database is restored without the matching key file, the server will refuse to open the database.

## Backup

1. Stop the application process or put it into maintenance mode.
2. Copy `data/parking.sqlite3`.
3. Copy `secrets/db-access.key`.
4. Store both files in the same backup set with the same timestamp.
5. Verify the backup can be read.

## Restore

1. Stop the application process.
2. Restore `data/parking.sqlite3` to the `data/` directory.
3. Restore the matching `secrets/db-access.key` to the `secrets/` directory.
4. Start the application.
5. Verify:
   - `GET /api/health` returns `ok: true`
   - admin login works
   - floors, spaces, and bookings are visible

## Test Procedure

Before production release, run one full restore test in staging:

1. Create test data.
2. Take a backup set.
3. Delete the staging `data/` and `secrets/` contents.
4. Restore from the backup set.
5. Confirm the application starts and the restored data is intact.
