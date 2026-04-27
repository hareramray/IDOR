# VulnVault — sample target for IDOR Tester

A tiny Flask app with deliberate IDOR bugs. Use it as a target for the
scanner in `../backend`.

> **Do not deploy this anywhere reachable.** Every check is broken on
> purpose.

## Run

```bash
# Windows
run.bat

# macOS / Linux / Git Bash
./run.sh
```

The app starts on **http://127.0.0.1:5050** and seeds an SQLite DB
(`vulnvault.db`) on first launch. Delete that file to re-seed.

## Demo accounts

| Username | Password    | Role  | User ID |
|----------|-------------|-------|---------|
| alice    | alicepass   | user  | 1       |
| bob      | bobpass     | user  | 2       |
| admin    | adminpass   | admin | 3       |

## Endpoints and bugs

| Method | Path                       | Bug                            | Try                                     |
|--------|----------------------------|--------------------------------|-----------------------------------------|
| GET    | `/api/notes/<id>`          | Horizontal IDOR                | log in as bob, GET `/api/notes/1`       |
| PUT    | `/api/notes/<id>`          | Unauthorized modification      | bob edits alice's note                  |
| DELETE | `/api/notes/<id>`          | Unauthorized deletion          | bob deletes alice's note                |
| GET    | `/api/users/<id>`          | Profile leak (email, SSN)      | bob fetches alice's profile             |
| GET    | `/api/invoices/<id>`       | Billing data leak              | bob fetches alice's invoice             |
| GET    | `/api/admin/users`         | Vertical priv esc (header)     | non-admin sends `X-Admin: true`         |
| GET    | `/api/secure/notes/<id>`   | **Properly secured (control)** | bob gets 404 for alice's note           |

The dashboard renders raw resource IDs in `<a>` tags and `data-id`
attributes so the scanner can discover them through Playwright snapshots.

## Configuring the scanner

In the IDOR Tester UI (or a `Scan` record), use:

```jsonc
{
  "name": "VulnVault local",
  "target_url": "http://127.0.0.1:5050",
  "user_a_credentials": {
    "auth_type": "form",
    "login_url": "/login",
    "username_field": "username",
    "password_field": "password",
    "username": "alice",
    "password": "alicepass"
  },
  "user_b_credentials": {
    "auth_type": "form",
    "login_url": "/login",
    "username_field": "username",
    "password_field": "password",
    "username": "bob",
    "password": "bobpass"
  },
  "admin_credentials": {
    "auth_type": "form",
    "login_url": "/login",
    "username_field": "username",
    "password_field": "password",
    "username": "admin",
    "password": "adminpass"
  },
  "endpoints": [
    { "path": "/dashboard",         "method": "GET",    "id_location": "path" },
    { "path": "/api/notes/1",       "method": "GET",    "id_param": "id", "id_location": "path", "sample_id": "1" },
    { "path": "/api/notes/1",       "method": "PUT",    "id_param": "id", "id_location": "path", "sample_id": "1" },
    { "path": "/api/notes/1",       "method": "DELETE", "id_param": "id", "id_location": "path", "sample_id": "1" },
    { "path": "/api/users/1",       "method": "GET",    "id_param": "id", "id_location": "path", "sample_id": "1" },
    { "path": "/api/invoices/1",    "method": "GET",    "id_param": "id", "id_location": "path", "sample_id": "1" },
    { "path": "/api/admin/users",   "method": "GET",    "id_location": "header" },
    { "path": "/api/secure/notes/1","method": "GET",    "id_param": "id", "id_location": "path", "sample_id": "1" }
  ]
}
```

## Manual smoke test (curl)

```bash
# Log in as bob, save the cookie
curl -c bob.txt -X POST http://127.0.0.1:5050/login \
     -d 'username=bob&password=bobpass'

# Read alice's note (should succeed — bug)
curl -b bob.txt http://127.0.0.1:5050/api/notes/1

# Same note via the secure endpoint (should 404)
curl -b bob.txt http://127.0.0.1:5050/api/secure/notes/1

# Vertical priv esc — non-admin lists all users
curl -b bob.txt -H 'X-Admin: true' http://127.0.0.1:5050/api/admin/users
```
