# IDOR Tester

An agentic IDOR (Insecure Direct Object Reference) scanner that drives a
real browser via Playwright MCP, plans attacks with an LLM, and ships
with a deliberately vulnerable target app you can practise against.

The repo contains three pieces:

| Folder            | What it is                                      |
|-------------------|-------------------------------------------------|
| `backend/`        | Django + DRF + Channels API, the IDOR agent     |
| `frontend/`       | React (Vite) UI for configuring & watching scans|
| `vulnerable-app/` | Flask "VulnVault" — practice target with bugs   |

```
                    ┌────────── React UI (Vite, :3000)
                    │
                    │ REST + WebSocket
                    ▼
        Django + Channels (:8000) ──── SQLite (scans, findings, logs)
                    │
                    │ spawn agent thread per scan
                    ▼
           IDOR agent (Claude tool use) ──► Playwright MCP server (npx)
                    │                              │
                    │ JSON-RPC over stdio          │ controls
                    ▼                              ▼
           Claude Opus 4.7 decides       Real Chromium browser
                                                   │
                                                   ▼
                                       Target app under test
                                       (e.g. VulnVault :5050)
```

---

## 1. Prerequisites

- **Python 3.12+** (the project was developed against 3.12).
- **Node.js 18+** with `npx` on PATH (Playwright MCP runs via npx).
- **Anthropic API key** with access to the model in `ANTHROPIC_MODEL`
  (default `claude-opus-4-7`). The agent makes tool-use requests.
- **Playwright Chromium** — auto-downloaded the first time the MCP
  server runs; no extra step needed.
- Windows, macOS, or Linux. Setup scripts ship for both `*.sh` and
  `*.bat`.

---

## 2. One-shot setup

From the repo root:

```bash
# Linux / macOS / Git Bash
./setup.sh

# Windows cmd
setup.bat
```

What the script does:

1. Copies `.env.example` → `backend/.env` (edit it with your real
   `ANTHROPIC_API_KEY`).
2. Creates `backend/venv`, installs Python deps, runs Django migrations.
3. `npm install -g @playwright/mcp@latest` — the MCP server.
4. `npm install` inside `frontend/`.

Set up the practice target separately (see §5).

---

## 3. Running the scanner

Two terminals from the repo root:

```bash
# Terminal 1 — Django API + WebSocket
cd backend
source venv/Scripts/activate    # Windows: venv\Scripts\activate.bat
python manage.py runserver

# Terminal 2 — React UI
cd frontend
npm run dev
```

Open <http://localhost:3000>. Vite proxies `/api` and `/ws` traffic to
Django on `:8000`, so there's no CORS dance in dev.

---

## 4. Backend (`backend/`)

### Stack
- **Django 4.2 + DRF** — REST API at `/api/`.
- **Channels + Daphne** — WebSocket transport for live scan logs.
- **Anthropic Python SDK** — drives the agentic loop with Claude tool use.
- **MCP Python SDK** — talks to `@playwright/mcp` over stdio JSON-RPC.

### Layout
```
backend/
├── core/                  Django project (settings, ASGI/WSGI, URLs)
├── scanner/
│   ├── models.py          Scan, Finding, ScanLog
│   ├── serializers.py     DRF input/output schemas + validation
│   ├── views.py           ScanViewSet, FindingViewSet, /start, /cancel
│   ├── urls.py            DRF router → /api/scans, /api/findings
│   ├── consumers.py       WS consumer pushing live log events
│   ├── routing.py         WS routes
│   ├── migrations/        0001_initial.py (created by makemigrations)
│   └── agent/
│       ├── browser.py     Playwright MCP client (PlaywrightMCPBrowser)
│       ├── idor_agent.py  IDORAgent — orchestration + LLM calls
│       └── prompts.py     System prompt + planning + analysis prompts
├── manage.py
└── requirements.txt
```

### Data model
- `Scan` — one scan session. Owns target URL, two user credential
  bundles (User A = victim, User B = attacker), optional admin creds,
  endpoints to test, config flags, and rolled-up counters.
- `Finding` — a single positive or negative test result. Stores
  request/response evidence, severity, IDOR type
  (horizontal / vertical / data leak / unauthorized modify / delete),
  and the LLM's analysis.
- `ScanLog` — append-only line of `level + message + details` streamed
  to the UI via WebSocket and persisted for replay.

### REST endpoints
| Method | Path                                       | Purpose                          |
|--------|--------------------------------------------|----------------------------------|
| GET    | `/api/scans/`                              | List scans (summary)             |
| POST   | `/api/scans/`                              | Create a scan                    |
| GET    | `/api/scans/{id}/`                         | Scan detail with findings + logs |
| POST   | `/api/scans/{id}/start/`                   | Launch agent in a worker thread  |
| POST   | `/api/scans/{id}/cancel/`                  | Cooperative cancel               |
| GET    | `/api/scans/{id}/findings/?severity=`      | Filter findings by severity      |
| GET    | `/api/scans/{id}/logs/?after=ISO8601`      | Poll logs after a timestamp      |
| GET    | `/api/findings/?scan={id}`                 | Cross-scan finding list          |

### WebSocket
- Path: `/ws/scans/{scan_id}/`
- Group: `scan_<id>`
- Each `ScanLog.objects.create()` emits a `scan_log` event with
  `level`, `message`, `details`, `created_at`.

### How a scan runs (`scanner/agent/idor_agent.py`)
1. **Spin up MCP** — `PlaywrightMCPBrowser.start()` runs
   `npx -y @playwright/mcp@latest` over stdio JSON-RPC (headless
   controlled by `BROWSER_HEADLESS`). It caches the 21-ish browser
   tools so the LLM can request them.
2. **Login as User A** — the LLM gets a prompt + the MCP tools and
   drives a real browser through `browser_navigate` → `browser_snapshot`
   → `browser_type` → `browser_click`. Bearer / custom-header auth modes
   inject into `window.fetch` via `browser_console_exec`.
3. **Collect User A's resources** — for each endpoint, the agent
   navigates and extracts numeric IDs / UUIDs from the snapshot (regex
   fallback if the LLM-parsed JSON is malformed).
4. **Capture per-endpoint baseline** snapshots (User A's view).
5. **Switch tabs, login as User B** with a fresh session; collect User
   B's IDs too.
6. **LLM plans** — `PLAN_TESTS_PROMPT` is templated with both users'
   data; Claude emits a JSON test plan (one test case per attack idea).
7. **Edge-case generator** appends mechanical variants:
   sequential ±1, base64/hex/url encoding, parameter pollution, body
   injection, content-type swaps, etc. (see `_generate_id_variants`,
   `_generate_edge_case_tests`).
8. **Execute** — each test runs in the User B browser tab; for non-GET
   methods the agent calls `fetch()` via `browser_console_exec`. The
   response goes back to the LLM with the baseline for analysis. The
   LLM returns `is_vulnerable / severity / explanation / remediation`,
   which becomes a `Finding`.
9. **Unauthenticated pass** — fresh tab with cookies cleared; if an
   endpoint serves real content (no `login` in the response) it gets
   flagged as a candidate vertical IDOR.
10. **Summary** — Claude is asked for an executive summary of the
    vulnerable findings; the scan is marked completed.

### Configuration (`backend/.env`)
```dotenv
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-opus-4-7    # or claude-sonnet-4-6 for ~5x cheaper
DJANGO_SECRET_KEY=change-me
DEBUG=True
BROWSER_HEADLESS=false   # false = visible window during scans
```

### Concurrency caveat
The agent runs in a `threading.Thread` and creates its own asyncio
event loop. Sync ORM calls inside that coroutine trip Django's
`async_unsafe` guard, so `views._run_scan_in_thread` sets
`DJANGO_ALLOW_ASYNC_UNSAFE=true` before importing the agent. This is
safe here because each scan owns its thread and loop, and ORM access
is serial — but if you ever swap in an async DB driver, switch to
`asgiref.sync.sync_to_async` instead.

---

## 5. Practice target — VulnVault (`vulnerable-app/`)

A small Flask app with intentional IDOR bugs. Use it as the first
target while you wire up the scanner.

```bash
cd vulnerable-app
./run.sh           # or run.bat on Windows
```

It listens on **<http://127.0.0.1:5050>** and seeds an SQLite DB
(`vulnvault.db`) on first launch.

### Demo accounts
| Username | Password    | Role  | User ID |
|----------|-------------|-------|---------|
| alice    | alicepass   | user  | 1       |
| bob      | bobpass     | user  | 2       |
| admin    | adminpass   | admin | 3       |

### Endpoints and intentional bugs
| Method | Path                       | Bug                          |
|--------|----------------------------|------------------------------|
| GET    | `/api/notes/<id>`          | Horizontal IDOR              |
| PUT    | `/api/notes/<id>`          | Unauthorized modification    |
| DELETE | `/api/notes/<id>`          | Unauthorized deletion        |
| GET    | `/api/users/<id>`          | Profile leak (email, SSN)    |
| GET    | `/api/invoices/<id>`       | Billing data leak            |
| GET    | `/api/admin/users`         | Vertical priv esc (`X-Admin`)|
| GET    | `/api/secure/notes/<id>`   | **Properly secured (control)**|

The HTML dashboard renders raw resource IDs into `<a>` and `data-id`
attributes so the scanner can discover them through Playwright
snapshots. See `vulnerable-app/README.md` for a paste-ready scan config
and curl-based smoke tests.

---

## 6. Frontend (`frontend/`)

### Stack
- **React 18 + Vite** (port 3000, proxies `/api` and `/ws` to Django).
- **react-router-dom** for the three pages.
- **axios** for REST.
- **lucide-react** for icons.

### Layout
```
frontend/
├── src/
│   ├── api.js          axios client + endpoint helpers
│   ├── App.jsx         router + layout
│   ├── App.css         design tokens, cards, forms, severity colours
│   ├── main.jsx        entry
│   └── pages/
│       ├── Dashboard.jsx   list of scans with status & counts
│       ├── NewScan.jsx     scan-config form + JSON import/export
│       └── ScanDetail.jsx  live logs, findings, evidence
├── index.html
├── package.json
└── vite.config.js
```

### Pages
- **Dashboard** — every scan with status, total tests, vulnerability
  count, click-through to detail.
- **New Scan** — three credential blocks (User A, User B, optional
  admin), endpoint editor, config flags, and a **JSON Import / Export**
  panel. Paste the same JSON shape the API accepts and click
  *Apply JSON* to populate the form; *Export current form* dumps the
  live state back out. *Load sample* drops the VulnVault config in.
- **Scan Detail** — live log stream over WebSocket, findings list with
  severity badges, evidence (request, attack response, baseline) per
  finding, and a cancel button while running.

---

## 7. End-to-end demo

```bash
# Terminal 1 — VulnVault
cd vulnerable-app && ./run.sh

# Terminal 2 — backend
cd backend && source venv/Scripts/activate && python manage.py runserver

# Terminal 3 — frontend
cd frontend && npm run dev
```

In the UI:

1. Open <http://localhost:3000/scans/new>.
2. **Import / Export via JSON → Show → Load sample → Apply JSON**.
3. **Launch IDOR Scan**.
4. Watch a Chromium window log alice in, then bob, then run dozens of
   tests. The detail page streams logs and fills with findings as the
   LLM analyses each response.

Expected outcome on VulnVault: high/critical findings on every
endpoint *except* `/api/secure/notes/<id>`, which should come back as
properly protected.

---

## 8. Troubleshooting

- **`no such table: scanner_scan`** — run `python manage.py migrate`
  in `backend/` (the `0001_initial` migration has to be applied to a
  fresh `db.sqlite3`).
- **`Scan failed: Connection closed` immediately after starting MCP** —
  almost always an `npx` flag mismatch. Make sure
  `backend/scanner/agent/browser.py` uses
  `args = ["-y", "@playwright/mcp@latest"]` and only appends
  `--headless` when `BROWSER_HEADLESS=true` (newer
  `@playwright/mcp` runs headed by default).
- **`You cannot call this from an async context`** — make sure the
  `DJANGO_ALLOW_ASYNC_UNSAFE=true` set in `views._run_scan_in_thread`
  is still in place.
- **First scan is very slow** — the Playwright Chromium download
  happens on the first MCP launch. Subsequent scans hit the cache at
  `%LOCALAPPDATA%\ms-playwright` (Windows) /
  `~/Library/Caches/ms-playwright` (mac) /
  `~/.cache/ms-playwright` (Linux).
- **Login step succeeds but resource collection finds nothing** — the
  agent extracts IDs from rendered DOM snapshots. Make sure the
  endpoint pages actually render IDs in `<a href>` or `data-id`
  attributes (or list them in JSON). VulnVault's dashboard already
  does this; copy the pattern when targeting your own apps.

---

## 9. License

Licensed under the **Apache License, Version 2.0**. See [`LICENSE`](LICENSE)
for the full text.

```
Copyright 2026 Hareram Ray

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
```

---

## 10. Safety

- **Only scan apps you own or have written authorisation to test.**
- The scanner sends real PUT/DELETE/etc. requests as User B against
  the target. Run it against staging or a dedicated test user.
- VulnVault is intentionally vulnerable — never expose it to the
  internet.
- Treat `backend/.env` and `vulnerable-app/vulnvault.db` as untrusted
  artefacts; both are in `.gitignore`.
