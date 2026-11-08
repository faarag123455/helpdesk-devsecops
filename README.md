# HelpDesk DevSecOps

HelpDesk is a deliberately vulnerable ticketing application built for TEK-UP
DevSecOps coursework. It runs locally with Flask, PostgreSQL, Jinja templates,
raw SQL, and Flask sessions. The vulnerabilities are intentional training
fixtures for demonstrating static analysis, secret scanning, dependency
scanning, and dynamic application testing.

> **Warning:** Run this project only on a local development machine with fake
> data. Do not expose it to a network or use real credentials.

## Stack

- Python 3.11
- Flask 2.2.2
- Werkzeug 2.2.2
- PostgreSQL 15
- psycopg2-binary
- Jinja templates
- Docker Compose for PostgreSQL

## Project layout

```text
app/
  app.py                 Flask routes and application startup
  config.py              Environment settings and intentional fake secrets
  db.py                  PostgreSQL connection and query helpers
  schema.sql             Database tables
  docker-compose.yml     Local PostgreSQL service
  requirements.txt       Python dependencies
  templates/             Jinja HTML templates
  static/style.css       Application styling
exploit_pickle.py        Local VULN-11 payload generator
```

## Local setup on Windows PowerShell

Run these commands from the repository root. Docker Desktop must be running.

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -r .\app\requirements.txt

docker compose -f .\app\docker-compose.yml up -d postgres
Start-Sleep -Seconds 5

Get-Content .\app\schema.sql -Raw |
  docker compose -f .\app\docker-compose.yml exec -T postgres psql -U helpdesk -d helpdesk -f -

$env:FLASK_HOST = "127.0.0.1"
$env:FLASK_DEBUG = "1"
$env:SECRET_KEY = "local-development-secret"
$env:DB_HOST = "localhost"
$env:DB_PORT = "5432"
$env:DB_NAME = "helpdesk"
$env:DB_USER = "helpdesk"
$env:DB_PASSWORD = "fake-db-password-123"

Set-Location .\app
python .\app.py
```

Open [http://127.0.0.1:5000/](http://127.0.0.1:5000/). The application defaults
to the loopback host, and PostgreSQL is published only on
`127.0.0.1:5432`.

To stop PostgreSQL:

```powershell
docker compose -f .\app\docker-compose.yml down
```

## Application features

### Authentication and roles

- `/register` creates regular user accounts.
- `/login` and `/logout` manage Flask sessions.
- `user` accounts can create and comment on their own tickets.
- `agent` accounts can view, comment on, assign, and close tickets.
- `admin` accounts have user-management features.

### Tickets

- `/tickets` lists tickets visible to the current role.
- `/tickets/new` creates a ticket.
- `/tickets/<id>` displays a ticket and its comments.
- `/tickets/<id>/comment` adds a comment.
- `/tickets/<id>/assign` assigns a ticket to an agent or admin.
- `/tickets/<id>/close` closes a ticket.
- `/tickets/<id>/attach-url` fetches and stores a remote response.
- `/tickets/<id>/preview` renders a submitted template preview.

### Search and administration

- `/search?q=` searches ticket titles.
- `/admin/users` lists users and role controls.
- `/admin/users/<id>/role` changes a user role.
- `/admin/diagnostics` runs a host connectivity diagnostic.
- `/tickets/save-preset` stores a ticket filter preset.
- `/tickets/load-preset` loads the saved preset.

## Intentional vulnerability inventory

These vulnerabilities are intentionally present for scanner demonstrations.
They should not be deployed or exposed outside the local coursework environment.

| ID | Vulnerability | Location |
|---|---|---|
| VULN-1 | SQL injection in ticket search | `app/app.py`, `/search` |
| VULN-2 | Stored XSS in ticket comments | `app/templates/ticket_detail.html` |
| VULN-3 | IDOR in ticket detail access | `app/app.py`, `/tickets/<id>` |
| VULN-4 | Login-only admin user management | `app/app.py`, `/admin/users` |
| VULN-5 | Hardcoded fake secrets | `app/config.py` |
| VULN-6 | Flask debug mode enabled by default | `app/app.py` |
| VULN-7 | Intentionally old Flask/Werkzeug dependencies | `app/requirements.txt` |
| VULN-8 | OS command injection in diagnostics | `app/app.py`, `/admin/diagnostics` |
| VULN-9 | SSRF in ticket URL attachments | `app/app.py`, `/tickets/<id>/attach-url` |
| VULN-10 | Server-side template injection | `app/app.py`, `/tickets/<id>/preview` |
| VULN-11 | Insecure pickle deserialization | `app/app.py`, `/tickets/load-preset` |

Each planted vulnerability is marked next to its implementation with a
`VULN-*` comment to make the later remediation exercise easy to navigate.

## Logging

The application logs to stdout:

- One line per request with timestamp, method, path, status, and username.
- Failed login attempts.
- Search query values.
- Diagnostics host values.
- Submitted preview template values.
- Attachment URLs.
- Preset-load events.

Passwords, tokens, and session cookies are not logged.

## Testing and security tooling

The project is intended to be scanned before remediation with:

- Semgrep for source vulnerabilities
- Gitleaks for fake secrets
- Trivy for dependency and image findings
- OWASP ZAP for runtime web testing

The `exploit_pickle.py` helper prints a base64-encoded pickle payload for
testing VULN-11 against the local `/tickets/load-preset` route. It only
generates the payload; execution occurs when the value is supplied as the
`ticket_preset` cookie.

## Cleanup

Stop the Flask process with `Ctrl+C`, then stop PostgreSQL:

```powershell
docker compose -f .\app\docker-compose.yml down
```
