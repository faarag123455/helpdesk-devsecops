#!/usr/bin/env python3
"""
HelpDesk "Security Proof" - automated exploitation tests.

For each intentional vulnerability (VULN-1 .. VULN-11), this script tries the
real attack against a running instance of HelpDesk and reports whether it
actually succeeds ("exploitable") or was blocked ("blocked").

This is NOT a vulnerability scanner: it performs the real attack steps
described in the project's report, against our own lab application only.
It never touches any other host, and APP_URL must point at the app started
by the pipeline (or at your local docker compose instance).

Usage:
    APP_URL=http://127.0.0.1:5000 python run_tests.py

Output:
    - security-tests/exploit-report.json  (machine-readable, one entry per test)
    - security-tests/exploit-report.md     (human-readable table)
    - exit code is always 0: this script NEVER fails the pipeline by itself.
      Whether "exploitable" findings should block the pipeline is a policy
      decision made later in .github/workflows/security.yml, once the team
      agrees the app should be clean.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sys
import time
from dataclasses import dataclass, field

import requests

APP_URL = os.environ.get("APP_URL", "http://127.0.0.1:5000").rstrip("/")
TIMEOUT = 10


@dataclass
class Result:
    vuln_id: str
    name: str
    exploitable: bool
    detail: str


RESULTS: list[Result] = []


def record(vuln_id: str, name: str, exploitable: bool, detail: str) -> None:
    RESULTS.append(Result(vuln_id, name, exploitable, detail))
    status = "EXPLOITABLE" if exploitable else "blocked"
    print(f"[{vuln_id}] {name}: {status} - {detail}")


def wait_for_app(max_wait: int = 60) -> None:
    """Poll the app until it responds, so the pipeline doesn't race the container."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            r = requests.get(APP_URL + "/login", timeout=TIMEOUT)
            if r.status_code < 500:
                print(f"App is up at {APP_URL} (status {r.status_code})")
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise SystemExit(f"App never became ready at {APP_URL} after {max_wait}s")


def unique(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(4)}"


def register(session: requests.Session, username: str, email: str, password: str) -> None:
    r = session.post(
        APP_URL + "/register",
        data={"username": username, "email": email, "password": password},
        timeout=TIMEOUT,
        allow_redirects=True,
    )
    if r.status_code not in (200, 302):
        raise RuntimeError(f"register({email}) failed: HTTP {r.status_code}")


def login(session: requests.Session, email: str, password: str) -> None:
    r = session.post(
        APP_URL + "/login",
        data={"email": email, "password": password},
        timeout=TIMEOUT,
        allow_redirects=True,
    )
    if r.status_code != 200 or "Invalid email or password" in r.text:
        raise RuntimeError(f"login({email}) failed: HTTP {r.status_code}")


def new_user(role_hint: str) -> dict:
    """Create and log in a fresh throwaway test account. Returns its session + info."""
    username = unique(role_hint)
    email = f"{username}@example.invalid"
    password = "TestPassw0rd!"
    session = requests.Session()
    register(session, username, email, password)
    login(session, email, password)
    return {"session": session, "username": username, "email": email}


def create_ticket(session: requests.Session, title: str, description: str) -> int:
    r = session.post(
        APP_URL + "/tickets/new",
        data={"title": title, "description": description, "priority": "medium"},
        timeout=TIMEOUT,
        allow_redirects=True,
    )
    if r.status_code != 200:
        raise RuntimeError(f"create_ticket failed: HTTP {r.status_code}")
    # The app redirects to /tickets/<id> after creation; pull the id from the final URL.
    match = re.search(r"/tickets/(\d+)", r.url)
    if not match:
        raise RuntimeError(f"could not find ticket id in final URL: {r.url}")
    return int(match.group(1))


# -----------------------------------------------------------------------------
# VULN-1: SQL injection in /search (app/app.py)
#
# The app builds its query as:
#   WHERE t.title ILIKE '%{query_text}%' {visibility}
# where {visibility} is "AND t.created_by = <id>" for a normal user, or empty
# for agent/admin. A payload that closes the quote and comments out (or
# always-trues) the rest removes the "created_by" filter, so a normal user
# can see other users' tickets.
# -----------------------------------------------------------------------------
def test_vuln1_sql_injection_search() -> None:
    alice = new_user("alice")
    bob = new_user("bob")

    secret_title = f"ALICE-PRIVATE-TICKET-{secrets.token_hex(4)}"
    create_ticket(alice["session"], secret_title, "Only Alice should be able to find this.")

    # Baseline: Bob searching for an unrelated term must not see Alice's ticket.
    baseline = bob["session"].get(APP_URL + "/search", params={"q": "no-such-ticket-xyz"}, timeout=TIMEOUT)
    if secret_title in baseline.text:
        record("VULN-1", "SQL injection (/search)", True,
               "Alice's ticket leaked even on an unrelated search term (unexpected).")
        return

    # Attack: classic "always true" payload that breaks out of the quoted LIKE
    # pattern and neutralises the "AND t.created_by = ..." filter.
    payload = "x%' OR '1'='1"
    attack = bob["session"].get(APP_URL + "/search", params={"q": payload}, timeout=TIMEOUT)
    leaked = secret_title in attack.text

    record(
        "VULN-1",
        "SQL injection (/search)",
        leaked,
        (f"Bob retrieved Alice's private ticket via payload q={payload!r}"
         if leaked else
         "Bob could not retrieve Alice's ticket; filter/parameterization holds."),
    )


TESTS = [
    test_vuln1_sql_injection_search,
    # VULN-2 .. VULN-11 will be added here, one function per vulnerability.
]


def main() -> int:
    wait_for_app()

    for test in TESTS:
        try:
            test()
        except Exception as exc:  # a broken test must not crash the whole run
            record(test.__name__, test.__name__, True, f"TEST ERROR (treated as exploitable/unknown): {exc}")

    exploitable = sum(1 for r in RESULTS if r.exploitable)
    total = len(RESULTS)

    report = {
        "app_url": APP_URL,
        "total": total,
        "exploitable": exploitable,
        "blocked": total - exploitable,
        "results": [r.__dict__ for r in RESULTS],
    }
    with open("exploit-report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    lines = [
        "# HelpDesk exploitation test results",
        "",
        f"**{exploitable} / {total} vulnerabilities are currently exploitable.**",
        "",
        "| ID | Name | Result | Detail |",
        "|---|---|---|---|",
    ]
    for r in RESULTS:
        status = "EXPLOITABLE" if r.exploitable else "blocked"
        lines.append(f"| {r.vuln_id} | {r.name} | {status} | {r.detail} |")
    md = "\n".join(lines) + "\n"
    with open("exploit-report.md", "w", encoding="utf-8") as f:
        f.write(md)
    print("\n" + md)

    # This script always exits 0: the pipeline's job decides, via its own
    # policy step, whether "exploitable" findings should block the build.
    return 0


if __name__ == "__main__":
    sys.exit(main())
