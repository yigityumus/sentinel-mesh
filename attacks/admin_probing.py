#!/usr/bin/env python3
"""
SentinelMesh demo attack: admin endpoint probing by non-admin user.

Usage:
  python attacks/admin_probing.py --email testuser@example.com
  python attacks/admin_probing.py --email testuser@example.com --attempts 6 --base-url http://localhost:8080

Notes:
- This script logs in as a non-admin user
- Then attempts to access /api/admin/stats multiple times
- It should trigger the log-service admin_probing rule (>=5 denials / 120s / same IP).
"""

import argparse
import time
import sys
import json
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError


def post_json(url: str, payload: dict, headers: dict | None = None, timeout: float = 3.0) -> tuple[int, dict | str]:
    data = json.dumps(payload).encode("utf-8")
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib_request.Request(
        url,
        data=data,
        method="POST",
        headers=req_headers,
    )
    try:
        with urllib_request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(body)
            except json.JSONDecodeError:
                return resp.status, body
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, body
    except URLError as e:
        return 0, f"Network error: {e}"


def get_json(url: str, headers: dict | None = None, timeout: float = 3.0) -> tuple[int, dict | list | str]:
    req_headers = {}
    if headers:
        req_headers.update(headers)
    req = urllib_request.Request(url, method="GET", headers=req_headers)
    try:
        with urllib_request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(body)
            except json.JSONDecodeError:
                return resp.status, body
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, body
    except URLError as e:
        return 0, f"Network error: {e}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Trigger admin-probing detection via repeated unauthorized admin access.")
    parser.add_argument("--base-url", default="http://localhost:8080", help="Base URL (default: http://localhost:8080)")
    parser.add_argument("--email", required=True, help="Non-admin user email (will be created if needed)")
    parser.add_argument("--password", default="TestPassword123", help="Password for the user (default: TestPassword123)")
    parser.add_argument("--attempts", type=int, default=6, help="How many admin access attempts to send (default: 6)")
    parser.add_argument("--delay-ms", type=int, default=150, help="Delay between attempts in ms (default: 150)")
    parser.add_argument("--show-alerts", action="store_true", help="Fetch /log/alerts after attack")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    signup_url = f"{base_url}/auth/signup"
    login_url = f"{base_url}/auth/login"
    admin_url = f"{base_url}/api/admin/stats"
    alerts_url = f"{base_url}/log/alerts"

    # Step 1: Create or sign up the user
    print(f"Signing up user: {args.email} ...")
    code, body = post_json(signup_url, {"email": args.email, "password": args.password})
    if code not in (201, 409):  # 201 Created or 409 Conflict already exists
        print(f"ERROR: Signup failed with HTTP {code}")
        print(json.dumps(body, indent=2) if isinstance(body, dict) else body)
        return 1
    print(f"[signup] HTTP {code} (user ready)")

    # Step 2: Log in to get a token
    print(f"Logging in as {args.email} ...")
    code, body = post_json(login_url, {"email": args.email, "password": args.password})
    if code != 200:
        print(f"ERROR: Login failed with HTTP {code}")
        print(json.dumps(body, indent=2) if isinstance(body, dict) else body)
        return 1

    if not isinstance(body, dict) or "access_token" not in body:
        print("ERROR: No access_token in login response")
        print(body)
        return 1

    token = body["access_token"]
    print(f"[login] HTTP 200, token obtained")

    # Step 3: Attempt to access admin endpoint multiple times
    print(f"\nAttempting to access admin endpoint {args.attempts} times ...")
    headers = {"Authorization": f"Bearer {token}"}

    denied = 0
    for i in range(1, args.attempts + 1):
        code, resp_body = get_json(admin_url, headers=headers)
        is_denied = (code == 403)  # expected
        denied += 1 if is_denied else 0

        msg = ""
        if isinstance(resp_body, dict) and "detail" in resp_body:
            msg = resp_body["detail"]
        elif isinstance(resp_body, str):
            msg = resp_body[:120]

        print(f"[{i:02d}] HTTP {code} {('(expected 403)' if is_denied else '')} {msg}")
        time.sleep(args.delay_ms / 1000.0)

    print(f"Done. Sent {args.attempts} attempts (expected 403 access denials).")

    if args.show_alerts:
        code, alerts_body = get_json(alerts_url)
        print(f"\nAlerts: GET {alerts_url} -> HTTP {code}")
        print(json.dumps(alerts_body, indent=2) if not isinstance(alerts_body, str) else alerts_body)

    print("\nTip: open http://localhost:8080/alerts.html to see admin_probing alert.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
