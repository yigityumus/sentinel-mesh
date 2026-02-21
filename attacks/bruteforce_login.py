#!/usr/bin/env python3
"""
SentinelMesh demo attack: brute-force login attempts to trigger detection.

Usage:
  python attacks/bruteforce_login.py --email user0@example.com --wrong-password WrongPassword123
  python attacks/bruteforce_login.py --email user0@example.com --base-url http://localhost:8080 --attempts 8

Notes:
- This intentionally sends wrong credentials multiple times.
- It should trigger the log-service brute_force_login rule (>=5 fails / 120s / same IP).
"""

import argparse
import time
import sys
import json
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError


def post_json(url: str, payload: dict, timeout: float = 3.0) -> tuple[int, dict | str]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib_request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
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


def get_json(url: str, timeout: float = 3.0) -> tuple[int, dict | list | str]:
    req = urllib_request.Request(url, method="GET")
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
    parser = argparse.ArgumentParser(description="Trigger brute-force detection via repeated failed logins.")
    parser.add_argument("--base-url", default="http://localhost:8080", help="Base URL (default: http://localhost:8080)")
    parser.add_argument("--email", required=True, help="Victim email (must exist in auth DB)")
    parser.add_argument("--wrong-password", default="WrongPassword123", help="Wrong password to use")
    parser.add_argument("--attempts", type=int, default=6, help="How many attempts to send (default: 6)")
    parser.add_argument("--delay-ms", type=int, default=150, help="Delay between attempts in ms (default: 150)")
    parser.add_argument("--show-alerts", action="store_true", help="Fetch /log/alerts after attack")
    args = parser.parse_args()

    login_url = args.base_url.rstrip("/") + "/auth/login"
    alerts_url = args.base_url.rstrip("/") + "/log/alerts"

    print(f"Target: {login_url}")
    print(f"Sending {args.attempts} failed logins for {args.email} ...")

    failures = 0
    for i in range(1, args.attempts + 1):
        code, body = post_json(login_url, {"email": args.email, "password": args.wrong_password})
        ok = (code == 401)  # expected
        failures += 1 if ok else 0

        msg = ""
        if isinstance(body, dict) and "detail" in body:
            msg = body["detail"]
        elif isinstance(body, str):
            msg = body[:120]

        print(f"[{i:02d}] HTTP {code} {('(expected 401)' if ok else '')} {msg}")

        time.sleep(args.delay_ms / 1000.0)

    print(f"Done. Sent {args.attempts} attempts (expected 401s).")

    if args.show_alerts:
        code, body = get_json(alerts_url)
        print(f"\nAlerts: GET {alerts_url} -> HTTP {code}")
        print(json.dumps(body, indent=2) if not isinstance(body, str) else body)

    print("\nTip: open http://localhost:8080/alerts.html to see alerts live.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())