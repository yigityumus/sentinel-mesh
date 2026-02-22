#!/usr/bin/env python3

import argparse
import time
import httpx


def run_attack(base_url: str, attempts: int, delay_ms: int, show_alerts: bool):
    print(f"[+] Target: {base_url}")
    print(f"[+] Sending {attempts} invalid JWT requests...\n")

    headers = {
        "Authorization": "Bearer not.a.valid.jwt",
    }

    with httpx.Client(timeout=2.0) as client:
        for i in range(1, attempts + 1):
            try:
                r = client.get(f"{base_url}/api/me", headers=headers)
                print(f"[{i:02d}] Status: {r.status_code}")
            except Exception as e:
                print(f"[{i:02d}] Request failed: {e}")

            time.sleep(delay_ms / 1000.0)

        print("\n[+] Attack complete.")

        if show_alerts:
            print("\n[+] Fetching alerts...")
            try:
                r = client.get(f"{base_url}/log/alerts")
                print(r.json())
            except Exception as e:
                print(f"Failed to fetch alerts: {e}")


def main():
    parser = argparse.ArgumentParser(description="Invalid JWT burst attack simulation")

    parser.add_argument("--base-url", default="http://localhost:8080")
    parser.add_argument("--attempts", type=int, default=12)
    parser.add_argument("--delay-ms", type=int, default=100)
    parser.add_argument("--show-alerts", action="store_true")

    args = parser.parse_args()

    run_attack(
        base_url=args.base_url,
        attempts=args.attempts,
        delay_ms=args.delay_ms,
        show_alerts=args.show_alerts,
    )


if __name__ == "__main__":
    main()
