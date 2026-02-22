# SentinelMesh – Attack Simulation Scripts

This directory contains scripts to simulate security attacks against SentinelMesh in order to demonstrate detection capabilities.

> ⚠️ Local development and demo only. Do not run against systems you do not own or have explicit permission to test.

## Prerequisites

- SentinelMesh running (`docker compose up`)
- A user exists in the system (signup once via the web UI)
- Default base URL: `http://localhost:8080`

You can view alerts in the UI:

- `http://localhost:8080/alerts.html`

Or via API:

- `curl http://localhost:8080/log/alerts`

## 1) Brute-Force Login Simulation

**File:** `bruteforce_login.py`

This script sends multiple failed login attempts to trigger the `brute_force_login` detection rule.

### Detection Rule (Expected)

If the same IP generates:

- ≥ 5 `login_failed` events
- within 120 seconds

Then SentinelMesh creates a **high** severity alert.

### Usage

Example:

```bash
python attacks/bruteforce_login.py --email user0@example.com --show-alerts
````

Options:

```bash
--base-url        Base URL (default: http://localhost:8080)
--email           Target email (required)
--wrong-password  Wrong password to use (default: WrongPassword123)
--attempts        Number of attempts (default: 6)
--delay-ms        Delay between attempts in milliseconds (default: 150)
--show-alerts     Fetch /log/alerts after execution
```

### Expected Result

You should see multiple `401 Unauthorized` responses.

Then:

```bash
curl http://localhost:8080/log/alerts
```

Should return something like:

```json
[
  {
    "rule": "brute_force_login",
    "severity": "high",
    "ip": "...",
    "count": 5
  }
]
```

## 2) Invalid / Missing JWT Burst (Probing Simulation)

**Goal:** Trigger an alert when many requests arrive with missing/invalid JWTs (common probing / endpoint discovery behavior).

**Expected alert metadata:** a note similar to:

* `"Burst of invalid/missing JWTs (possible probing)"`

### How to reproduce (manual)

You can reproduce this without a script by repeatedly calling a protected endpoint **without** a token or with a bad token.

Example (missing token):

```bash
for i in {1..20}; do
  curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/api/me
done
```

Example (invalid token):

```bash
for i in {1..20}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Authorization: Bearer invalid.invalid.invalid" \
    http://localhost:8080/api/me
done
```

Then check alerts:

```bash
curl http://localhost:8080/log/alerts
```

> Note: the exact threshold/window depends on your log-service detection rule configuration.

## Security Story (Demo Narrative)

1. Attacker generates suspicious behavior (failed logins or invalid token bursts)
2. `auth-service` and/or protected API generates security-relevant events
3. `log-service` detects the pattern based on rules
4. Alerts are stored (Postgres)
5. Alerts are visible via API + Web UI (`/alerts.html`)

This demonstrates:

* Centralized logging
* Detection rules
* Real-time alert generation
* Microservice architecture
* PostgreSQL-backed security analytics
