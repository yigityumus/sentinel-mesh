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

**File:** `invalid_token_burst.py`

This script sends multiple requests with missing or invalid JWT tokens to trigger the `invalid_token_burst` detection rule.

### Detection Rule (Expected)

If the same IP generates:

- ≥ 10 `invalid_token`, `invalid_token_claims`, or `missing_token` events
- within 120 seconds

Then SentinelMesh creates a **medium** severity alert.

### Usage

Example:

```bash
python attacks/invalid_token_burst.py --show-alerts
```

Options:

```bash
--base-url        Base URL (default: http://localhost:8080)
--attempts        Number of attempts (default: 15)
--delay-ms        Delay between attempts in milliseconds (default: 100)
--show-alerts     Fetch /log/alerts after execution
```

### Expected Result

You should see multiple `401 Unauthorized` responses.

Then:

```bash
curl http://localhost:8080/log/alerts
```

Should return an alert with:

```json
{
  "rule": "invalid_token_burst",
  "severity": "medium",
  "ip": "...",
  "count": 10
}
```

## 3) Admin Endpoint Probing Simulation

**File:** `admin_probing.py`

This script simulates a non-admin user attempting to access protected admin endpoints repeatedly, triggering the `admin_probing` detection rule.

### Detection Rule (Expected)

If the same IP generates:

- ≥ 5 `unauthorized_admin_access` events
- within 120 seconds

Then SentinelMesh creates a **medium** severity alert.

### Usage

Example:

```bash
python attacks/admin_probing.py --email attacker@example.com --password PassAttacker1. --attempts 6 --show-alerts
```

Options:

```bash
--base-url        Base URL (default: http://localhost:8080)
--email           Non-admin user email (required; will be created if needed)
--password        Password for the user (default: TestPassword123)
--attempts        Number of admin access attempts (default: 6)
--delay-ms        Delay between attempts in milliseconds (default: 150)
--show-alerts     Fetch /log/alerts after execution
```

### Expected Result

The script will:

1. Sign up a regular (non-admin) user
2. Log in to obtain a valid JWT token
3. Attempt to access `/api/admin/stats` multiple times (expecting 403 Forbidden)

Then:

```bash
curl http://localhost:8080/log/alerts
```

Should return an alert with:

```json
{
  "rule": "admin_probing",
  "severity": "medium",
  "ip": "...",
  "count": 5
}
```

## Security Story (Demo Narrative)

This attack tooling demonstrates a complete detection pipeline:

1. **Attacker generates suspicious behavior** (failed logins, invalid tokens, or unauthorized endpoint access)
2. **Services emit structured security events** (`auth-service`, `api-service`)
3. **Centralized log-service ingests events** via `/ingest` endpoint
4. **Detection rules analyze patterns** based on IP, event type, time windows, and thresholds
5. **Alerts are generated** with severity, context, and metadata
6. **Alerts are stored** in Postgres and exposed via `/log/alerts`
7. **Analysts view alerts** via the web UI (`/alerts.html`) or API

This demonstrates:

* Centralized security event logging
* Pluggable detection rules
* Real-time alert generation and lifecycle management
* Microservices architecture with shared event schema
* PostgreSQL-backed security analytics
* SOC-like operational workflow
