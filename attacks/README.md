# SentinelMesh – Attack Simulation Scripts

This directory contains scripts to simulate security attacks against SentinelMesh in order to demonstrate detection capabilities.

NOTE: These scripts are intended for local development and demonstration only.

## 1. Brute-Force Login Simulation

File: `bruteforce_login.py`

This script sends multiple failed login attempts to trigger the `brute_force_login` detection rule.

### Detection Rule

If the same IP generates:

- ≥ 5 `login_failed` events  
- within 120 seconds  

Then SentinelMesh creates a `high` severity alert.

## Usage

Make sure:

- SentinelMesh is running (`docker compose up`)
- A user exists in the system (signup once via the web UI)

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

---

## Expected Result

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

You can also open:

```
http://localhost:8080/alerts.html
```

To view alerts in the browser.

---

## Security Story (Demo Narrative)

1. Attacker sends repeated failed login attempts
2. `auth-service` logs events to `log-service`
3. `log-service` detects brute-force behavior
4. Alert is generated and stored in Postgres
5. Alerts are visible via API and UI

This demonstrates:

* Centralized logging
* Detection rules
* Real-time alert generation
* Microservice architecture
* PostgreSQL-backed security analytics
