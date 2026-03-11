# Log Service Tests

This directory contains the test suite for the SentinelMesh log microservice.

## Running Tests

### Prerequisites

Install test dependencies:

```bash
cd services/log
poetry install --with dev
```

### Run All Tests

```bash
poetry run pytest
```

### Run Specific Test File

```bash
poetry run pytest tests/test_brute_force.py
```

### Run Specific Test Class or Method

```bash
poetry run pytest tests/test_brute_force.py::TestBruteForceDetection::test_alert_on_threshold_reached
```

### Run with Coverage

```bash
poetry run pytest --cov=app tests/
```

### Run with Verbose Output

```bash
poetry run pytest -v
```

### Run with Print Statements

```bash
poetry run pytest -s
```

## Test Organization

### `conftest.py`
Pytest configuration and shared fixtures:
- `test_settings` - Settings with reduced thresholds for testing
- `db_engine` - In-memory SQLite database
- `db_session` - Database session for each test
- `sample_event_data` - Base event data
- `create_event` - Factory to create single events
- `create_multiple_events` - Factory to create multiple events

### `test_brute_force.py`
Tests for the brute force login detection rule:
- Threshold behavior
- Time window boundaries
- IP isolation
- Duplicate alert prevention
- Event timestamp tracking

### `test_token_abuse.py`
Tests for the invalid token burst detection rule:
- Multiple token event types (invalid_token, invalid_token_claims, missing_token)
- Threshold and window logic
- Different IP isolation
- Duplicate prevention

### `test_admin_probing.py`
Tests for the admin endpoint probing detection rule:
- Unauthorized admin access tracking
- Multiple endpoint aggregation
- Time window enforcement
- Duplicate alert deduplication

### `test_api.py`
Tests for the FastAPI endpoints:
- `POST /ingest` - Event ingestion
- `GET /alerts` - Alert listing and ordering
- `PATCH /alerts/{alert_id}` - Alert lifecycle management (ack, close, reopen)

### `test_integration.py`
Full pipeline integration tests:
- Multiple detection rules working together
- Pipeline execution flow
- Alert independence by IP
- Concurrent detections

## Detection Rules

The test suite covers three detection rules:

1. **Brute Force Login** (`brute_force_login`)
   - Threshold: 3 failed attempts in 120 seconds
   - Severity: High
   - Event type: `login_failed`

2. **Invalid Token Burst** (`invalid_token_burst`)
   - Threshold: 5 token-related events in 120 seconds
   - Severity: Medium
   - Event types: `invalid_token`, `invalid_token_claims`, `missing_token`

3. **Admin Probing** (`admin_probing`)
   - Threshold: 3 unauthorized admin access attempts in 120 seconds
   - Severity: Medium
   - Event type: `unauthorized_admin_access`

## Test Database

Tests use an in-memory SQLite database for isolation and speed. Each test gets a fresh database session that's rolled back after the test completes.

## Key Test Patterns

### Threshold Testing
```python
def test_alert_on_threshold_reached(self, db_session, create_multiple_events):
    create_multiple_events(3, event="login_failed", ip="192.168.1.100")
    trigger_event = Event(...)
    evaluate(db_session, trigger_event)
    alerts = db_session.query(Alert).all()
    assert len(alerts) == 1
```

### Time Window Testing
Tests verify that events are only counted within the specified time window and older events are excluded.

### IP Isolation Testing
Tests verify that events from different IPs don't trigger alerts together.

### Duplicate Prevention Testing
Tests verify that multiple triggers within the same window don't create duplicate alerts.

## Debugging Tests

Use pytest's `-s` flag to see print statements:
```bash
poetry run pytest -s tests/test_brute_force.py
```

Use `--pdb` to drop into debugger on failure:
```bash
poetry run pytest --pdb tests/test_brute_force.py
```

## Contributing

When adding new detection rules:
1. Create a new test file `test_<rule_name>.py`
2. Include tests for threshold behavior, time windows, IP isolation, and deduplication
3. Add integration test in `test_integration.py`

When modifying API endpoints:
1. Update relevant tests in `test_api.py`
2. Ensure backward compatibility is tested
