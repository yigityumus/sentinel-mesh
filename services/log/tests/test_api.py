"""Tests for log service API endpoints."""

import sys
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from sqlalchemy.orm import Session

# Mock the engine before importing app and FastAPI
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.models import Event, Alert


def utcnow():
    return datetime.now(timezone.utc)


@pytest.fixture
def test_app(db_session):
    """Create FastAPI app with test database."""
    from fastapi.testclient import TestClient
    from app.main import app
    
    def override_get_db():
        yield db_session
    
    # Import after db is mocked
    from app.db import get_db
    app.dependency_overrides[get_db] = override_get_db
    
    yield TestClient(app)
    app.dependency_overrides.clear()


def override_get_db(db: Session):
    """Override get_db dependency for testing."""
    yield db


class TestHealthz:
    """Test health check endpoint."""

    def test_healthz_endpoint(self, test_app):
        """Should return ok status."""
        response = test_app.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestIngestEndpoint:
    """Test event ingestion endpoint."""

    def test_ingest_valid_event(self, test_app, db_session):
        """Should ingest a valid event."""
        payload = {
            "v": 1,
            "ts": utcnow().isoformat(),
            "service": "auth",
            "event": "login_success",
            "ip": "192.168.1.100",
            "path": "/login",
            "user_id": "user123",
            "meta": {"duration_ms": 123},
        }

        response = test_app.post("/ingest", json=payload)
        assert response.status_code == 200
        assert response.json() == {"stored": True}

        # Verify event was stored
        events = db_session.query(Event).all()
        assert len(events) == 1
        assert events[0].service == "auth"
        assert events[0].event == "login_success"

    def test_ingest_event_with_optional_fields(self, test_app, db_session):
        """Should ingest event without optional user_id and meta."""
        payload = {
            "v": 1,
            "ts": utcnow().isoformat(),
            "service": "api",
            "event": "unauthorized_access",
            "ip": "192.168.1.100",
            "path": "/api/protected",
        }

        response = test_app.post("/ingest", json=payload)
        assert response.status_code == 200

        events = db_session.query(Event).all()
        assert len(events) == 1
        assert events[0].user_id is None
        assert events[0].meta == {}

    def test_ingest_missing_required_field(self, test_app):
        """Should reject event with missing required field."""
        payload = {
            "v": 1,
            "ts": utcnow().isoformat(),
            "service": "auth",
            # Missing 'event' field
            "ip": "192.168.1.100",
            "path": "/login",
        }

        response = test_app.post("/ingest", json=payload)
        assert response.status_code == 422

    def test_ingest_invalid_field_type(self, test_app):
        """Should reject event with invalid field types."""
        payload = {
            "v": 1,
            "ts": "not-a-datetime",  # Invalid
            "service": "auth",
            "event": "login_success",
            "ip": "192.168.1.100",
            "path": "/login",
        }

        response = test_app.post("/ingest", json=payload)
        assert response.status_code == 422

    def test_ingest_triggers_detection_pipeline(self, test_app, db_session):
        """Should trigger detection pipeline after ingesting event."""
        base_time = utcnow()

        # Create multiple failed login events
        for i in range(3):
            payload = {
                "v": 1,
                "ts": (base_time - timedelta(seconds=i * 10)).isoformat(),
                "service": "auth",
                "event": "login_failed",
                "ip": "192.168.1.100",
                "path": "/login",
            }
            test_app.post("/ingest", json=payload)

        # Trigger event that should create alert
        payload = {
            "v": 1,
            "ts": base_time.isoformat(),
            "service": "auth",
            "event": "login_failed",
            "ip": "192.168.1.100",
            "path": "/login",
        }

        response = test_app.post("/ingest", json=payload)
        assert response.status_code == 200

        # Verify alert was created
        alerts = db_session.query(Alert).filter(Alert.rule == "brute_force_login").all()
        assert len(alerts) == 1

    def test_ingest_persists_meta(self, test_app, db_session):
        """Should persist metadata in event."""
        payload = {
            "v": 1,
            "ts": utcnow().isoformat(),
            "service": "api",
            "event": "request_processed",
            "ip": "192.168.1.100",
            "path": "/api/endpoint",
            "meta": {
                "status_code": 200,
                "response_time_ms": 45,
                "user_agent": "Mozilla/5.0",
            },
        }

        response = test_app.post("/ingest", json=payload)
        assert response.status_code == 200

        events = db_session.query(Event).all()
        assert events[0].meta["status_code"] == 200
        assert events[0].meta["response_time_ms"] == 45


class TestAlertsListEndpoint:
    """Test alerts listing endpoint."""

    def test_list_alerts_empty(self, test_app):
        """Should return empty list when no alerts."""
        response = test_app.get("/alerts")
        assert response.status_code == 200
        assert response.json() == []

    def test_list_alerts_returns_alerts(self, test_app, db_session):
        """Should return list of alerts."""
        base_time = utcnow()

        # Create an alert
        alert = Alert(
            rule="brute_force_login",
            severity="high",
            ip="192.168.1.100",
            window_seconds=120,
            threshold=5,
            count=10,
            first_seen=base_time,
            last_seen=base_time,
            meta={"note": "Test alert"},
        )
        db_session.add(alert)
        db_session.commit()

        response = test_app.get("/alerts")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["rule"] == "brute_force_login"
        assert data[0]["severity"] == "high"
        assert data[0]["ip"] == "192.168.1.100"

    def test_list_alerts_order(self, test_app, db_session):
        """Should return alerts ordered by ID descending."""
        base_time = utcnow()

        # Create multiple alerts
        for i in range(3):
            alert = Alert(
                rule="brute_force_login",
                severity="high",
                ip=f"192.168.1.{100 + i}",
                window_seconds=120,
                threshold=5,
                count=10,
                first_seen=base_time,
                last_seen=base_time,
                meta={},
            )
            db_session.add(alert)
        db_session.commit()

        response = test_app.get("/alerts")
        data = response.json()

        # Should be in reverse ID order (newest first)
        assert len(data) == 3
        for i in range(len(data) - 1):
            assert data[i]["id"] >= data[i + 1]["id"]

    def test_list_alerts_limit(self, test_app, db_session):
        """Should limit alerts to 50 results."""
        base_time = utcnow()

        # Create many alerts
        for i in range(60):
            alert = Alert(
                rule="brute_force_login",
                severity="high",
                ip=f"192.168.1.{100 + (i % 256)}",
                window_seconds=120,
                threshold=5,
                count=10,
                first_seen=base_time,
                last_seen=base_time,
                meta={},
            )
            db_session.add(alert)
        db_session.commit()

        response = test_app.get("/alerts")
        data = response.json()
        assert len(data) == 50


class TestAlertUpdateEndpoint:
    """Test alert update endpoint."""

    def test_acknowledge_alert(self, test_app, db_session):
        """Should acknowledge an alert."""
        base_time = utcnow()

        alert = Alert(
            rule="brute_force_login",
            severity="high",
            ip="192.168.1.100",
            window_seconds=120,
            threshold=5,
            count=10,
            first_seen=base_time,
            last_seen=base_time,
            meta={},
        )
        db_session.add(alert)
        db_session.commit()

        payload = {
            "action": "ack",
            "actor": "security-team",
        }

        response = test_app.patch(f"/alerts/{alert.id}", json=payload)
        assert response.status_code == 200

        updated = response.json()
        assert updated["status"] == "acknowledged"
        assert updated["acknowledged_by"] == "security-team"
        assert updated["acknowledged_at"] is not None

    def test_close_alert(self, test_app, db_session):
        """Should close an alert."""
        base_time = utcnow()

        alert = Alert(
            rule="brute_force_login",
            severity="high",
            ip="192.168.1.100",
            window_seconds=120,
            threshold=5,
            count=10,
            first_seen=base_time,
            last_seen=base_time,
            meta={},
        )
        db_session.add(alert)
        db_session.commit()

        payload = {
            "action": "close",
            "actor": "security-team",
        }

        response = test_app.patch(f"/alerts/{alert.id}", json=payload)
        assert response.status_code == 200

        updated = response.json()
        assert updated["status"] == "closed"
        assert updated["closed_by"] == "security-team"
        assert updated["closed_at"] is not None

    def test_reopen_alert(self, test_app, db_session):
        """Should reopen an alert."""
        base_time = utcnow()

        alert = Alert(
            rule="brute_force_login",
            severity="high",
            ip="192.168.1.100",
            window_seconds=120,
            threshold=5,
            count=10,
            first_seen=base_time,
            last_seen=base_time,
            status="closed",
            closed_at=base_time,
            closed_by="someone",
            meta={},
        )
        db_session.add(alert)
        db_session.commit()

        payload = {
            "action": "reopen",
            "actor": "analyst",
        }

        response = test_app.patch(f"/alerts/{alert.id}", json=payload)
        assert response.status_code == 200

        updated = response.json()
        assert updated["status"] == "open"
        assert updated["closed_at"] is None
        assert updated["closed_by"] is None
        assert updated["acknowledged_at"] is None

    def test_update_nonexistent_alert(self, test_app):
        """Should return 404 for nonexistent alert."""
        payload = {
            "action": "ack",
            "actor": "security-team",
        }

        response = test_app.patch("/alerts/99999", json=payload)
        assert response.status_code == 404

    def test_update_alert_with_default_actor(self, test_app, db_session):
        """Should use default actor 'web-ui' if not provided."""
        base_time = utcnow()

        alert = Alert(
            rule="brute_force_login",
            severity="high",
            ip="192.168.1.100",
            window_seconds=120,
            threshold=5,
            count=10,
            first_seen=base_time,
            last_seen=base_time,
            meta={},
        )
        db_session.add(alert)
        db_session.commit()

        payload = {
            "action": "ack",
            # actor will use default "web-ui"
        }

        response = test_app.patch(f"/alerts/{alert.id}", json=payload)
        assert response.status_code == 200

        updated = response.json()
        assert updated["acknowledged_by"] == "web-ui"
