"""Tests for invalid token burst detection rule."""

from datetime import datetime, timezone, timedelta

from app.models import Event, Alert
from app.detections.token_abuse import evaluate as eval_token_abuse


def utcnow():
    return datetime.now(timezone.utc)


class TestTokenAbuseDetection:
    """Test suite for invalid_token_burst detection rule."""

    def test_no_alert_below_threshold(self, db_session, create_multiple_events):
        """Should not create alert if invalid token count is below threshold."""
        # Threshold is 5 in test settings
        create_multiple_events(4, event="invalid_token", ip="192.168.1.100")

        trigger_event = Event(
            v=1,
            ts=utcnow(),
            service="api",
            event="invalid_token",
            ip="192.168.1.100",
            path="/api/protected",
            user_id=None,
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_token_abuse(db_session, trigger_event)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "invalid_token_burst").all()
        assert len(alerts) == 0

    def test_alert_on_threshold_reached(self, db_session, create_multiple_events):
        """Should create alert when threshold is reached."""
        create_multiple_events(5, event="invalid_token", ip="192.168.1.100")

        trigger_event = Event(
            v=1,
            ts=utcnow(),
            service="api",
            event="invalid_token",
            ip="192.168.1.100",
            path="/api/protected",
            user_id=None,
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_token_abuse(db_session, trigger_event)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "invalid_token_burst").all()
        assert len(alerts) == 1
        assert alerts[0].severity == "medium"
        assert alerts[0].ip == "192.168.1.100"
        assert alerts[0].count == 6

    def test_counts_multiple_token_event_types(self, db_session):
        """Should count all token-related events together."""
        base_time = utcnow()

        # Mix of different token-related events
        for i in range(2):
            for event_type in ["invalid_token", "invalid_token_claims", "missing_token"]:
                event = Event(
                    v=1,
                    ts=base_time - timedelta(seconds=i * 10),
                    service="api",
                    event=event_type,
                    ip="192.168.1.100",
                    path="/api/protected",
                    user_id=None,
                    meta={},
                )
                db_session.add(event)

        db_session.commit()

        trigger_event = Event(
            v=1,
            ts=base_time,
            service="api",
            event="invalid_token_claims",
            ip="192.168.1.100",
            path="/api/protected",
            user_id=None,
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_token_abuse(db_session, trigger_event)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "invalid_token_burst").all()
        assert len(alerts) == 1
        # Should count all 6 events (2 of each type)
        assert alerts[0].count == 6

    def test_no_alert_for_valid_token_requests(self, db_session, create_multiple_events):
        """Should not trigger alert for events without token issues."""
        create_multiple_events(10, event="valid_request", ip="192.168.1.100")

        trigger_event = Event(
            v=1,
            ts=utcnow(),
            service="api",
            event="valid_request",
            ip="192.168.1.100",
            path="/api/protected",
            user_id="user123",
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_token_abuse(db_session, trigger_event)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "invalid_token_burst").all()
        assert len(alerts) == 0

    def test_window_time_boundary(self, db_session):
        """Should only count events within the time window."""
        base_time = utcnow()
        window_seconds = 120

        # Old event (outside window)
        old_event = Event(
            v=1,
            ts=base_time - timedelta(seconds=window_seconds + 10),
            service="api",
            event="invalid_token",
            ip="192.168.1.100",
            path="/api/protected",
            user_id=None,
            meta={},
        )
        db_session.add(old_event)

        # Recent events (inside window)
        for i in range(5):
            event = Event(
                v=1,
                ts=base_time - timedelta(seconds=i * 10),
                service="api",
                event="invalid_token",
                ip="192.168.1.100",
                path="/api/protected",
                user_id=None,
                meta={},
            )
            db_session.add(event)

        db_session.commit()

        trigger_event = Event(
            v=1,
            ts=base_time,
            service="api",
            event="invalid_token",
            ip="192.168.1.100",
            path="/api/protected",
            user_id=None,
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_token_abuse(db_session, trigger_event)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "invalid_token_burst").all()
        assert len(alerts) == 1
        # Should only count 5 events in window, not the old one
        assert alerts[0].count == 5

    def test_different_ips_isolated(self, db_session):
        """Should not alert on events from different IPs."""
        base_time = utcnow()

        # Create events for IP1
        for i in range(5):
            event = Event(
                v=1,
                ts=base_time - timedelta(seconds=i * 10),
                service="api",
                event="invalid_token",
                ip="192.168.1.100",
                path="/api/protected",
                user_id=None,
                meta={},
            )
            db_session.add(event)

        db_session.commit()

        # Trigger from different IP with only 1 invalid token
        trigger_event = Event(
            v=1,
            ts=base_time,
            service="api",
            event="invalid_token",
            ip="192.168.1.101",
            path="/api/protected",
            user_id=None,
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_token_abuse(db_session, trigger_event)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "invalid_token_burst").all()
        assert len(alerts) == 0

    def test_no_duplicate_alerts_in_window(self, db_session):
        """Should not create duplicate alerts for same IP within time window."""
        base_time = utcnow()

        # Create first batch and trigger alert
        for i in range(5):
            event = Event(
                v=1,
                ts=base_time - timedelta(seconds=i * 10),
                service="api",
                event="invalid_token",
                ip="192.168.1.100",
                path="/api/protected",
                user_id=None,
                meta={},
            )
            db_session.add(event)

        db_session.commit()

        trigger_event1 = Event(
            v=1,
            ts=base_time,
            service="api",
            event="invalid_token",
            ip="192.168.1.100",
            path="/api/protected",
            user_id=None,
            meta={},
        )
        db_session.add(trigger_event1)
        db_session.commit()

        eval_token_abuse(db_session, trigger_event1)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "invalid_token_burst").all()
        assert len(alerts) == 1

        # Trigger again within window
        trigger_event2 = Event(
            v=1,
            ts=base_time + timedelta(seconds=30),
            service="api",
            event="invalid_token",
            ip="192.168.1.100",
            path="/api/protected",
            user_id=None,
            meta={},
        )
        db_session.add(trigger_event2)
        db_session.commit()

        eval_token_abuse(db_session, trigger_event2)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "invalid_token_burst").all()
        assert len(alerts) == 1  # Still only 1 alert

    def test_alert_metadata(self, db_session, create_multiple_events):
        """Should include correct metadata in alert."""
        create_multiple_events(5, event="invalid_token", ip="192.168.1.100")

        trigger_event = Event(
            v=1,
            ts=utcnow(),
            service="api",
            event="invalid_token",
            ip="192.168.1.100",
            path="/api/protected",
            user_id=None,
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_token_abuse(db_session, trigger_event)
        db_session.commit()

        alert = db_session.query(Alert).filter(Alert.rule == "invalid_token_burst").first()
        assert alert.window_seconds == 120
        assert alert.threshold == 5
        assert "token" in alert.meta.get("note", "").lower()

    def test_missing_token_event_type(self, db_session):
        """Should detect missing_token event type."""
        base_time = utcnow()

        for i in range(5):
            event = Event(
                v=1,
                ts=base_time - timedelta(seconds=i * 10),
                service="api",
                event="missing_token",
                ip="192.168.1.100",
                path="/api/protected",
                user_id=None,
                meta={},
            )
            db_session.add(event)

        db_session.commit()

        trigger_event = Event(
            v=1,
            ts=base_time,
            service="api",
            event="missing_token",
            ip="192.168.1.100",
            path="/api/protected",
            user_id=None,
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_token_abuse(db_session, trigger_event)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "invalid_token_burst").all()
        assert len(alerts) == 1

    def test_invalid_token_claims_event_type(self, db_session):
        """Should detect invalid_token_claims event type."""
        base_time = utcnow()

        for i in range(5):
            event = Event(
                v=1,
                ts=base_time - timedelta(seconds=i * 10),
                service="api",
                event="invalid_token_claims",
                ip="192.168.1.100",
                path="/api/protected",
                user_id=None,
                meta={},
            )
            db_session.add(event)

        db_session.commit()

        trigger_event = Event(
            v=1,
            ts=base_time,
            service="api",
            event="invalid_token_claims",
            ip="192.168.1.100",
            path="/api/protected",
            user_id=None,
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_token_abuse(db_session, trigger_event)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "invalid_token_burst").all()
        assert len(alerts) == 1
