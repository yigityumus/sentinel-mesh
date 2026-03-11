"""Integration tests for detection pipeline."""

from datetime import datetime, timezone, timedelta

from app.models import Event, Alert
from app.detections.engine import run_detection_pipeline


def utcnow():
    return datetime.now(timezone.utc)


class TestDetectionPipeline:
    """Integration tests for the full detection pipeline."""

    def test_pipeline_runs_all_rules(self, db_session):
        """Should run all detection rules when processing an event."""
        base_time = utcnow()

        # Create events for brute force detection
        for i in range(3):
            event = Event(
                v=1,
                ts=base_time - timedelta(seconds=i * 10),
                service="auth",
                event="login_failed",
                ip="192.168.1.100",
                path="/login",
                user_id=None,
                meta={},
            )
            db_session.add(event)

        db_session.commit()

        trigger_event = Event(
            v=1,
            ts=base_time,
            service="auth",
            event="login_failed",
            ip="192.168.1.100",
            path="/login",
            user_id=None,
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        # Run the full pipeline
        run_detection_pipeline(db_session, trigger_event)

        # Should have created a brute force alert
        alerts = db_session.query(Alert).filter(Alert.rule == "brute_force_login").all()
        assert len(alerts) == 1

    def test_pipeline_creates_multiple_alert_types(self, db_session):
        """Should potentially create different alert types from same event flow."""
        base_time = utcnow()

        # Create brute force events
        for i in range(3):
            event = Event(
                v=1,
                ts=base_time - timedelta(seconds=i * 10),
                service="auth",
                event="login_failed",
                ip="192.168.1.100",
                path="/login",
                user_id=None,
                meta={},
            )
            db_session.add(event)

        db_session.commit()

        trigger_event = Event(
            v=1,
            ts=base_time,
            service="auth",
            event="login_failed",
            ip="192.168.1.100",
            path="/login",
            user_id=None,
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        run_detection_pipeline(db_session, trigger_event)

        # Check for alerts
        all_alerts = db_session.query(Alert).all()
        brute_force_alerts = [a for a in all_alerts if a.rule == "brute_force_login"]
        assert len(brute_force_alerts) == 1

    def test_pipeline_ignores_irrelevant_events(self, db_session):
        """Should not create alerts for events that don't match any rule."""
        base_time = utcnow()

        trigger_event = Event(
            v=1,
            ts=base_time,
            service="api",
            event="request_processed",
            ip="192.168.1.100",
            path="/api/endpoint",
            user_id="user123",
            meta={"status": 200},
        )
        db_session.add(trigger_event)
        db_session.commit()

        run_detection_pipeline(db_session, trigger_event)

        alerts = db_session.query(Alert).all()
        assert len(alerts) == 0

    def test_pipeline_with_multiple_events_different_ips(self, db_session):
        """Should isolate detections by IP."""
        base_time = utcnow()

        # Create login failures for IP1
        for i in range(3):
            event = Event(
                v=1,
                ts=base_time - timedelta(seconds=i * 10),
                service="auth",
                event="login_failed",
                ip="192.168.1.100",
                path="/login",
                user_id=None,
                meta={},
            )
            db_session.add(event)

        # Create login failures for IP2 (below threshold)
        for i in range(2):
            event = Event(
                v=1,
                ts=base_time - timedelta(seconds=i * 10),
                service="auth",
                event="login_failed",
                ip="192.168.1.101",
                path="/login",
                user_id=None,
                meta={},
            )
            db_session.add(event)

        db_session.commit()

        # Trigger from IP1
        trigger_event1 = Event(
            v=1,
            ts=base_time,
            service="auth",
            event="login_failed",
            ip="192.168.1.100",
            path="/login",
            user_id=None,
            meta={},
        )
        db_session.add(trigger_event1)
        db_session.commit()

        run_detection_pipeline(db_session, trigger_event1)

        # Should have alert for IP1 only
        alerts = db_session.query(Alert).all()
        assert len(alerts) == 1
        assert alerts[0].ip == "192.168.1.100"

    def test_pipeline_token_abuse_detection(self, db_session):
        """Should detect token burst patterns."""
        base_time = utcnow()

        # Create token events
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

        run_detection_pipeline(db_session, trigger_event)

        alerts = db_session.query(Alert).filter(Alert.rule == "invalid_token_burst").all()
        assert len(alerts) == 1

    def test_pipeline_admin_probing_detection(self, db_session):
        """Should detect admin endpoint probing."""
        base_time = utcnow()

        # Create unauthorized admin access attempts
        for i in range(3):
            event = Event(
                v=1,
                ts=base_time - timedelta(seconds=i * 10),
                service="api",
                event="unauthorized_admin_access",
                ip="192.168.1.100",
                path="/admin/users",
                user_id="user123",
                meta={},
            )
            db_session.add(event)

        db_session.commit()

        trigger_event = Event(
            v=1,
            ts=base_time,
            service="api",
            event="unauthorized_admin_access",
            ip="192.168.1.100",
            path="/admin/users",
            user_id="user123",
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        run_detection_pipeline(db_session, trigger_event)

        alerts = db_session.query(Alert).filter(Alert.rule == "admin_probing").all()
        assert len(alerts) == 1

    def test_pipeline_concurrent_detections(self, db_session):
        """Should handle triggers for multiple rules."""
        base_time = utcnow()

        # Create both brute force and token abuse events
        # Brute force
        for i in range(3):
            event = Event(
                v=1,
                ts=base_time - timedelta(seconds=i * 10),
                service="auth",
                event="login_failed",
                ip="192.168.1.100",
                path="/login",
                user_id=None,
                meta={},
            )
            db_session.add(event)

        # Token abuse
        for i in range(5):
            event = Event(
                v=1,
                ts=base_time - timedelta(seconds=i * 20),
                service="api",
                event="invalid_token",
                ip="192.168.1.100",
                path="/api/protected",
                user_id=None,
                meta={},
            )
            db_session.add(event)

        db_session.commit()

        # Trigger both
        trigger_token = Event(
            v=1,
            ts=base_time,
            service="api",
            event="invalid_token",
            ip="192.168.1.100",
            path="/api/protected",
            user_id=None,
            meta={},
        )
        db_session.add(trigger_token)
        db_session.commit()

        run_detection_pipeline(db_session, trigger_token)

        alerts = db_session.query(Alert).all()
        # Should have token burst alert (brute force won't trigger from token event)
        token_alerts = [a for a in alerts if a.rule == "invalid_token_burst"]
        assert len(token_alerts) == 1
