"""Tests for admin probing detection rule."""

from datetime import datetime, timezone, timedelta

from app.models import Event, Alert
from app.detections.admin_probing import evaluate as eval_admin_probing


def utcnow():
    return datetime.now(timezone.utc)


class TestAdminProbingDetection:
    """Test suite for admin_probing detection rule."""

    def test_no_alert_below_threshold(self, db_session, create_multiple_events):
        """Should not create alert if unauthorized admin access count is below threshold."""
        # Threshold is 3 in test settings
        create_multiple_events(1, event="unauthorized_admin_access", ip="192.168.1.100")

        trigger_event = Event(
            v=1,
            ts=utcnow(),
            service="api",
            event="unauthorized_admin_access",
            ip="192.168.1.100",
            path="/admin/users",
            user_id="user123",
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_admin_probing(db_session, trigger_event)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "admin_probing").all()
        assert len(alerts) == 0

    def test_alert_on_threshold_reached(self, db_session, create_multiple_events):
        """Should create alert when threshold is reached."""
        create_multiple_events(3, event="unauthorized_admin_access", ip="192.168.1.100")

        trigger_event = Event(
            v=1,
            ts=utcnow(),
            service="api",
            event="unauthorized_admin_access",
            ip="192.168.1.100",
            path="/admin/users",
            user_id="user123",
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_admin_probing(db_session, trigger_event)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "admin_probing").all()
        assert len(alerts) == 1
        assert alerts[0].severity == "medium"
        assert alerts[0].ip == "192.168.1.100"
        assert alerts[0].count == 4

    def test_no_alert_for_authorized_admin_access(self, db_session, create_multiple_events):
        """Should not trigger alert for authorized admin access."""
        create_multiple_events(5, event="authorized_admin_access", ip="192.168.1.100")

        trigger_event = Event(
            v=1,
            ts=utcnow(),
            service="api",
            event="authorized_admin_access",
            ip="192.168.1.100",
            path="/admin/users",
            user_id="admin_user",
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_admin_probing(db_session, trigger_event)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "admin_probing").all()
        assert len(alerts) == 0

    def test_no_alert_for_other_unauthorized_events(self, db_session, create_multiple_events):
        """Should not trigger alert for unauthorized events that are not admin access."""
        create_multiple_events(5, event="unauthorized_access", ip="192.168.1.100")

        trigger_event = Event(
            v=1,
            ts=utcnow(),
            service="api",
            event="unauthorized_access",
            ip="192.168.1.100",
            path="/api/protected",
            user_id="user123",
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_admin_probing(db_session, trigger_event)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "admin_probing").all()
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
            event="unauthorized_admin_access",
            ip="192.168.1.100",
            path="/admin/users",
            user_id="user123",
            meta={},
        )
        db_session.add(old_event)

        # Recent events (inside window)
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

        eval_admin_probing(db_session, trigger_event)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "admin_probing").all()
        assert len(alerts) == 1
        # Should only count 4 events in window (3 pre-trigger + 1 trigger), not the old one
        assert alerts[0].count == 4

    def test_different_ips_isolated(self, db_session):
        """Should not alert on events from different IPs."""
        base_time = utcnow()

        # Create events for IP1
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

        # Trigger from different IP with only 1 attempt
        trigger_event = Event(
            v=1,
            ts=base_time,
            service="api",
            event="unauthorized_admin_access",
            ip="192.168.1.101",
            path="/admin/users",
            user_id="user456",
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_admin_probing(db_session, trigger_event)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "admin_probing").all()
        assert len(alerts) == 0

    def test_no_duplicate_alerts_in_window(self, db_session):
        """Should not create duplicate alerts for same IP within time window."""
        base_time = utcnow()

        # Create first batch and trigger alert
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

        trigger_event1 = Event(
            v=1,
            ts=base_time,
            service="api",
            event="unauthorized_admin_access",
            ip="192.168.1.100",
            path="/admin/users",
            user_id="user123",
            meta={},
        )
        db_session.add(trigger_event1)
        db_session.commit()

        eval_admin_probing(db_session, trigger_event1)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "admin_probing").all()
        assert len(alerts) == 1

        # Trigger again within window
        trigger_event2 = Event(
            v=1,
            ts=base_time + timedelta(seconds=30),
            service="api",
            event="unauthorized_admin_access",
            ip="192.168.1.100",
            path="/admin/users",
            user_id="user123",
            meta={},
        )
        db_session.add(trigger_event2)
        db_session.commit()

        eval_admin_probing(db_session, trigger_event2)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "admin_probing").all()
        assert len(alerts) == 1  # Still only 1 alert

    def test_alert_metadata(self, db_session, create_multiple_events):
        """Should include correct metadata in alert."""
        create_multiple_events(3, event="unauthorized_admin_access", ip="192.168.1.100")

        trigger_event = Event(
            v=1,
            ts=utcnow(),
            service="api",
            event="unauthorized_admin_access",
            ip="192.168.1.100",
            path="/admin/users",
            user_id="user123",
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_admin_probing(db_session, trigger_event)
        db_session.commit()

        alert = db_session.query(Alert).filter(Alert.rule == "admin_probing").first()
        assert alert.window_seconds == 120
        assert alert.threshold == 3
        assert "admin" in alert.meta.get("note", "").lower()

    def test_first_and_last_seen(self, db_session):
        """Should track first and last event timestamps correctly."""
        base_time = utcnow()

        times = []
        for i in range(3):
            ts = base_time - timedelta(seconds=30 - i * 10)
            times.append(ts)
            event = Event(
                v=1,
                ts=ts,
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

        eval_admin_probing(db_session, trigger_event)
        db_session.commit()

        alert = db_session.query(Alert).filter(Alert.rule == "admin_probing").first()
        # Compare without timezone since Alert stores naive datetimes
        # Include trigger event in the range (it's the most recent event)
        all_times = times + [base_time]
        assert alert.first_seen == min(all_times).replace(tzinfo=None)
        assert alert.last_seen == max(all_times).replace(tzinfo=None)

    def test_multiple_admin_endpoints(self, db_session):
        """Should count unauthorized admin access attempts across different admin endpoints."""
        base_time = utcnow()
        admin_paths = ["/admin/users", "/admin/settings", "/admin/logs"]

        for i, path in enumerate(admin_paths):
            event = Event(
                v=1,
                ts=base_time - timedelta(seconds=i * 10),
                service="api",
                event="unauthorized_admin_access",
                ip="192.168.1.100",
                path=path,
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

        eval_admin_probing(db_session, trigger_event)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "admin_probing").all()
        assert len(alerts) == 1
        # Should count all 4 attempts across different endpoints (3 pre-trigger + 1 trigger)
        assert alerts[0].count == 4
