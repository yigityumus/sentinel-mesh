"""Tests for brute force login detection rule."""

import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import select

from app.models import Event, Alert
from app.detections.brute_force import evaluate as eval_brute_force


def utcnow():
    return datetime.now(timezone.utc)


class TestBruteForceDetection:
    """Test suite for brute_force_login detection rule."""

    def test_no_alert_below_threshold(self, db_session, create_multiple_events):
        """Should not create alert if failed login count is below threshold."""
        # Threshold is 3 in test settings
        create_multiple_events(2, event="login_failed", ip="192.168.1.100")

        # Create trigger event
        trigger_event = Event(
            v=1,
            ts=utcnow(),
            service="auth",
            event="login_failed",
            ip="192.168.1.100",
            path="/login",
            user_id=None,
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_brute_force(db_session, trigger_event)

        alerts = db_session.query(Alert).filter(Alert.rule == "brute_force_login").all()
        assert len(alerts) == 0

    def test_alert_on_threshold_reached(self, db_session, create_multiple_events):
        """Should create alert when threshold is reached."""
        # Create 3 failed login events (threshold in test settings)
        create_multiple_events(3, event="login_failed", ip="192.168.1.100")

        # Create trigger event
        trigger_event = Event(
            v=1,
            ts=utcnow(),
            service="auth",
            event="login_failed",
            ip="192.168.1.100",
            path="/login",
            user_id=None,
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_brute_force(db_session, trigger_event)
        db_session.commit()  # Commit the alert

        alerts = db_session.query(Alert).filter(Alert.rule == "brute_force_login").all()
        assert len(alerts) == 1
        assert alerts[0].severity == "high"
        assert alerts[0].ip == "192.168.1.100"
        assert alerts[0].count == 3

    def test_no_alert_for_successful_login(self, db_session, create_multiple_events):
        """Should not trigger alert for successful logins."""
        create_multiple_events(5, event="login_success", ip="192.168.1.100")

        trigger_event = Event(
            v=1,
            ts=utcnow(),
            service="auth",
            event="login_success",
            ip="192.168.1.100",
            path="/login",
            user_id="user123",
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_brute_force(db_session, trigger_event)

        alerts = db_session.query(Alert).filter(Alert.rule == "brute_force_login").all()
        assert len(alerts) == 0

    def test_window_time_boundary(self, db_session, db_engine):
        """Should only count events within the time window."""
        base_time = utcnow()
        window_seconds = 120

        # Create old event (outside window)
        old_event = Event(
            v=1,
            ts=base_time - timedelta(seconds=window_seconds + 10),
            service="auth",
            event="login_failed",
            ip="192.168.1.100",
            path="/login",
            user_id=None,
            meta={},
        )
        db_session.add(old_event)

        # Create recent events (inside window)
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

        # Trigger event at current time
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

        eval_brute_force(db_session, trigger_event)
        db_session.commit()

        alerts = db_session.query(Alert).filter(Alert.rule == "brute_force_login").all()
        # Should only count 3 events in window, not the old one
        assert len(alerts) == 1
        assert alerts[0].count == 3

    def test_different_ips_isolated(self, db_session):
        """Should not alert on events from different IPs."""
        base_time = utcnow()

        # Create events for IP1
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

        # Trigger from different IP with only 1 failed attempt
        trigger_event = Event(
            v=1,
            ts=base_time,
            service="auth",
            event="login_failed",
            ip="192.168.1.101",
            path="/login",
            user_id=None,
            meta={},
        )
        db_session.add(trigger_event)
        db_session.commit()

        eval_brute_force(db_session, trigger_event)

        alerts = db_session.query(Alert).filter(Alert.rule == "brute_force_login").all()
        assert len(alerts) == 0

    def test_no_duplicate_alerts_in_window(self, db_session):
        """Should not create duplicate alerts for same IP within time window."""
        base_time = utcnow()

        # Create first batch of events and trigger alert
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

        eval_brute_force(db_session, trigger_event1)        db_session.commit()
        # Verify first alert was created
        alerts = db_session.query(Alert).filter(Alert.rule == "brute_force_login").all()
        assert len(alerts) == 1

        # Create more events and trigger again within window
        trigger_event2 = Event(
            v=1,
            ts=base_time + timedelta(seconds=30),
            service="auth",
            event="login_failed",
            ip="192.168.1.100",
            path="/login",
            user_id=None,
            meta={},
        )
        db_session.add(trigger_event2)
        db_session.commit()

        eval_brute_force(db_session, trigger_event2)
        db_session.commit()

        # Should still have only 1 alert (no duplicate)
        alerts = db_session.query(Alert).filter(Alert.rule == "brute_force_login").all()
        assert len(alerts) == 1

    def test_alert_metadata(self, db_session, create_multiple_events):
        """Should include correct metadata in alert."""
        base_time = utcnow()
        create_multiple_events(3, event="login_failed", ip="192.168.1.100")

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

        eval_brute_force(db_session, trigger_event)

        alert = db_session.query(Alert).filter(Alert.rule == "brute_force_login").first()
        assert alert.window_seconds == 120
        assert alert.threshold == 3
        assert "login" in alert.meta.get("note", "").lower()

    def test_first_and_last_seen(self, db_session):
        """Should track first and last event timestamps correctly."""
        base_time = utcnow()

        # Create events with 10-second spacing
        times = []
        for i in range(3):
            ts = base_time - timedelta(seconds=30 - i * 10)
            times.append(ts)
            event = Event(
                v=1,
                ts=ts,
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

        eval_brute_force(db_session, trigger_event)
        db_session.commit()

        alert = db_session.query(Alert).filter(Alert.rule == "brute_force_login").first()
        assert alert.first_seen == min(times)
        assert alert.last_seen == max(times)
