from datetime import timedelta
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from ..models import Event, Alert
from ..settings import settings


RULE_NAME = "admin_probing"


def evaluate(db: Session, event) -> None:
    # Only care about unauthorized admin access attempts
    if event.event != "unauthorized_admin_access":
        return

    threshold = settings.ADMIN_PROBING_THRESHOLD
    window_seconds = settings.ADMIN_PROBING_WINDOW_SECONDS

    ip = event.ip
    now_ts = event.ts
    window_start = now_ts - timedelta(seconds=window_seconds)

    count_q = select(func.count()).select_from(Event).where(
        Event.event == "unauthorized_admin_access",
        Event.ip == ip,
        Event.ts >= window_start,
        Event.ts <= now_ts,
    )
    count = db.execute(count_q).scalar_one()

    if count < threshold:
        return

    # Avoid duplicate alerts in same window
    recent_alert_q = select(Alert).where(
        Alert.rule == RULE_NAME,
        Alert.ip == ip,
        Alert.created_at >= (now_ts - timedelta(seconds=window_seconds)),
    ).order_by(Alert.id.desc())

    recent = db.execute(recent_alert_q).scalars().first()
    if recent:
        return

    bounds_q = select(func.min(Event.ts), func.max(Event.ts)).where(
        Event.event == "unauthorized_admin_access",
        Event.ip == ip,
        Event.ts >= window_start,
        Event.ts <= now_ts,
    )
    first_seen, last_seen = db.execute(bounds_q).one()

    alert = Alert(
        rule=RULE_NAME,
        severity="medium",
        ip=ip,
        window_seconds=window_seconds,
        threshold=threshold,
        count=count,
        first_seen=first_seen,
        last_seen=last_seen,
        meta={"note": "Repeated attempts to access admin endpoints by non-admin user"},
    )

    db.add(alert)
