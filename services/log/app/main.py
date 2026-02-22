from fastapi import FastAPI, Depends
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta

from .db import Base, engine, get_db
from .models import Event, Alert
from .schemas import IngestEvent, IngestResponse, AlertOut, AlertUpdate
from .detections.engine import run_detection_pipeline

app = FastAPI(title="log-service")

Base.metadata.create_all(bind=engine)


# TODO : There's another now() function in app/app/log_client.py. 
# Even though it's another microservice, think about if the similar functions should have same names and code.
def utcnow():
    return datetime.now(timezone.utc)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


def detect_bruteforce_login_failed(db: Session, *, ip: str, now_ts):
    RULE = "brute_force_login"
    WINDOW_SECONDS = 120
    THRESHOLD = 5

    window_start = now_ts - timedelta(seconds=WINDOW_SECONDS)

    # Count failed logins from same IP in time window
    count_q = select(func.count()).select_from(Event).where(
        Event.event == "login_failed",
        Event.ip == ip,
        Event.ts >= window_start,
        Event.ts <= now_ts,
    )
    count = db.execute(count_q).scalar_one()

    if count < THRESHOLD:
        return

    # Avoid spamming alerts: if we already created one for this IP in the last window, skip
    recent_alert_q = select(Alert).where(
        Alert.rule == RULE,
        Alert.ip == ip,
        Alert.created_at >= (now_ts - timedelta(seconds=WINDOW_SECONDS)),
    ).order_by(Alert.id.desc())
    recent = db.execute(recent_alert_q).scalars().first()
    if recent:
        return

    # Determine first/last seen in the window
    bounds_q = select(func.min(Event.ts), func.max(Event.ts)).where(
        Event.event == "login_failed",
        Event.ip == ip,
        Event.ts >= window_start,
        Event.ts <= now_ts,
    )
    first_seen, last_seen = db.execute(bounds_q).one()

    alert = Alert(
        rule=RULE,
        severity="high",
        ip=ip,
        window_seconds=WINDOW_SECONDS,
        threshold=THRESHOLD,
        count=count,
        first_seen=first_seen,
        last_seen=last_seen,
        meta={"note": "Too many failed logins from same IP"},
    )
    db.add(alert)


@app.post("/ingest", response_model=IngestResponse)
def ingest(payload: IngestEvent, db: Session = Depends(get_db)):
    ev = Event(
        v=payload.v,
        ts=payload.ts,
        service=payload.service,
        event=payload.event,
        ip=payload.ip,
        path=payload.path,
        user_id=payload.user_id,
        meta=payload.meta,
    )
    db.add(ev)
    db.commit()

    # Run detection pipeline
    run_detection_pipeline(db, ev)
    db.commit()

    return IngestResponse(stored=True)


@app.get("/alerts", response_model=list[AlertOut])
def list_alerts(db: Session = Depends(get_db)):
    q = select(Alert).order_by(Alert.id.desc()).limit(50)
    return list(db.execute(q).scalars().all())


@app.patch("/alerts/{alert_id}", response_model=AlertOut)
def update_alert(alert_id: int, payload: AlertUpdate, db: Session = Depends(get_db)):
    alert = db.execute(select(Alert).where(Alert.id == alert_id)).scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    now = utcnow()

    if payload.action == "ack":
        alert.status = "acknowledged"
        alert.acknowledged_at = now
        alert.acknowledged_by = payload.actor

    elif payload.action == "close":
        alert.status = "closed"
        alert.closed_at = now
        alert.closed_by = payload.actor

    elif payload.action == "reopen":
        alert.status = "open"
        alert.acknowledged_at = None
        alert.acknowledged_by = None
        alert.closed_at = None
        alert.closed_by = None

    alert.updated_at = now
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert
