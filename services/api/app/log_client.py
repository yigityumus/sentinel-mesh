from datetime import datetime, timezone
import httpx
from .settings import settings


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def send_event(*, event: str, ip: str, path: str, user_id: str | None, meta: dict | None = None) -> None:
    payload = {
        "v": 1,
        "ts": _now_iso(),
        "service": "api",
        "event": event,
        "ip": ip or "unknown",
        "path": path or "unknown",
        "user_id": user_id,
        "meta": meta or {},
    }
    try:
        with httpx.Client(timeout=1.0) as client:
            client.post(f"{settings.LOG_SERVICE_URL}/ingest", json=payload)
    except Exception as e:
        print("send_event failed:", repr(e)) # Don't forget to delete print statements in production code!
