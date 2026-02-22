from pydantic import BaseModel, Field
from datetime import datetime
from typing import Literal


class IngestEvent(BaseModel):
    v: int = 1
    ts: datetime
    service: str = Field(min_length=1, max_length=64)
    event: str = Field(min_length=1, max_length=64)
    ip: str = Field(min_length=1, max_length=64)
    path: str = Field(min_length=1, max_length=256)
    user_id: str | None = None
    meta: dict = Field(default_factory=dict)


class IngestResponse(BaseModel):
    stored: bool = True


class AlertOut(BaseModel):
    id: int
    rule: str
    severity: str
    ip: str
    window_seconds: int
    threshold: int
    count: int
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    status: str
    acknowledged_at: datetime | None
    acknowledged_by: str | None
    closed_at: datetime | None
    closed_by: str | None

    meta: dict

    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    action: Literal["ack", "close", "reopen"]
    actor: str = "web-ui"
