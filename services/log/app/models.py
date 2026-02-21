from sqlalchemy import String, DateTime, func, Integer
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    v: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    ts: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)
    service: Mapped[str] = mapped_column(String(64), nullable=False)
    event: Mapped[str] = mapped_column(String(64), nullable=False)

    ip: Mapped[str] = mapped_column(String(64), nullable=False)
    path: Mapped[str] = mapped_column(String(256), nullable=False)

    user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    meta: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g., brute_force_login
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")

    ip: Mapped[str] = mapped_column(String(64), nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False)

    first_seen: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)

    meta: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
