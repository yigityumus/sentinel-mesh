from sqlalchemy import String, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(500), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="user", nullable=False)

    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
