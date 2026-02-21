from fastapi import FastAPI, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import select

from .db import Base, engine, get_db
from .models import User
from .schemas import SignupRequest, LoginRequest, TokenResponse
from .security import hash_password, verify_password, create_access_token
from .log_client import send_event

app = FastAPI(title="auth-service")

# v1: create tables on startup (simple). Later: Alembic migrations.
Base.metadata.create_all(bind=engine)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/signup", status_code=status.HTTP_201_CREATED)
def signup(request: Request, payload: SignupRequest, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()

    existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if existing:
        send_event(
            event="signup_conflict",
            ip=client_ip(request),
            path=str(request.url.path),
            user_id=None,
            meta={"email": email},
        )
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(
        email=email,
        password_hash=hash_password(payload.password),
        role="user",
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    send_event(
        event="signup_success",
        ip=client_ip(request),
        path=str(request.url.path),
        user_id=str(user.id),
        meta={"email": user.email},
    )

    return {"id": user.id, "email": user.email, "role": user.role}


@app.post("/login", response_model=TokenResponse)
def login(request: Request, payload: LoginRequest, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()

    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()

    # generic error to avoid user enumeration
    if not user or not verify_password(payload.password, user.password_hash):
        send_event(
            event="login_failed",
            ip=client_ip(request),
            path=str(request.url.path),
            user_id=None,
            meta={"email": email},
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(user_id=user.id, role=user.role)

    send_event(
        event="login_success",
        ip=client_ip(request),
        path=str(request.url.path),
        user_id=str(user.id),
        meta={"email": user.email},
    )

    return TokenResponse(access_token=token)


def client_ip(request: Request) -> str:
    # nginx sets X-Real-IP; fallback to client host
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "unknown")
