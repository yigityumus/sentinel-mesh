from fastapi import FastAPI, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import select
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from .db import Base, engine, get_db
from .models import User
from .schemas import SignupRequest, LoginRequest, TokenResponse
from .security import hash_password, verify_password, create_access_token
from .log_client import send_event
from .settings import settings

app = FastAPI(title="auth-service")

# v1: create tables on startup (simple). Later: Alembic migrations.
Base.metadata.create_all(bind=engine)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/.well-known/jwks.json")
def get_jwks():
    """Expose public key in JWKS format for JWT verification."""
    public_key_pem = settings.public_key_pem
    
    # Load the public key
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode("utf-8"),
        backend=default_backend(),
    )
    
    # Extract RSA numbers
    public_numbers = public_key.public_numbers()
    
    # Convert to base64url without padding (JWKS format)
    def int_to_base64url(n: int, length: int) -> str:
        """Convert integer to base64url string of specified byte length."""
        b = n.to_bytes(length, byteorder='big')
        return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')
    
    # Calculate byte lengths for RSA key components
    key_bit_length = public_key.key_size
    key_byte_length = (key_bit_length + 7) // 8
    
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "sentinel-auth-key-1",
                "n": int_to_base64url(public_numbers.n, key_byte_length),
                "e": int_to_base64url(public_numbers.e, 3),
                "alg": "RS256",
            }
        ]
    }
    return jwks


@app.post("/signup", status_code=status.HTTP_201_CREATED)
def signup(request: Request, payload: SignupRequest, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()

    existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if existing:
        send_event(
            event="signup_conflict",
            ip=client_ip(request),
            path=original_path(request),
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
        path=original_path(request),
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
            path=original_path(request),
            user_id=None,
            meta={"email": email},
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(user_id=user.id, role=user.role)

    send_event(
        event="login_success",
        ip=client_ip(request),
        path=original_path(request),
        user_id=str(user.id),
        meta={"email": user.email},
    )

    return TokenResponse(access_token=token)


def client_ip(request: Request) -> str:
    # nginx sets X-Real-IP; fallback to client host
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "unknown")


def original_path(request: Request) -> str:
    # nginx sets X-Original-URI with full path; fallback to url.path
    return request.headers.get("x-original-uri") or str(request.url.path)
