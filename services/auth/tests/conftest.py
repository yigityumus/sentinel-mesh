"""Pytest configuration and shared fixtures for auth service tests."""

from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

# Delay imports of app modules to avoid initializing db engine
# They are imported inside fixtures as needed


# ==============================================================================
# Database and Session Fixtures
# ==============================================================================


@pytest.fixture
def db_engine():
    """Create an in-memory SQLite engine for testing with StaticPool."""
    from app.db import Base
    from sqlalchemy.pool import StaticPool
    
    # StaticPool ensures all connections use the same in-memory database
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        echo=False,
        poolclass=StaticPool,
    )

    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session(db_engine) -> Session:
    """Provide a fresh database session for each test."""
    SessionLocal = sessionmaker(bind=db_engine, autoflush=False, autocommit=False)
    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


# ==============================================================================
# Settings Fixtures
# ==============================================================================


@pytest.fixture
def test_settings():
    """Create test settings with generated RSA keys."""
    from app.keys import generate_rsa_keypair
    from app.settings import Settings

    private_key_pem, public_key_pem = generate_rsa_keypair()

    settings = Settings(
        JWT_ALG="RS256",
        ACCESS_TOKEN_TTL_MIN=15,
        DATABASE_URL="sqlite:///:memory:",
        LOG_SERVICE_URL="http://localhost:8003",
        _private_key_pem=private_key_pem,
        _public_key_pem=public_key_pem,
    )
    return settings


# ==============================================================================
# Sample Data Fixtures
# ==============================================================================


@pytest.fixture
def sample_user_data():
    """Sample user data for tests."""
    return {
        "email": "test@example.com",
        "password": "secure_password_123",
    }


@pytest.fixture
def sample_signup_request(sample_user_data):
    """Create a SignupRequest from sample data."""
    from app.schemas import SignupRequest
    return SignupRequest(
        email=sample_user_data["email"],
        password=sample_user_data["password"],
    )


@pytest.fixture
def sample_login_request(sample_user_data):
    """Create a LoginRequest from sample data."""
    from app.schemas import LoginRequest
    return LoginRequest(
        email=sample_user_data["email"],
        password=sample_user_data["password"],
    )


# ==============================================================================
# User Factory Fixtures
# ==============================================================================


@pytest.fixture
def create_user(db_session):
    """Factory fixture for creating users in the database."""
    from app.models import User
    from app.security import hash_password

    def _create_user(
        email: str = "user@example.com",
        password: str = "secure_password_123",
        role: str = "user",
    ) -> User:
        user = User(
            email=email.lower().strip(),
            password_hash=hash_password(password),
            role=role,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        return user

    return _create_user


@pytest.fixture
def create_multiple_users(db_session):
    """Factory fixture for creating multiple users."""
    from app.models import User
    from app.security import hash_password

    def _create_multiple_users(count: int, **kwargs) -> list[User]:
        users = []
        for i in range(count):
            email = kwargs.get("email") or f"user{i}@example.com"
            password = kwargs.get("password") or "secure_password_123"
            role = kwargs.get("role") or "user"

            user = User(
                email=email,
                password_hash=hash_password(password),
                role=role,
            )
            db_session.add(user)
            users.append(user)

        db_session.commit()
        for user in users:
            db_session.refresh(user)

        return users

    return _create_multiple_users


# ==============================================================================
# Mock Fixtures
# ==============================================================================


@pytest.fixture
def mock_send_event():
    """Mock the send_event function to avoid calling the log service."""
    with patch("app.log_client.send_event") as mock:
        yield mock


@pytest.fixture
def mock_log_client():
    """Mock the entire log client module."""
    with patch("app.log_client.send_event") as mock:
        yield mock


# ==============================================================================
# FastAPI Test Client Fixtures
# ==============================================================================


@pytest.fixture
def app_with_mocks(test_settings, db_session, mock_send_event):
    """Create a FastAPI app with mocked dependencies."""
    from fastapi.testclient import TestClient
    from app.main import app
    from app.db import get_db

    # Override settings
    with patch("app.main.settings", test_settings):
        with patch("app.security.settings", test_settings):
            # Override get_db dependency
            def override_get_db():
                yield db_session

            app.dependency_overrides[get_db] = override_get_db

            client = TestClient(app)
            yield client

            # Clean up
            app.dependency_overrides.clear()


@pytest.fixture
def fastapi_client(db_engine, db_session, mock_send_event):
    """Create a FastAPI TestClient with test endpoints and test database."""
    from fastapi import FastAPI, Depends, HTTPException, status, Request
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import Session
    from sqlalchemy import select
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    from app.models import User
    from app.schemas import SignupRequest, LoginRequest, TokenResponse
    from app.security import hash_password, verify_password, create_access_token
    from app.log_client import send_event
    from app.settings import settings

    # Create fresh app instance for testing
    app = FastAPI(title="auth-service-test")

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/.well-known/jwks.json")
    def get_jwks():
        """Expose public key in JWKS format for JWT verification."""
        public_key_pem = settings.public_key_pem
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8"),
            backend=default_backend(),
        )
        public_numbers = public_key.public_numbers()

        def int_to_base64url(n: int, length: int) -> str:
            b = n.to_bytes(length, byteorder='big')
            return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')

        key_bit_length = public_key.key_size
        key_byte_length = (key_bit_length + 7) // 8

        return {
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

    def _get_db():
        yield db_session

    @app.post("/signup", status_code=status.HTTP_201_CREATED)
    def signup(request: Request, payload: SignupRequest, db: Session = Depends(_get_db)):
        email = payload.email.lower().strip()
        existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if existing:
            send_event(
                event="signup_conflict",
                ip="127.0.0.1",
                path="/signup",
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
            ip="127.0.0.1",
            path="/signup",
            user_id=str(user.id),
            meta={"email": user.email},
        )

        return {"id": user.id, "email": user.email, "role": user.role}

    @app.post("/login", response_model=TokenResponse)
    def login(request: Request, payload: LoginRequest, db: Session = Depends(_get_db)):
        email = payload.email.lower().strip()
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()

        if not user or not verify_password(payload.password, user.password_hash):
            send_event(
                event="login_failed",
                ip="127.0.0.1",
                path="/login",
                user_id=None,
                meta={"email": email},
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")

        token = create_access_token(user_id=user.id, role=user.role)

        send_event(
            event="login_success",
            ip="127.0.0.1",
            path="/login",
            user_id=str(user.id),
            meta={"email": user.email},
        )

        return TokenResponse(access_token=token)

    return TestClient(app)
