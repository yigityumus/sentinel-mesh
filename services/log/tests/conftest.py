"""Pytest configuration and fixtures for log-service tests."""

import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB

from app.db import Base
from app.models import Event
from app.settings import Settings

# Import detection modules so we can mock their settings
import app.detections.brute_force as brute_force_module
import app.detections.token_abuse as token_abuse_module
import app.detections.admin_probing as admin_probing_module


# Make JSONB work with SQLite for testing
@compiles(JSONB, 'sqlite')
def compile_jsonb_sqlite(type_, compiler, **kw):
    return 'JSON'


# Override settings for testing
@pytest.fixture
def test_settings():
    """Return test settings with lower thresholds for easier testing."""
    settings_obj = Settings(
        DATABASE_URL="sqlite:///:memory:",
        BRUTE_FORCE_THRESHOLD=3,
        BRUTE_FORCE_WINDOW_SECONDS=120,
        TOKEN_BURST_THRESHOLD=5,
        TOKEN_BURST_WINDOW_SECONDS=120,
        ADMIN_PROBING_THRESHOLD=3,
        ADMIN_PROBING_WINDOW_SECONDS=120,
    )
    # Replace the global settings in all detection modules
    brute_force_module.settings = settings_obj
    token_abuse_module.settings = settings_obj
    admin_probing_module.settings = settings_obj
    return settings_obj


@pytest.fixture
def db_engine(test_settings):
    """Create an in-memory SQLite database for testing."""
    # Create a NEW database for each test to ensure full isolation
    engine = create_engine(
        test_settings.DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def db_session(db_engine) -> Session:
    """Create a test database session."""
    TestingSessionLocal = sessionmaker(bind=db_engine, autoflush=False, autocommit=False)
    session = TestingSessionLocal()
    yield session
    session.rollback()  # Rollback to ensure test isolation
    session.close()


def utcnow():
    """Return current UTC time."""
    return datetime.now(timezone.utc)


@pytest.fixture
def sample_event_data():
    """Return base event data for creating events in tests."""
    base_time = utcnow()
    return {
        "v": 1,
        "ts": base_time,
        "service": "api",
        "ip": "192.168.1.100",
        "path": "/login",
        "user_id": None,
        "meta": {},
    }


@pytest.fixture
def create_event(db_session, sample_event_data):
    """Factory fixture to create Event objects."""
    def _create_event(**kwargs):
        data = sample_event_data.copy()
        data.update(kwargs)
        event = Event(**data)
        db_session.add(event)
        db_session.commit()
        return event
    return _create_event


@pytest.fixture
def create_multiple_events(db_session, sample_event_data):
    """Factory fixture to create multiple Event objects."""
    def _create_multiple_events(count: int, **kwargs):
        events = []
        base_time = utcnow()
        for i in range(count):
            data = sample_event_data.copy()
            # Create events with past timestamps (subtract seconds so they're before trigger)
            data["ts"] = base_time - timedelta(seconds=count - i)
            data.update(kwargs)
            event = Event(**data)
            db_session.add(event)
            events.append(event)
        db_session.commit()
        return events
    return _create_multiple_events
