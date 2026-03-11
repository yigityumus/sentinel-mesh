"""Tests for User model."""

import pytest
from sqlalchemy import inspect
from datetime import datetime, timezone

from app.models import User
from app.security import hash_password


class TestUserModel:
    """Test User model structure and constraints."""

    def test_user_has_required_columns(self):
        """User model should have all required columns."""
        mapper = inspect(User)
        column_names = [col.name for col in mapper.columns]

        assert "id" in column_names
        assert "email" in column_names
        assert "password_hash" in column_names
        assert "role" in column_names
        assert "created_at" in column_names

    def test_user_email_is_unique(self, db_session):
        """Email field should be unique."""
        email = "unique@example.com"
        user1 = User(email=email, password_hash=hash_password("password1"), role="user")
        db_session.add(user1)
        db_session.commit()

        user2 = User(email=email, password_hash=hash_password("password2"), role="user")
        db_session.add(user2)

        with pytest.raises(Exception):  # IntegrityError
            db_session.commit()

    def test_user_email_is_indexed(self):
        """Email field should be indexed."""
        mapper = inspect(User)
        # Check if email column has index=True
        email_column = mapper.columns["email"]
        assert email_column.index is True

    def test_user_id_is_primary_key(self):
        """ID should be the primary key."""
        mapper = inspect(User)
        pk_columns = mapper.primary_key
        assert len(pk_columns) == 1
        assert pk_columns[0].name == "id"

    def test_user_default_role_is_user(self, db_session):
        """Default role should be 'user'."""
        user = User(
            email="test@example.com",
            password_hash=hash_password("password123"),
        )
        # Don't set role, let it use default
        db_session.add(user)
        db_session.commit()

        assert user.role == "user"

    def test_user_role_can_be_set_to_admin(self, db_session):
        """Role should be settable to 'admin'."""
        user = User(
            email="admin@example.com",
            password_hash=hash_password("password123"),
            role="admin",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        assert user.role == "admin"

    def test_user_created_at_is_set_automatically(self, db_session):
        """created_at should be set automatically."""
        user = User(
            email="test@example.com",
            password_hash=hash_password("password123"),
            role="user",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        assert user.created_at is not None
        assert isinstance(user.created_at, datetime)

    def test_user_created_at_is_recent(self, db_session):
        """created_at should be approximately now."""
        user = User(
            email="test@example.com",
            password_hash=hash_password("password123"),
            role="user",
        )
        before = datetime.now(timezone.utc).replace(microsecond=0)
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        after = datetime.now(timezone.utc).replace(microsecond=999999)

        # created_at should be between before and after
        user_created_tz = user.created_at.replace(tzinfo=timezone.utc) if user.created_at.tzinfo is None else user.created_at
        user_created_tz = user_created_tz.replace(microsecond=0)
        assert before <= user_created_tz <= after

    def test_user_email_is_not_nullable(self, db_session):
        """Email should be required (not nullable)."""
        user = User(
            email=None,
            password_hash=hash_password("password123"),
            role="user",
        )
        db_session.add(user)

        with pytest.raises(Exception):  # IntegrityError or similar
            db_session.commit()

    def test_user_password_hash_is_not_nullable(self, db_session):
        """Password hash should be required (not nullable)."""
        user = User(
            email="test@example.com",
            password_hash=None,
            role="user",
        )
        db_session.add(user)

        with pytest.raises(Exception):  # IntegrityError
            db_session.commit()

    def test_user_can_be_created_with_minimal_fields(self, db_session):
        """User should be creatable with just email and password_hash."""
        user = User(
            email="minimal@example.com",
            password_hash=hash_password("password123"),
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        assert user.id is not None
        assert user.email == "minimal@example.com"
        assert user.role == "user"  # default


class TestUserModelQueryOperations:
    """Test querying and filtering User records."""

    def test_query_user_by_email(self, create_user, db_session):
        """Should be able to query user by email."""
        from sqlalchemy import select

        user = create_user(email="query@example.com")

        result = db_session.execute(select(User).where(User.email == "query@example.com")).scalar_one_or_none()
        assert result is not None
        assert result.id == user.id
        assert result.email == user.email

    def test_query_user_case_insensitive_email(self, create_user, db_session):
        """Email queries should work with lowercase after normalization."""
        from sqlalchemy import select

        create_user(email="CaseTest@Example.com")

        # App normalizes emails to lowercase on insert, so query with lowercase should find it
        result = db_session.execute(select(User).where(User.email == "casetest@example.com")).scalar_one_or_none()

        # Should find it because the app normalizes emails to lowercase
        assert result is not None
        assert result.email == "casetest@example.com"

    def test_query_nonexistent_user_returns_none(self, db_session):
        """Query for nonexistent user should return None."""
        from sqlalchemy import select

        result = db_session.execute(select(User).where(User.email == "nonexistent@example.com")).scalar_one_or_none()
        assert result is None

    def test_count_users(self, create_multiple_users, db_session):
        """Should be able to count users."""
        from sqlalchemy import select, func

        create_multiple_users(5)

        count = db_session.execute(select(func.count(User.id))).scalar()
        assert count == 5


class TestUserModelRelations:
    """Test User model relationships and constraints."""

    def test_user_email_max_length(self, db_session):
        """Email field should have max length of 320."""
        # Create a valid email that's 320 chars
        email = "a" * 64 + "@" + "b" * 250 + ".com"  # Under 320
        user = User(
            email=email[:320],
            password_hash=hash_password("password123"),
            role="user",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        assert user.email == email[:320]

    def test_user_password_hash_max_length(self, db_session):
        """Password hash field should have max length of 500."""
        # Argon2 hashes are typically ~100 chars, so 500 is plenty
        user = User(
            email="test@example.com",
            password_hash=hash_password("password123"),
            role="user",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        assert len(user.password_hash) <= 500

    def test_user_role_max_length(self, db_session):
        """Role field should have max length of 32."""
        user = User(
            email="test@example.com",
            password_hash=hash_password("password123"),
            role="a" * 32,  # Max length
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        assert user.role == "a" * 32
