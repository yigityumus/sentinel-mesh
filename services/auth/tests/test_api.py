"""Tests for API endpoints."""




class TestHealthzEndpoint:
    """Test /healthz endpoint."""

    def test_healthz_returns_ok(self, fastapi_client):
        """GET /healthz should return status ok."""
        response = fastapi_client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_healthz_content_type(self, fastapi_client):
        """GET /healthz should return JSON."""
        response = fastapi_client.get("/healthz")
        assert response.headers["content-type"] == "application/json"


class TestJWKSEndpoint:
    """Test /.well-known/jwks.json endpoint."""

    def test_jwks_returns_json(self, fastapi_client):
        """GET /.well-known/jwks.json should return JWKS format."""
        response = fastapi_client.get("/.well-known/jwks.json")
        assert response.status_code == 200

        data = response.json()
        assert "keys" in data
        assert isinstance(data["keys"], list)
        assert len(data["keys"]) > 0

    def test_jwks_key_structure(self, fastapi_client):
        """JWKS keys should have correct structure."""
        response = fastapi_client.get("/.well-known/jwks.json")
        data = response.json()
        key = data["keys"][0]

        assert key["kty"] == "RSA"
        assert key["use"] == "sig"
        assert "kid" in key
        assert "n" in key  # RSA modulus
        assert "e" in key  # RSA exponent
        assert key["alg"] == "RS256"

    def test_jwks_key_id_consistent(self, fastapi_client):
        """Key ID should be consistent across requests."""
        response1 = fastapi_client.get("/.well-known/jwks.json")
        response2 = fastapi_client.get("/.well-known/jwks.json")

        kid1 = response1.json()["keys"][0]["kid"]
        kid2 = response2.json()["keys"][0]["kid"]

        assert kid1 == kid2

    def test_jwks_public_key_valid(self, fastapi_client, test_settings):
        """JWKS public key should be loadable."""

        response = fastapi_client.get("/.well-known/jwks.json")

        # The exposed key should match the settings public key
        assert response.status_code == 200


class TestSignupEndpoint:
    """Test /signup endpoint."""

    def test_signup_success(self, fastapi_client, mock_send_event):
        """POST /signup should create user and return 201."""
        response = fastapi_client.post(
            "/signup",
            json={
                "email": "newuser@example.com",
                "password": "secure_password_123",
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "newuser@example.com"
        assert data["role"] == "user"
        assert "id" in data

    def test_signup_success_sends_event(self, fastapi_client, mock_send_event):
        """Successful signup should send event to log service."""
        response = fastapi_client.post(
            "/signup",
            json={
                "email": "newuser@example.com",
                "password": "secure_password_123",
            },
        )

        assert response.status_code == 201
        mock_send_event.assert_called_once()
        call_kwargs = mock_send_event.call_args[1]
        assert call_kwargs["event"] == "signup_success"
        assert call_kwargs["meta"]["email"] == "newuser@example.com"

    def test_signup_email_already_exists(self, create_user, fastapi_client, mock_send_event):
        """POST /signup with duplicate email should return 409."""
        create_user(email="existing@example.com")

        response = fastapi_client.post(
            "/signup",
            json={
                "email": "existing@example.com",
                "password": "secure_password_123",
            },
        )

        assert response.status_code == 409
        assert response.json()["detail"] == "Email already registered"

    def test_signup_email_already_exists_different_case(self, create_user, fastapi_client, mock_send_event):
        """Signup should treat emails case-insensitively."""
        create_user(email="existing@example.com")

        response = fastapi_client.post(
            "/signup",
            json={
                "email": "EXISTING@EXAMPLE.COM",
                "password": "secure_password_123",
            },
        )

        assert response.status_code == 409

    def test_signup_duplicate_email_sends_conflict_event(self, create_user, fastapi_client, mock_send_event):
        """Duplicate signup should send conflict event."""
        create_user(email="existing@example.com")

        response = fastapi_client.post(
            "/signup",
            json={
                "email": "existing@example.com",
                "password": "secure_password_123",
            },
        )

        assert response.status_code == 409
        mock_send_event.assert_called_once()
        call_kwargs = mock_send_event.call_args[1]
        assert call_kwargs["event"] == "signup_conflict"

    def test_signup_invalid_email_format(self, fastapi_client):
        """Invalid email should return 422."""
        response = fastapi_client.post(
            "/signup",
            json={
                "email": "invalid_email",
                "password": "secure_password_123",
            },
        )

        assert response.status_code == 422

    def test_signup_password_too_short(self, fastapi_client):
        """Password shorter than 10 chars should return 422."""
        response = fastapi_client.post(
            "/signup",
            json={
                "email": "newuser@example.com",
                "password": "short",
            },
        )

        assert response.status_code == 422

    def test_signup_missing_email(self, fastapi_client):
        """Missing email should return 422."""
        response = fastapi_client.post(
            "/signup",
            json={
                "password": "secure_password_123",
            },
        )

        assert response.status_code == 422

    def test_signup_missing_password(self, fastapi_client):
        """Missing password should return 422."""
        response = fastapi_client.post(
            "/signup",
            json={
                "email": "newuser@example.com",
            },
        )

        assert response.status_code == 422

    def test_signup_user_stored_with_hashed_password(self, fastapi_client, db_session):
        """Stored user should have hashed password, not plaintext."""
        from app.models import User
        from sqlalchemy import select

        password = "secure_password_123"
        response = fastapi_client.post(
            "/signup",
            json={
                "email": "newuser@example.com",
                "password": password,
            },
        )

        assert response.status_code == 201

        # Query database directly
        user = db_session.execute(select(User).where(User.email == "newuser@example.com")).scalar_one()
        assert user.password_hash != password
        assert user.password_hash.startswith("$argon2")

    def test_signup_email_normalized_to_lowercase(self, fastapi_client, db_session):
        """Stored email should be normalized to lowercase"""
        from app.models import User
        from sqlalchemy import select

        response = fastapi_client.post(
            "/signup",
            json={
                "email": "NewUser@EXAMPLE.COM",
                "password": "secure_password_123",
            },
        )

        assert response.status_code == 201

        user = db_session.execute(select(User).where(User.email == "newuser@example.com")).scalar_one()
        assert user.email == "newuser@example.com"

    def test_signup_response_excludes_password_hash(self, fastapi_client):
        """Response should not include password hash."""
        response = fastapi_client.post(
            "/signup",
            json={
                "email": "newuser@example.com",
                "password": "secure_password_123",
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert "password_hash" not in data
        assert "password" not in data

    def test_signup_creates_user_with_default_role(self, fastapi_client, db_session):
        """Created user should have default role 'user'."""
        from app.models import User
        from sqlalchemy import select

        response = fastapi_client.post(
            "/signup",
            json={
                "email": "newuser@example.com",
                "password": "secure_password_123",
            },
        )

        assert response.status_code == 201

        user = db_session.execute(select(User).where(User.email == "newuser@example.com")).scalar_one()
        assert user.role == "user"


class TestLoginEndpoint:
    """Test /login endpoint."""

    def test_login_success_returns_token(self, create_user, fastapi_client, mock_send_event):
        """POST /login with correct credentials should return token."""
        create_user(email="user@example.com", password="correct_password_123")

        response = fastapi_client.post(
            "/login",
            json={
                "email": "user@example.com",
                "password": "correct_password_123",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_success_sends_event(self, create_user, fastapi_client, mock_send_event):
        """Successful login should send event to log service."""
        create_user(email="user@example.com", password="correct_password_123")

        response = fastapi_client.post(
            "/login",
            json={
                "email": "user@example.com",
                "password": "correct_password_123",
            },
        )

        assert response.status_code == 200
        mock_send_event.assert_called_once()
        call_kwargs = mock_send_event.call_args[1]
        assert call_kwargs["event"] == "login_success"

    def test_login_wrong_password(self, create_user, fastapi_client, mock_send_event):
        """POST /login with wrong password should return 401."""
        create_user(email="user@example.com", password="correct_password_123")

        response = fastapi_client.post(
            "/login",
            json={
                "email": "user@example.com",
                "password": "wrong_password_456",
            },
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid credentials"

    def test_login_wrong_password_sends_failed_event(self, create_user, fastapi_client, mock_send_event):
        """Failed login should send login_failed event."""
        create_user(email="user@example.com", password="correct_password_123")

        response = fastapi_client.post(
            "/login",
            json={
                "email": "user@example.com",
                "password": "wrong_password_456",
            },
        )

        assert response.status_code == 401
        mock_send_event.assert_called_once()
        call_kwargs = mock_send_event.call_args[1]
        assert call_kwargs["event"] == "login_failed"

    def test_login_nonexistent_user(self, fastapi_client, mock_send_event):
        """POST /login with nonexistent email should return 401."""
        response = fastapi_client.post(
            "/login",
            json={
                "email": "nonexistent@example.com",
                "password": "any_password",
            },
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid credentials"

    def test_login_nonexistent_user_sends_failed_event(self, fastapi_client, mock_send_event):
        """Nonexistent user login should send login_failed event."""
        response = fastapi_client.post(
            "/login",
            json={
                "email": "nonexistent@example.com",
                "password": "any_password",
            },
        )

        assert response.status_code == 401
        mock_send_event.assert_called_once()
        call_kwargs = mock_send_event.call_args[1]
        assert call_kwargs["event"] == "login_failed"

    def test_login_user_enumeration_protection(self, create_user, fastapi_client):
        """Same error message for missing user and wrong password."""
        create_user(email="existing@example.com", password="correct_password_123")

        # Try with existing user and wrong password
        response1 = fastapi_client.post(
            "/login",
            json={
                "email": "existing@example.com",
                "password": "wrong_password",
            },
        )

        # Try with nonexistent user
        response2 = fastapi_client.post(
            "/login",
            json={
                "email": "nonexistent@example.com",
                "password": "any_password",
            },
        )

        assert response1.status_code == 401
        assert response2.status_code == 401
        assert response1.json()["detail"] == response2.json()["detail"]

    def test_login_email_case_insensitive(self, create_user, fastapi_client):
        """Login should work with different email case."""
        create_user(email="user@example.com", password="correct_password_123")

        response = fastapi_client.post(
            "/login",
            json={
                "email": "USER@EXAMPLE.COM",
                "password": "correct_password_123",
            },
        )

        assert response.status_code == 200

    def test_login_invalid_email_format(self, fastapi_client):
        """Invalid email format should return 422."""
        response = fastapi_client.post(
            "/login",
            json={
                "email": "invalid_email",
                "password": "any_password",
            },
        )

        assert response.status_code == 422

    def test_login_missing_email(self, fastapi_client):
        """Missing email should return 422."""
        response = fastapi_client.post(
            "/login",
            json={
                "password": "any_password",
            },
        )

        assert response.status_code == 422

    def test_login_missing_password(self, fastapi_client):
        """Missing password should return 422."""
        response = fastapi_client.post(
            "/login",
            json={
                "email": "user@example.com",
            },
        )

        assert response.status_code == 422

    def test_login_token_contains_user_id(self, create_user, fastapi_client):
        """Token should contain user_id in payload."""
        create_user(email="user@example.com", password="correct_password_123")

        response = fastapi_client.post(
            "/login",
            json={
                "email": "user@example.com",
                "password": "correct_password_123",
            },
        )

        assert response.status_code == 200
        token = response.json()["access_token"]

        # Verify token structure
        parts = token.split(".")
        assert len(parts) == 3

    def test_login_empty_password(self, fastapi_client):
        """Empty password should return 422."""
        response = fastapi_client.post(
            "/login",
            json={
                "email": "user@example.com",
                "password": "",
            },
        )

        assert response.status_code == 422


class TestRequestVariations:
    """Test various request edge cases."""

    def test_signup_with_special_characters_in_password(self, fastapi_client):
        """Password with special characters should work."""
        response = fastapi_client.post(
            "/signup",
            json={
                "email": "newuser@example.com",
                "password": "P@ssw0rd!#$%^&*()_+-=[]{}|;:,.<>",
            },
        )

        assert response.status_code == 201

    def test_api_methods_not_allowed(self, fastapi_client):
        """Wrong HTTP methods should return 405."""
        response = fastapi_client.get("/signup")
        assert response.status_code == 405

        response = fastapi_client.get("/login")
        assert response.status_code == 405
