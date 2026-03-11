"""Tests for request/response schemas."""

import pytest
from pydantic import ValidationError

from app.schemas import SignupRequest, LoginRequest, TokenResponse


class TestSignupRequestSchema:
    """Test SignupRequest schema validation."""

    def test_signup_request_valid_data(self):
        """Valid signup request should be accepted."""
        request = SignupRequest(
            email="test@example.com",
            password="secure_password_123",
        )
        assert request.email == "test@example.com"
        assert request.password == "secure_password_123"

    def test_signup_request_email_required(self):
        """Email is required in signup request."""
        with pytest.raises(ValidationError):
            SignupRequest(password="secure_password_123")

    def test_signup_request_password_required(self):
        """Password is required in signup request."""
        with pytest.raises(ValidationError):
            SignupRequest(email="test@example.com")

    def test_signup_request_invalid_email_format(self):
        """Invalid email format should be rejected."""
        with pytest.raises(ValidationError):
            SignupRequest(
                email="invalid_email",
                password="secure_password_123",
            )

    def test_signup_request_email_with_spaces(self):
        """Email with invalid spaces should be rejected."""
        with pytest.raises(ValidationError):
            SignupRequest(
                email="test @example.com",
                password="secure_password_123",
            )

    def test_signup_request_email_empty_string(self):
        """Empty email should be rejected."""
        with pytest.raises(ValidationError):
            SignupRequest(
                email="",
                password="secure_password_123",
            )

    def test_signup_request_password_too_short(self):
        """Password shorter than 10 characters should be rejected."""
        with pytest.raises(ValidationError):
            SignupRequest(
                email="test@example.com",
                password="short123",  # 8 chars
            )

    def test_signup_request_password_exactly_10_chars(self):
        """Password with exactly 10 characters should be accepted."""
        request = SignupRequest(
            email="test@example.com",
            password="password10",  # 10 chars
        )
        assert request.password == "password10"

    def test_signup_request_password_too_long(self):
        """Password longer than 128 characters should be rejected."""
        with pytest.raises(ValidationError):
            SignupRequest(
                email="test@example.com",
                password="a" * 129,
            )

    def test_signup_request_password_exactly_128_chars(self):
        """Password with exactly 128 characters should be accepted."""
        password = "a" * 128
        request = SignupRequest(
            email="test@example.com",
            password=password,
        )
        assert request.password == password

    def test_signup_request_email_normalization_with_plus(self):
        """Email with plus addressing should be accepted."""
        request = SignupRequest(
            email="user+tag@example.com",
            password="secure_password_123",
        )
        assert request.email == "user+tag@example.com"

    def test_signup_request_email_with_subdomain(self):
        """Email with subdomain should be accepted."""
        request = SignupRequest(
            email="user@mail.example.co.uk",
            password="secure_password_123",
        )
        assert request.email == "user@mail.example.co.uk"

    def test_signup_request_special_characters_in_password(self):
        """Password with special characters should be accepted."""
        request = SignupRequest(
            email="test@example.com",
            password="P@ssw0rd!#$%^&*()",
        )
        assert request.password == "P@ssw0rd!#$%^&*()"


class TestLoginRequestSchema:
    """Test LoginRequest schema validation."""

    def test_login_request_valid_data(self):
        """Valid login request should be accepted."""
        request = LoginRequest(
            email="test@example.com",
            password="any_password",
        )
        assert request.email == "test@example.com"
        assert request.password == "any_password"

    def test_login_request_email_required(self):
        """Email is required in login request."""
        with pytest.raises(ValidationError):
            LoginRequest(password="any_password")

    def test_login_request_password_required(self):
        """Password is required in login request."""
        with pytest.raises(ValidationError):
            LoginRequest(email="test@example.com")

    def test_login_request_invalid_email_format(self):
        """Invalid email format should be rejected."""
        with pytest.raises(ValidationError):
            LoginRequest(
                email="invalid_email",
                password="any_password",
            )

    def test_login_request_empty_password(self):
        """Empty password should be rejected."""
        with pytest.raises(ValidationError):
            LoginRequest(
                email="test@example.com",
                password="",
            )

    def test_login_request_password_min_length_1(self):
        """Password with 1 character should be accepted."""
        request = LoginRequest(
            email="test@example.com",
            password="a",
        )
        assert request.password == "a"

    def test_login_request_password_too_long(self):
        """Password longer than 128 characters should be rejected."""
        with pytest.raises(ValidationError):
            LoginRequest(
                email="test@example.com",
                password="a" * 129,
            )

    def test_login_request_password_exactly_128_chars(self):
        """Password with exactly 128 characters should be accepted."""
        password = "a" * 128
        request = LoginRequest(
            email="test@example.com",
            password=password,
        )
        assert request.password == password

    def test_login_request_password_exactly_1_char(self):
        """Password with exactly 1 character should be accepted."""
        request = LoginRequest(
            email="test@example.com",
            password="x",
        )
        assert request.password == "x"


class TestTokenResponseSchema:
    """Test TokenResponse schema validation."""

    def test_token_response_valid_data(self):
        """Valid token response should be accepted."""
        response = TokenResponse(access_token="test_token_string")
        assert response.access_token == "test_token_string"
        assert response.token_type == "bearer"

    def test_token_response_default_token_type(self):
        """Token type should default to 'bearer'."""
        response = TokenResponse(access_token="test_token_string")
        assert response.token_type == "bearer"

    def test_token_response_custom_token_type(self):
        """Token type can be customized (though not recommended)."""
        response = TokenResponse(access_token="test_token_string", token_type="custom")
        assert response.token_type == "custom"

    def test_token_response_long_token_string(self):
        """TokenResponse should accept long token strings."""
        long_token = "a" * 1000
        response = TokenResponse(access_token=long_token)
        assert response.access_token == long_token

    def test_token_response_access_token_required(self):
        """access_token is required."""
        with pytest.raises(ValidationError):
            TokenResponse()

    def test_token_response_serialization(self):
        """TokenResponse should serialize correctly to dict."""
        response = TokenResponse(access_token="test_token")
        data = response.model_dump()
        assert data["access_token"] == "test_token"
        assert data["token_type"] == "bearer"

    def test_token_response_json_schema(self):
        """TokenResponse should have correct JSON schema."""
        schema = TokenResponse.model_json_schema()
        assert "access_token" in schema["properties"]
        assert "token_type" in schema["properties"]
        assert "access_token" in schema["required"]


class TestSchemaIntegration:
    """Integration tests for schemas."""

    def test_signup_then_login_schema_compatibility(self):
        """Signup request email/password should be compatible with login."""
        signup = SignupRequest(
            email="user@example.com",
            password="secure_password_123",
        )

        login = LoginRequest(
            email=signup.email,
            password=signup.password,
        )

        assert login.email == signup.email
        assert login.password == signup.password

    def test_schema_doesnt_mutate_input_data(self):
        """Schema validation should not mutate input data."""
        data = {
            "email": "test@example.com",
            "password": "secure_password_123",
        }
        original_data = data.copy()

        SignupRequest(**data)

        assert data == original_data
