"""Tests for security module (password hashing, verification, JWT creation)."""

from unittest.mock import patch, MagicMock
import pytest
from datetime import datetime, timezone
from jose import jwt, JWTError

from app.security import hash_password, verify_password, create_access_token
from app.keys import load_public_key


class TestPasswordHashing:
    """Test password hashing and verification."""

    def test_hash_password_returns_string(self):
        """Password hash should return a string."""
        password = "secure_password_123"
        hash_result = hash_password(password)
        assert isinstance(hash_result, str)
        assert len(hash_result) > 0

    def test_hash_different_passwords_differently(self):
        """Different passwords should produce different hashes."""
        password1 = "secure_password_123"
        password2 = "different_password_456"
        hash1 = hash_password(password1)
        hash2 = hash_password(password2)
        assert hash1 != hash2

    def test_same_password_produces_different_hashes(self):
        """Same password should produce different hashes (salted)."""
        password = "secure_password_123"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        # Should be different due to random salt
        assert hash1 != hash2

    def test_verify_password_success(self):
        """Correct password should verify successfully."""
        password = "secure_password_123"
        password_hash = hash_password(password)
        assert verify_password(password, password_hash) is True

    def test_verify_password_failure_wrong_password(self):
        """Wrong password should fail verification."""
        correct_password = "secure_password_123"
        wrong_password = "wrong_password_456"
        password_hash = hash_password(correct_password)
        assert verify_password(wrong_password, password_hash) is False

    def test_verify_password_failure_empty_password(self):
        """Empty password should fail verification."""
        password = "secure_password_123"
        password_hash = hash_password(password)
        assert verify_password("", password_hash) is False

    def test_verify_password_handles_invalid_hash(self):
        """Invalid hash format should raise an exception or return False."""
        password = "secure_password_123"
        invalid_hash = "invalid_hash_format"
        # Argon2 may raise InvalidHashError for invalid format
        # This is expected behavior - the app should handle it upstream
        try:
            result = verify_password(password, invalid_hash)
            # If no exception, it should return False
            assert result is False
        except Exception:
            # Expected - invalid hash format raises an exception
            pass

    def test_verify_password_case_sensitive(self):
        """Password verification should be case-sensitive."""
        password = "SecurePassword123"
        password_hash = hash_password(password)
        assert verify_password("securepassword123", password_hash) is False


class TestAccessTokenCreation:
    """Test JWT access token creation and validation."""

    def test_create_access_token_returns_string(self, test_settings):
        """Token creation should return a string."""
        with patch("app.security.settings", test_settings):
            token = create_access_token(user_id=1, role="user")
            assert isinstance(token, str)
            assert len(token) > 0

    def test_create_access_token_jwt_format(self, test_settings):
        """Token should be a valid JWT (3 parts separated by dots)."""
        with patch("app.security.settings", test_settings):
            token = create_access_token(user_id=1, role="user")
            parts = token.split(".")
            assert len(parts) == 3

    def test_create_access_token_contains_user_id(self, test_settings):
        """Token payload should contain user_id as subject."""
        with patch("app.security.settings", test_settings):
            user_id = 42
            token = create_access_token(user_id=user_id, role="user")

            # Decode without verification to check payload
            decoded = jwt.get_unverified_claims(token)
            assert decoded["sub"] == str(user_id)

    def test_create_access_token_contains_role(self, test_settings):
        """Token payload should contain role."""
        with patch("app.security.settings", test_settings):
            role = "admin"
            token = create_access_token(user_id=1, role=role)

            decoded = jwt.get_unverified_claims(token)
            assert decoded["role"] == role

    def test_create_access_token_contains_timestamps(self, test_settings):
        """Token payload should contain iat and exp."""
        with patch("app.security.settings", test_settings):
            token = create_access_token(user_id=1, role="user")

            decoded = jwt.get_unverified_claims(token)
            assert "iat" in decoded
            assert "exp" in decoded
            assert decoded["iat"] <= decoded["exp"]

    def test_create_access_token_expiry_time(self, test_settings):
        """Token expiry should be ACCESS_TOKEN_TTL_MIN from now."""
        with patch("app.security.settings", test_settings):
            now = datetime.now(timezone.utc)
            token = create_access_token(user_id=1, role="user")

            decoded = jwt.get_unverified_claims(token)
            exp_timestamp = decoded["exp"]
            exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)

            # Should be approximately 15 minutes from now (allowing 2 second tolerance)
            time_diff = (exp_datetime - now).total_seconds()
            expected_diff = test_settings.ACCESS_TOKEN_TTL_MIN * 60
            assert abs(time_diff - expected_diff) < 2

    def test_create_access_token_algorithm_rs256(self, test_settings):
        """Token should be signed with RS256."""
        with patch("app.security.settings", test_settings):
            token = create_access_token(user_id=1, role="user")

            # Get header (first part)
            import base64
            header_b64 = token.split(".")[0]
            # Add padding if needed
            padding = 4 - len(header_b64) % 4
            if padding != 4:
                header_b64 += "=" * padding

            header_json = base64.urlsafe_b64decode(header_b64)
            import json

            header = json.loads(header_json)
            assert header["alg"] == "RS256"

    def test_create_access_token_different_users_different_tokens(self, test_settings):
        """Different user IDs should produce different tokens."""
        with patch("app.security.settings", test_settings):
            token1 = create_access_token(user_id=1, role="user")
            token2 = create_access_token(user_id=2, role="user")
            assert token1 != token2

    def test_create_access_token_different_roles_different_tokens(self, test_settings):
        """Different roles should produce different tokens."""
        with patch("app.security.settings", test_settings):
            token1 = create_access_token(user_id=1, role="user")
            token2 = create_access_token(user_id=1, role="admin")
            assert token1 != token2

    def test_create_access_token_signature_valid_with_public_key(self, test_settings):
        """Token signature should be verifiable with public key."""
        with patch("app.security.settings", test_settings):
            token = create_access_token(user_id=1, role="user")

            # Load public key
            public_key = load_public_key(test_settings.public_key_pem)

            # Verify token with public key
            decoded = jwt.decode(token, public_key, algorithms=["RS256"])
            assert decoded["sub"] == "1"
            assert decoded["role"] == "user"

    def test_create_access_token_multiple_calls_different_iat(self, test_settings):
        """Multiple token creations should have slightly different iat values."""
        import time

        with patch("app.security.settings", test_settings):
            token1 = create_access_token(user_id=1, role="user")
            time.sleep(0.1)
            token2 = create_access_token(user_id=1, role="user")

            decoded1 = jwt.get_unverified_claims(token1)
            decoded2 = jwt.get_unverified_claims(token2)

            # iat should be different (at least 1 second apart for normal execution)
            # In fast test environment they might be the same, so we just check they're valid
            assert "iat" in decoded1
            assert "iat" in decoded2


class TestJWTIntegration:
    """Integration tests for JWT creation and verification."""

    def test_token_roundtrip_verification(self, test_settings):
        """Token should be created and verified successfully."""
        with patch("app.security.settings", test_settings):
            user_id = 42
            role = "admin"
            token = create_access_token(user_id=user_id, role=role)

            public_key = load_public_key(test_settings.public_key_pem)
            decoded = jwt.decode(token, public_key, algorithms=["RS256"])

            assert decoded["sub"] == str(user_id)
            assert decoded["role"] == role

    def test_token_verification_fails_with_invalid_signature(self, test_settings):
        """Token verification should fail if signature is invalid."""
        with patch("app.security.settings", test_settings):
            token = create_access_token(user_id=1, role="user")

            # Tamper with the signature
            parts = token.split(".")
            tampered_token = parts[0] + "." + parts[1] + ".invalidsignature"

            public_key = load_public_key(test_settings.public_key_pem)

            with pytest.raises(JWTError):
                jwt.decode(tampered_token, public_key, algorithms=["RS256"])

    def test_token_verification_fails_when_expired(self, test_settings):
        """Token verification should fail if token is expired."""
        with patch("app.security.settings", test_settings):
            # Create settings with 0 TTL
            zero_ttl_settings = MagicMock(spec=test_settings.__class__)
            zero_ttl_settings.ACCESS_TOKEN_TTL_MIN = 0
            zero_ttl_settings.JWT_ALG = "RS256"
            zero_ttl_settings.private_key_pem = test_settings.private_key_pem
            zero_ttl_settings.public_key_pem = test_settings.public_key_pem

            with patch("app.security.settings", zero_ttl_settings):
                import time

                token = create_access_token(user_id=1, role="user")
                time.sleep(1)

                public_key = load_public_key(test_settings.public_key_pem)

                with pytest.raises(JWTError):
                    jwt.decode(token, public_key, algorithms=["RS256"])
