"""Tests for authentication module."""

from unittest.mock import MagicMock, patch
from fastapi import Request, status
import pytest
from jose import jwt
from datetime import datetime, timezone, timedelta


class TestGetBearerToken:
    """Test suite for get_bearer_token function."""
    
    def test_extracts_bearer_token(self):
        """Should extract token from 'Bearer <token>' format."""
        from app.auth import get_bearer_token
        
        request = MagicMock(spec=Request)
        request.headers.get.return_value = "Bearer valid.jwt.token"
        
        token = get_bearer_token(request)
        assert token == "valid.jwt.token"
    
    def test_raises_on_missing_header(self):
        """Should raise HTTPException when Authorization header is missing."""
        from app.auth import get_bearer_token
        
        request = MagicMock(spec=Request)
        request.headers.get.return_value = ""
        
        with patch("app.auth.send_event"):
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc_info:
                get_bearer_token(request)
            
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
            assert exc_info.value.detail == "Missing token"
    
    def test_raises_on_invalid_format(self):
        """Should raise HTTPException when Authorization format is invalid."""
        from app.auth import get_bearer_token
        
        request = MagicMock(spec=Request)
        request.headers.get.return_value = "InvalidFormat token"
        
        with patch("app.auth.send_event"):
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc_info:
                get_bearer_token(request)
            
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_logs_missing_token_event(self):
        """Should log event when token is missing."""
        from app.auth import get_bearer_token
        
        request = MagicMock(spec=Request)
        request.headers.get.return_value = ""
        
        with patch("app.auth.send_event") as mock_send:
            from fastapi import HTTPException
            try:
                get_bearer_token(request)
            except HTTPException:
                pass
            
            mock_send.assert_called_once()
            assert mock_send.call_args[1]["event"] == "missing_token"


class TestGetCurrentUser:
    """Test suite for get_current_user function."""
    
    def test_validates_valid_token(self, rsa_keys, test_settings):
        """Should validate and return user info from valid token."""
        from app.auth import get_current_user
        
        payload = {
            "sub": "test-user",
            "role": "user",
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        }
        token = jwt.encode(payload, rsa_keys["private"], algorithm="RS256")
        
        request = MagicMock(spec=Request)
        request.headers.get.side_effect = lambda k, default="": (
            f"Bearer {token}" if k == "Authorization" else default
        )
        
        with patch("app.auth.settings", test_settings):
            with patch("app.auth.send_event"):
                user = get_current_user(request, token)
                
                assert user["user_id"] == "test-user"
                assert user["role"] == "user"
    
    def test_rejects_invalid_signature(self, test_settings):
        """Should reject token with invalid signature."""
        from app.auth import get_current_user
        from fastapi import HTTPException
        import pytest
        
        invalid_token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0Iiwicm9sZSI6InVzZXIifQ.invalid_sig"
        
        request = MagicMock(spec=Request)
        
        with patch("app.auth.settings", test_settings):
            with patch("app.auth.send_event"):
                with pytest.raises(HTTPException) as exc_info:
                    get_current_user(request, invalid_token)
                
                assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
                assert exc_info.value.detail == "Invalid token"
    
    def test_rejects_expired_token(self, rsa_keys, test_settings):
        """Should reject expired token."""
        from app.auth import get_current_user
        from fastapi import HTTPException
        import pytest
        
        payload = {
            "sub": "test-user",
            "role": "user",
            "iat": int((datetime.now(timezone.utc) - timedelta(hours=2)).timestamp()),
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),
        }
        token = jwt.encode(payload, rsa_keys["private"], algorithm="RS256")
        
        request = MagicMock(spec=Request)
        
        with patch("app.auth.settings", test_settings):
            with patch("app.auth.send_event"):
                with pytest.raises(HTTPException) as exc_info:
                    get_current_user(request, token)
                
                assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_rejects_token_missing_sub(self, rsa_keys, test_settings):
        """Should reject token without 'sub' claim."""
        from app.auth import get_current_user
        from fastapi import HTTPException
        import pytest
        
        payload = {
            "role": "user",
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        }
        token = jwt.encode(payload, rsa_keys["private"], algorithm="RS256")
        
        request = MagicMock(spec=Request)
        
        with patch("app.auth.settings", test_settings):
            with patch("app.auth.send_event"):
                with pytest.raises(HTTPException) as exc_info:
                    get_current_user(request, token)
                
                assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
                assert exc_info.value.detail == "Invalid token claims"
    
    def test_rejects_token_missing_role(self, rsa_keys, test_settings):
        """Should reject token without 'role' claim."""
        from app.auth import get_current_user
        from fastapi import HTTPException
        import pytest
        
        payload = {
            "sub": "test-user",
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        }
        token = jwt.encode(payload, rsa_keys["private"], algorithm="RS256")
        
        request = MagicMock(spec=Request)
        
        with patch("app.auth.settings", test_settings):
            with patch("app.auth.send_event"):
                with pytest.raises(HTTPException) as exc_info:
                    get_current_user(request, token)
                
                assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
                assert exc_info.value.detail == "Invalid token claims"


class TestClientIPExtraction:
    """Test suite for client_ip function."""
    
    def test_extracts_x_real_ip_header(self):
        """Should use x-real-ip header if present."""
        from app.auth import client_ip
        
        request = MagicMock(spec=Request)
        request.headers.get.side_effect = lambda k, default="": (
            "192.168.1.100" if k == "x-real-ip" else default
        )
        request.client.host = "127.0.0.1"
        
        ip = client_ip(request)
        assert ip == "192.168.1.100"
    
    def test_falls_back_to_client_host(self):
        """Should fall back to request.client.host if x-real-ip not present."""
        from app.auth import client_ip
        
        request = MagicMock(spec=Request)
        request.headers.get.return_value = ""
        request.client.host = "192.168.1.50"
        
        ip = client_ip(request)
        assert ip == "192.168.1.50"
    
    def test_handles_missing_client(self):
        """Should handle missing client gracefully."""
        from app.auth import client_ip
        
        request = MagicMock(spec=Request)
        request.headers.get.return_value = ""
        request.client = None
        
        ip = client_ip(request)
        assert ip == "unknown"


class TestOriginalPathExtraction:
    """Test suite for original_path function."""
    
    def test_extracts_x_original_uri_header(self):
        """Should use x-original-uri header if present."""
        from app.auth import original_path
        
        request = MagicMock(spec=Request)
        request.headers.get.side_effect = lambda k, default="": (
            "/api/v1/protected" if k == "x-original-uri" else default
        )
        request.url.path = "/protected"
        
        path = original_path(request)
        assert path == "/api/v1/protected"
    
    def test_falls_back_to_request_path(self):
        """Should fall back to request.url.path if header not present."""
        from app.auth import original_path
        
        request = MagicMock(spec=Request)
        request.headers.get.return_value = ""
        request.url.path = "/me"
        
        path = original_path(request)
        assert path == "/me"
