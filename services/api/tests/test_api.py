"""Tests for API service endpoints."""

from fastapi import status


class TestHealthzEndpoint:
    """Test suite for /healthz endpoint."""
    
    def test_healthz_returns_ok(self, api_client):
        """Should return ok status without authentication."""
        response = api_client.get("/healthz")
        
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {"status": "ok"}
    
    def test_healthz_always_available(self, api_client):
        """Should be available regardless of other service status."""
        for _ in range(5):
            response = api_client.get("/healthz")
            assert response.status_code == status.HTTP_200_OK


class TestMeEndpoint:
    """Test suite for GET /me endpoint (requires auth)."""
    
    def test_me_returns_user_info(self, authenticated_client):
        """Should return authenticated user's info."""
        response = authenticated_client.get("/me")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["user_id"] == "test-user"
        assert data["role"] == "user"
    
    def test_me_returns_current_user_id(self, api_client, create_token):
        """Should return the specific user making the request."""
        for user_id in ["user1", "user2", "user3"]:
            token = create_token(user_id=user_id, role="user")
            headers = {"Authorization": f"Bearer {token}"}
            response = api_client.get("/me", headers=headers)
            
            assert response.status_code == status.HTTP_200_OK
            assert response.json()["user_id"] == user_id
    
    def test_me_requires_authentication(self, api_client):
        """Should reject request without authorization header."""
        response = api_client.get("/me")
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()["detail"] == "Missing token"


class TestAdminStatsEndpoint:
    """Test suite for GET /admin/stats endpoint (requires admin role)."""
    
    def test_admin_stats_returns_stats(self, admin_client):
        """Should return stats for authenticated admin."""
        response = admin_client.get("/admin/stats")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["message"] == "admin ok"
        assert data["admin_user_id"] == "admin-user"
        assert "stats" in data
        assert "users_total" in data["stats"]
        assert "alerts_total" in data["stats"]
    
    def test_admin_stats_requires_admin_role(self, authenticated_client):
        """Should reject non-admin users."""
        response = authenticated_client.get("/admin/stats")
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.json()["detail"] == "Forbidden"
    
    def test_admin_stats_requires_authentication(self, api_client):
        """Should reject request without authentication."""
        response = api_client.get("/admin/stats")
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestAuthenticationFailures:
    """Test suite for authentication error scenarios."""
    
    def test_missing_authorization_header(self, api_client):
        """Should return 401 when Authorization header is missing."""
        response = api_client.get("/me")
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()["detail"] == "Missing token"
    
    def test_invalid_bearer_token_format(self, api_client):
        """Should reject malformed Bearer token."""
        headers = {"Authorization": "InvalidToken"}
        response = api_client.get("/me", headers=headers)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()["detail"] == "Missing token"
    
    def test_invalid_jwt_signature(self, api_client):
        """Should reject JWT with invalid signature."""
        invalid_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0Iiwicm9sZSI6InVzZXIifQ.invalid_signature"
        headers = {"Authorization": f"Bearer {invalid_token}"}
        response = api_client.get("/me", headers=headers)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()["detail"] == "Invalid token"
    
    def test_expired_token(self, api_client, create_token):
        """Should reject expired tokens."""
        # Create token with negative expiry (expired)
        token = create_token(user_id="test-user", role="user", exp_delta=-1)
        headers = {"Authorization": f"Bearer {token}"}
        response = api_client.get("/me", headers=headers)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()["detail"] == "Invalid token"
    
    def test_token_missing_subject_claim(self, api_client, rsa_keys):
        """Should reject token without 'sub' claim."""
        from jose import jwt
        from datetime import datetime, timezone, timedelta
        
        payload = {
            "role": "user",
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        }
        token = jwt.encode(payload, rsa_keys["private"], algorithm="RS256")
        headers = {"Authorization": f"Bearer {token}"}
        response = api_client.get("/me", headers=headers)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()["detail"] == "Invalid token claims"
    
    def test_token_missing_role_claim(self, api_client, rsa_keys):
        """Should reject token without 'role' claim."""
        from jose import jwt
        from datetime import datetime, timezone, timedelta
        
        payload = {
            "sub": "test-user",
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        }
        token = jwt.encode(payload, rsa_keys["private"], algorithm="RS256")
        headers = {"Authorization": f"Bearer {token}"}
        response = api_client.get("/me", headers=headers)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()["detail"] == "Invalid token claims"


class TestClientIPHeader:
    """Test suite for x-real-ip header handling."""
    
    def test_client_ip_from_x_real_ip_header(self, authenticated_client, mock_send_event):
        """Should use x-real-ip header for client IP."""
        authenticated_client.client.headers["x-real-ip"] = "192.168.1.100"
        response = authenticated_client.get("/me")
        
        assert response.status_code == status.HTTP_200_OK
    
    def test_logs_with_correct_ip_on_auth_failure(self, api_client, mock_send_event):
        """Should log auth failures with client IP."""
        headers = {"x-real-ip": "203.0.113.50"}
        response = api_client.get("/me", headers=headers)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        # Verify send_event was called
        assert mock_send_event.called


class TestOriginalPathHeader:
    """Test suite for x-original-uri header handling."""
    
    def test_original_path_from_header(self, authenticated_client):
        """Should use x-original-uri header for path."""
        authenticated_client.client.headers["x-original-uri"] = "/api/v1/me"
        response = authenticated_client.get("/me")
        
        assert response.status_code == status.HTTP_200_OK
    
    def test_logs_with_correct_path_on_auth_failure(self, api_client, mock_send_event):
        """Should log auth failures with original path."""
        headers = {"x-original-uri": "/api/v1/me"}
        response = api_client.get("/me", headers=headers)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        # Verify send_event was called
        assert mock_send_event.called


class TestRoleManagement:
    """Test suite for role-based access control."""
    
    def test_admin_role_access_to_admin_endpoint(self, admin_client):
        """Admin users should access admin endpoints."""
        response = admin_client.get("/admin/stats")
        
        assert response.status_code == status.HTTP_200_OK
    
    def test_user_role_denied_admin_endpoint(self, authenticated_client):
        """Non-admin users should be denied admin endpoints."""
        response = authenticated_client.get("/admin/stats")
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_different_roles_different_access(self, api_client, create_token):
        """Different roles should have different access levels."""
        # User role
        user_token = create_token(user_id="user1", role="user")
        user_headers = {"Authorization": f"Bearer {user_token}"}
        user_response = api_client.get("/admin/stats", headers=user_headers)
        assert user_response.status_code == status.HTTP_403_FORBIDDEN
        
        # Admin role
        admin_token = create_token(user_id="admin1", role="admin")
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        admin_response = api_client.get("/admin/stats", headers=admin_headers)
        assert admin_response.status_code == status.HTTP_200_OK


class TestEventLogging:
    """Test suite for event logging on auth failures."""
    
    def test_logs_missing_token_event(self, api_client, mock_send_event):
        """Should log missing_token event."""
        api_client.get("/me")
        
        mock_send_event.assert_called_once()
        call_kwargs = mock_send_event.call_args[1]
        assert call_kwargs["event"] == "missing_token"
    
    def test_logs_invalid_token_event(self, api_client, mock_send_event):
        """Should log invalid_token event."""
        invalid_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.invalid"
        headers = {"Authorization": f"Bearer {invalid_token}"}
        api_client.get("/me", headers=headers)
        
        mock_send_event.assert_called_once()
        call_kwargs = mock_send_event.call_args[1]
        assert call_kwargs["event"] == "invalid_token"
    
    def test_logs_invalid_token_claims_event(self, api_client, mock_send_event, rsa_keys):
        """Should log invalid_token_claims event."""
        from jose import jwt
        from datetime import datetime, timezone, timedelta
        
        payload = {
            "sub": "test",
            # Missing 'role' claim
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        }
        token = jwt.encode(payload, rsa_keys["private"], algorithm="RS256")
        headers = {"Authorization": f"Bearer {token}"}
        api_client.get("/me", headers=headers)
        
        mock_send_event.assert_called_once()
        call_kwargs = mock_send_event.call_args[1]
        assert call_kwargs["event"] == "invalid_token_claims"
