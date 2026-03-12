"""Pytest configuration and fixtures for API service tests."""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
from fastapi.testclient import TestClient
from jose import jwt

# Import after fixtures are set up to avoid loading production settings
def utcnow():
    """Return current UTC time."""
    return datetime.now(timezone.utc)


@pytest.fixture
def rsa_keys():
    """Generate RSA keypair for testing."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    
    return {
        "private": private_pem,
        "public": public_pem,
        "private_key": private_key,
        "public_key_obj": public_key,
    }


@pytest.fixture
def test_settings(rsa_keys):
    """Create test settings with mocked JWKS endpoint."""
    from app.settings import Settings
    
    settings_obj = Settings(
        JWT_ALG="RS256",
        AUTH_SERVICE_URL="http://localhost:8001",
        JWKS_URL="http://localhost:8001/.well-known/jwks.json",
        LOG_SERVICE_URL="http://localhost:8003",
    )
    # Bypass pydantic's private attr handling by setting directly
    object.__setattr__(settings_obj, '_public_key_pem', rsa_keys["public"])
    return settings_obj


@pytest.fixture
def create_token(rsa_keys):
    """Factory fixture to create valid JWT tokens."""
    def _create_token(user_id: str = "test-user-1", role: str = "user", exp_delta: int = 3600):
        payload = {
            "sub": user_id,
            "role": role,
            "iat": int(utcnow().timestamp()),
            "exp": int((utcnow() + timedelta(seconds=exp_delta)).timestamp()),
        }
        token = jwt.encode(
            payload,
            rsa_keys["private"],
            algorithm="RS256",
        )
        return token
    return _create_token


@pytest.fixture
def api_client(test_settings, rsa_keys):
    """Create FastAPI test client with properly injected dependencies."""
    # Patch settings in the correct namespaces BEFORE importing app
    from app import settings as settings_module
    from app import auth as auth_module
    
    # Replace settings in all modules that import it
    settings_module.settings = test_settings
    auth_module.settings = test_settings
    
    # Start patches and keep them active during test
    # Patch where functions are USED, not where they're DEFINED
    fetch_patcher = patch("app.keys.fetch_public_key_from_jwks")
    send_patcher = patch("app.auth.send_event")  # auth.py imports send_event directly
    
    mock_fetch = fetch_patcher.start()
    mock_fetch.return_value = rsa_keys["public"]
    
    mock_send = send_patcher.start()
    
    try:
        # Import app after all patches are in place
        from app.main import app
        
        client = TestClient(app)
        client._mock_send_event = mock_send
        yield client
    finally:
        fetch_patcher.stop()
        send_patcher.stop()


@pytest.fixture
def mock_send_event(api_client):
    """Return the mocked send_event from the api_client."""
    return api_client._mock_send_event


@pytest.fixture
def mock_fetch_public_key(rsa_keys):
    """Mock the fetch_public_key_from_jwks function globally."""
    def mock_fn(*args, **kwargs):
        return rsa_keys["public"]
    return mock_fn


@pytest.fixture
def authenticated_client(api_client, create_token):
    """Create a test client with authentication headers."""
    token = create_token(user_id="test-user", role="user")
    
    class AuthenticatedClient:
        def __init__(self, client, token):
            self.client = client
            self.token = token
            self.headers = {"Authorization": f"Bearer {token}"}
        
        def get(self, *args, **kwargs):
            if "headers" not in kwargs:
                kwargs["headers"] = {}
            kwargs["headers"].update(self.headers)
            return self.client.get(*args, **kwargs)
        
        def post(self, *args, **kwargs):
            if "headers" not in kwargs:
                kwargs["headers"] = {}
            kwargs["headers"].update(self.headers)
            return self.client.post(*args, **kwargs)
    
    return AuthenticatedClient(api_client, token)


@pytest.fixture
def admin_client(api_client, create_token):
    """Create a test client with admin authentication."""
    token = create_token(user_id="admin-user", role="admin")
    
    class AuthenticatedClient:
        def __init__(self, client, token):
            self.client = client
            self.token = token
            self.headers = {"Authorization": f"Bearer {token}"}
        
        def get(self, *args, **kwargs):
            if "headers" not in kwargs:
                kwargs["headers"] = {}
            kwargs["headers"].update(self.headers)
            return self.client.get(*args, **kwargs)
        
        def post(self, *args, **kwargs):
            if "headers" not in kwargs:
                kwargs["headers"] = {}
            kwargs["headers"].update(self.headers)
            return self.client.post(*args, **kwargs)
    
    return AuthenticatedClient(api_client, token)
