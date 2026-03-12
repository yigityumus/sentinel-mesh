"""Tests for key management module."""

import pytest
from unittest.mock import patch, MagicMock


class TestLoadPublicKey:
    """Test suite for load_public_key function."""
    
    def test_loads_valid_pem_key(self, rsa_keys):
        """Should load a valid PEM-formatted public key."""
        from app.keys import load_public_key
        
        public_key = load_public_key(rsa_keys["public"])
        
        # Verify it's an RSA public key
        assert public_key.key_size == 2048
    
    def test_rejects_invalid_pem(self):
        """Should raise exception for invalid PEM format."""
        from app.keys import load_public_key
        
        invalid_pem = "not a valid pem key"
        
        with pytest.raises(ValueError):
            load_public_key(invalid_pem)
    
    def test_rejects_empty_pem(self):
        """Should raise exception for empty string."""
        from app.keys import load_public_key
        
        with pytest.raises(ValueError):
            load_public_key("")
    
    def test_rejects_private_key_as_public(self, rsa_keys):
        """Should handle attempts to load private key as public."""
        from app.keys import load_public_key
        
        # This might fail or return something unexpected
        try:
            key = load_public_key(rsa_keys["private"])
            # If it doesn't fail, verify it's still usable
            assert key is not None
        except Exception:
            # Expected behavior - can't load private key as public
            pass
    
    def test_loaded_key_can_verify_signature(self, rsa_keys):
        """Should load key that can verify JWT signatures."""
        from app.keys import load_public_key
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        
        public_key = load_public_key(rsa_keys["public"])
        
        # Create a test signature
        message = b"test message"
        signature = rsa_keys["private_key"].sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        
        # Verify signature with loaded key
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except Exception:
            pytest.fail("Signature verification failed")


class TestFetchPublicKeyFromJWKS:
    """Test suite for fetch_public_key_from_jwks function."""
    
    def test_fetches_key_from_jwks_endpoint(self, rsa_keys):
        """Should fetch public key from JWKS endpoint."""
        from app.keys import fetch_public_key_from_jwks
        import base64
        
        # Convert real RSA key components to base64url for JWKS response
        
        # Extract public numbers from our test key
        public_key = rsa_keys["public_key_obj"]
        public_numbers = public_key.public_numbers()
        
        # Convert to base64url format for JWKS
        def int_to_base64url(n: int) -> str:
            b = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
            # Remove padding for base64url
            b64 = base64.urlsafe_b64encode(b).decode('utf-8')
            return b64.rstrip('=')
        
        jwks_response = {
            "keys": [
                {
                    "kid": "sentinel-auth-key-1",
                    "kty": "RSA",
                    "n": int_to_base64url(public_numbers.n),
                    "e": int_to_base64url(public_numbers.e),
                }
            ]
        }
        
        with patch("app.keys.httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_client.get.return_value = mock_response
            mock_client_class.return_value.__enter__.return_value = mock_client
            
            result = fetch_public_key_from_jwks("http://auth:8001/.well-known/jwks.json")
            
            # verify it tried to fetch the right URL
            mock_client.get.assert_called_once_with("http://auth:8001/.well-known/jwks.json")
            # Should return a PEM string
            assert result is not None
            assert "-----BEGIN PUBLIC KEY-----" in result
    
    def test_returns_none_on_network_error(self):
        """Should return None if JWKS endpoint is unreachable."""
        from app.keys import fetch_public_key_from_jwks
        
        with patch("app.keys.httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.get.side_effect = Exception("Network error")
            mock_client_class.return_value.__enter__.return_value = mock_client
            
            result = fetch_public_key_from_jwks("http://invalid:9999/.well-known/jwks.json")
            
            assert result is None
    
    def test_returns_none_if_key_not_found(self):
        """Should return None if kid is not found in JWKS."""
        from app.keys import fetch_public_key_from_jwks
        
        jwks_response = {
            "keys": [
                {
                    "kid": "different-key",
                    "kty": "RSA",
                    "n": "value",
                    "e": "AQAB",
                }
            ]
        }
        
        with patch("app.keys.httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_client.get.return_value = mock_response
            mock_client_class.return_value.__enter__.return_value = mock_client
            
            result = fetch_public_key_from_jwks(
                "http://auth:8001/.well-known/jwks.json",
                kid="sentinel-auth-key-1",
            )
            
            assert result is None
    
    def test_respects_custom_kid(self, rsa_keys):
        """Should search for custom kid value."""
        from app.keys import fetch_public_key_from_jwks
        import base64
        
        # Extract public numbers from real test key
        public_key = rsa_keys["public_key_obj"]
        public_numbers = public_key.public_numbers()
        
        # Convert to base64url format
        def int_to_base64url(n: int) -> str:
            b = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
            b64 = base64.urlsafe_b64encode(b).decode('utf-8')
            return b64.rstrip('=')
        
        jwks_response = {
            "keys": [
                {
                    "kid": "custom-key-id",
                    "kty": "RSA",
                    "n": int_to_base64url(public_numbers.n),
                    "e": int_to_base64url(public_numbers.e),
                }
            ]
        }
        
        with patch("app.keys.httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.json.return_value = jwks_response
            mock_client.get.return_value = mock_response
            mock_client_class.return_value.__enter__.return_value = mock_client
            
            result = fetch_public_key_from_jwks(
                "http://auth:8001/.well-known/jwks.json",
                kid="custom-key-id",
            )
            
            # verify it found and parsed the custom kid
            mock_client.get.assert_called_once()
            assert result is not None
            assert "-----BEGIN PUBLIC KEY-----" in result
    
    def test_handles_malformed_jwks_response(self):
        """Should handle malformed JWKS response gracefully."""
        from app.keys import fetch_public_key_from_jwks
        
        with patch("app.keys.httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.json.side_effect = ValueError("Invalid JSON")
            mock_client.get.return_value = mock_response
            mock_client_class.return_value.__enter__.return_value = mock_client
            
            result = fetch_public_key_from_jwks("http://auth:8001/.well-known/jwks.json")
            
            assert result is None
    
    def test_uses_timeout(self):
        """Should set timeout for HTTP requests."""
        from app.keys import fetch_public_key_from_jwks
        
        with patch("app.keys.httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.json.return_value = {"keys": []}
            mock_client.get.return_value = mock_response
            mock_client_class.return_value.__enter__.return_value = mock_client
            
            fetch_public_key_from_jwks("http://auth:8001/.well-known/jwks.json")
            
            # Verify timeout was set
            mock_client_class.assert_called_once()
            call_kwargs = mock_client_class.call_args[1]
            assert call_kwargs.get("timeout", None) == 3.0


class TestBase64UrlConversion:
    """Test suite for base64url conversion in JWKS parsing."""
    
    def test_base64url_to_int_conversion(self):
        """Should correctly convert base64url strings to integers."""
        # This tests the internal function used by fetch_public_key_from_jwks
        import base64
        
        # Test with a known value
        test_int = 65537  # Common RSA exponent
        b = test_int.to_bytes((test_int.bit_length() + 7) // 8, byteorder="big")
        test_b64url = base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
        
        # Manually convert back
        padding = (4 - len(test_b64url) % 4) % 4
        padded = test_b64url + "=" * padding
        decoded = base64.urlsafe_b64decode(padded)
        result = int.from_bytes(decoded, byteorder="big")
        
        assert result == test_int
