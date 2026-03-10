"""
Public key management for JWT verification.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import httpx
from typing import Optional


def load_public_key(pem: str):
    """Load a public key from PEM string."""
    return serialization.load_pem_public_key(
        pem.encode("utf-8"),
        backend=default_backend(),
    )


def fetch_public_key_from_jwks(jwks_url: str, kid: str = "sentinel-auth-key-1") -> Optional[str]:
    """
    Fetch public key from JWKS endpoint.
    Returns PEM-encoded public key string.
    """
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(jwks_url)
            resp.raise_for_status()
            jwks = resp.json()
            
            # Find the key with matching kid
            for key in jwks.get("keys", []):
                if key.get("kid") == kid:
                    # Reconstruct public key from JWKS components
                    import base64
                    
                    def base64url_to_int(s: str) -> int:
                        """Convert base64url string to integer."""
                        # Add padding
                        padding = (4 - len(s) % 4) % 4
                        s_padded = s + '=' * padding
                        b = base64.urlsafe_b64decode(s_padded)
                        return int.from_bytes(b, byteorder='big')
                    
                    n = base64url_to_int(key["n"])
                    e = base64url_to_int(key["e"])
                    
                    # Reconstruct RSA public key
                    from cryptography.hazmat.primitives.asymmetric import rsa
                    public_numbers = rsa.RSAPublicNumbers(e, n)
                    public_key = public_numbers.public_key(default_backend())
                    
                    # Export to PEM
                    public_pem = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    ).decode("utf-8")
                    
                    return public_pem
            
            return None
    except Exception:
        return None
