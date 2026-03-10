"""
RSA key management for JWT signing/verification.
"""

import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def generate_rsa_keypair() -> tuple[str, str]:
    """
    Generate a new RSA 2048-bit keypair.
    Returns (private_key_pem, public_key_pem)
    """
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

    return private_pem, public_pem


def load_private_key(pem: str):
    """Load a private key from PEM string."""
    return serialization.load_pem_private_key(
        pem.encode("utf-8"),
        password=None,
        backend=default_backend(),
    )


def load_public_key(pem: str):
    """Load a public key from PEM string."""
    return serialization.load_pem_public_key(
        pem.encode("utf-8"),
        backend=default_backend(),
    )


def get_or_generate_keys(private_key_env_var: str = "AUTH_PRIVATE_KEY") -> tuple[str, str]:
    """
    Get keys from environment or generate them.
    Returns (private_key_pem, public_key_pem)
    """
    private_pem = os.environ.get(private_key_env_var)

    if private_pem:
        # Load existing key
        private_key = load_private_key(private_pem)
        public_key = private_key.public_key()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        return private_pem, public_pem
    else:
        # Generate new keys
        return generate_rsa_keypair()
