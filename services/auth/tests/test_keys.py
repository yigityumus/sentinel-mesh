"""Tests for RSA key management."""

import pytest
from cryptography.hazmat.primitives import serialization

from app.keys import (
    generate_rsa_keypair,
    load_private_key,
    load_public_key,
    get_or_generate_keys,
)


class TestRSAKeyGeneration:
    """Test RSA keypair generation."""

    def test_generate_rsa_keypair_returns_tuple(self):
        """generate_rsa_keypair should return a tuple of two strings."""
        result = generate_rsa_keypair()
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_generate_rsa_keypair_returns_strings(self):
        """Keypair should be strings."""
        private_pem, public_pem = generate_rsa_keypair()
        assert isinstance(private_pem, str)
        assert isinstance(public_pem, str)

    def test_generated_private_key_has_pem_format(self):
        """Generated private key should be in PEM format."""
        private_pem, _ = generate_rsa_keypair()
        assert private_pem.startswith("-----BEGIN PRIVATE KEY-----")
        assert private_pem.endswith("-----END PRIVATE KEY-----\n")

    def test_generated_public_key_has_pem_format(self):
        """Generated public key should be in PEM format."""
        _, public_pem = generate_rsa_keypair()
        assert public_pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert public_pem.endswith("-----END PUBLIC KEY-----\n")

    def test_generated_keys_are_different(self):
        """Each generated keypair should be different."""
        private1, public1 = generate_rsa_keypair()
        private2, public2 = generate_rsa_keypair()
        assert private1 != private2
        assert public1 != public2

    def test_generated_key_pair_length(self):
        """Generated RSA keys should be 2048 bits."""
        private_pem, public_pem = generate_rsa_keypair()

        private_key = load_private_key(private_pem)
        public_key = load_public_key(public_pem)

        assert private_key.key_size == 2048
        assert public_key.key_size == 2048

    def test_generated_public_key_matches_private_key(self):
        """Public key derived from private key should be correct."""
        private_pem, generated_public_pem = generate_rsa_keypair()

        private_key = load_private_key(private_pem)
        derived_public_key = private_key.public_key()

        derived_public_pem = derived_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        # Both should load the same key
        pub1 = load_public_key(generated_public_pem)
        pub2 = load_public_key(derived_public_pem)

        pub1_numbers = pub1.public_numbers()
        pub2_numbers = pub2.public_numbers()

        assert pub1_numbers.n == pub2_numbers.n
        assert pub1_numbers.e == pub2_numbers.e


class TestKeyLoading:
    """Test loading keys from PEM format."""

    def test_load_private_key_returns_private_key_object(self):
        """load_private_key should return a private key object."""
        private_pem, _ = generate_rsa_keypair()
        private_key = load_private_key(private_pem)

        assert private_key is not None
        assert private_key.key_size == 2048

    def test_load_public_key_returns_public_key_object(self):
        """load_public_key should return a public key object."""
        _, public_pem = generate_rsa_keypair()
        public_key = load_public_key(public_pem)

        assert public_key is not None
        assert public_key.key_size == 2048

    def test_load_private_key_invalid_format_raises_error(self):
        """Loading invalid private key format should raise error."""
        with pytest.raises(Exception):
            load_private_key("invalid key")

    def test_load_public_key_invalid_format_raises_error(self):
        """Loading invalid public key format should raise error."""
        with pytest.raises(Exception):
            load_public_key("invalid key")

    def test_load_private_key_with_wrong_format_raises_error(self):
        """Loading public key as private key should raise error."""
        _, public_pem = generate_rsa_keypair()
        with pytest.raises(Exception):
            load_private_key(public_pem)

    def test_load_public_key_from_private_key_fails(self):
        """Loading private key as public key should raise error."""
        private_pem, _ = generate_rsa_keypair()
        with pytest.raises(Exception):
            load_public_key(private_pem)

    def test_load_multiple_times_same_key(self):
        """Loading the same key multiple times should work."""
        private_pem, public_pem = generate_rsa_keypair()

        private1 = load_private_key(private_pem)
        private2 = load_private_key(private_pem)
        public1 = load_public_key(public_pem)
        public2 = load_public_key(public_pem)

        # All should be valid key objects
        assert private1.key_size == 2048
        assert private2.key_size == 2048
        assert public1.key_size == 2048
        assert public2.key_size == 2048


class TestGetOrGenerateKeys:
    """Test get_or_generate_keys function."""

    def test_get_or_generate_keys_returns_tuple(self):
        """Function should return tuple of strings."""
        result = get_or_generate_keys()
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], str)
        assert isinstance(result[1], str)

    def test_get_or_generate_keys_no_env_generates_keys(self, monkeypatch):
        """Without env var, should generate new keys."""
        monkeypatch.delenv("AUTH_PRIVATE_KEY", raising=False)

        private_pem, public_pem = get_or_generate_keys()

        assert private_pem.startswith("-----BEGIN PRIVATE KEY-----")
        assert public_pem.startswith("-----BEGIN PUBLIC KEY-----")

    def test_get_or_generate_keys_with_env_uses_env(self, monkeypatch):
        """With env var set, should use that key."""
        private_pem_orig, public_pem_orig = generate_rsa_keypair()
        monkeypatch.setenv("AUTH_PRIVATE_KEY", private_pem_orig)

        private_pem, public_pem = get_or_generate_keys()

        assert private_pem == private_pem_orig
        assert public_pem == public_pem_orig

    def test_get_or_generate_keys_custom_env_var(self, monkeypatch):
        """Should use custom env var name."""
        private_pem_orig, public_pem_orig = generate_rsa_keypair()
        monkeypatch.setenv("CUSTOM_KEY_VAR", private_pem_orig)

        private_pem, public_pem = get_or_generate_keys(private_key_env_var="CUSTOM_KEY_VAR")

        assert private_pem == private_pem_orig
        assert public_pem == public_pem_orig

    def test_get_or_generate_keys_custom_env_var_not_set(self, monkeypatch):
        """Should generate keys if custom env var not set."""
        monkeypatch.delenv("CUSTOM_KEY_VAR", raising=False)

        private_pem, public_pem = get_or_generate_keys(private_key_env_var="CUSTOM_KEY_VAR")

        assert private_pem.startswith("-----BEGIN PRIVATE KEY-----")
        assert public_pem.startswith("-----BEGIN PUBLIC KEY-----")

    def test_get_or_generate_keys_returns_valid_keypair(self):
        """Returned keys should be valid and match."""
        private_pem, public_pem = get_or_generate_keys()

        private_key = load_private_key(private_pem)
        public_key_loaded = load_public_key(public_pem)

        # Derived public from private should match loaded public
        derived_public = private_key.public_key()
        derived_public_pem = derived_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        pub1_numbers = public_key_loaded.public_numbers()
        pub2_numbers = load_public_key(derived_public_pem).public_numbers()

        assert pub1_numbers.n == pub2_numbers.n
        assert pub1_numbers.e == pub2_numbers.e

    def test_get_or_generate_keys_consistency(self):
        """Multiple calls without env var should generate different keys."""
        private1, public1 = get_or_generate_keys()
        private2, public2 = get_or_generate_keys()

        # Should be different each time (no caching)
        assert private1 != private2
        assert public1 != public2


class TestKeyIntegration:
    """Integration tests for key operations."""

    def test_generate_load_roundtrip(self):
        """Generated keys should be loadable."""
        private_pem, public_pem = generate_rsa_keypair()

        private_key = load_private_key(private_pem)
        public_key = load_public_key(public_pem)

        # Should be valid 2048-bit RSA keys
        assert private_key.key_size == 2048
        assert public_key.key_size == 2048

        # Public key from private should match
        derived_public = private_key.public_key()
        assert derived_public.public_numbers().n == public_key.public_numbers().n

    def test_key_usage_for_signing(self):
        """Keys should be usable for signing."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        private_pem, _ = generate_rsa_keypair()
        private_key = load_private_key(private_pem)

        # Should be able to sign data
        data = b"test data"
        signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

        assert len(signature) > 0

    def test_key_usage_for_verification(self):
        """Keys should be usable for verification."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        private_pem, public_pem = generate_rsa_keypair()
        private_key = load_private_key(private_pem)
        public_key = load_public_key(public_pem)

        data = b"test data"
        signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

        # Should verify successfully
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
