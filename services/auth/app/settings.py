from pydantic_settings import BaseSettings, SettingsConfigDict
from .keys import get_or_generate_keys


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # RS256 with RSA keypair
    JWT_ALG: str = "RS256"
    ACCESS_TOKEN_TTL_MIN: int = 15

    DATABASE_URL: str = "sqlite:////data/auth.db"

    LOG_SERVICE_URL: str = "http://log:8003"

    # RSA keys (loaded/generated at startup)
    _private_key_pem: str | None = None
    _public_key_pem: str | None = None

    def __init__(self, **data):
        super().__init__(**data)
        # Load or generate keys on first instantiation
        if not self._private_key_pem:
            private_pem, public_pem = get_or_generate_keys()
            self._private_key_pem = private_pem
            self._public_key_pem = public_pem

    @property
    def private_key_pem(self) -> str:
        """Get the private key PEM."""
        if not self._private_key_pem:
            private_pem, public_pem = get_or_generate_keys()
            self._private_key_pem = private_pem
            self._public_key_pem = public_pem
        return self._private_key_pem

    @property
    def public_key_pem(self) -> str:
        """Get the public key PEM."""
        if not self._public_key_pem:
            private_pem, public_pem = get_or_generate_keys()
            self._private_key_pem = private_pem
            self._public_key_pem = public_pem
        return self._public_key_pem


settings = Settings()
