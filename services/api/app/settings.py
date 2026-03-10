from pydantic_settings import BaseSettings, SettingsConfigDict
from .keys import fetch_public_key_from_jwks


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    JWT_ALG: str = "RS256"
    AUTH_SERVICE_URL: str = "http://auth:8001"
    JWKS_URL: str = "http://auth:8001/.well-known/jwks.json"

    LOG_SERVICE_URL: str = "http://log:8003"

    # Public key PEM (fetched from auth-service JWKS endpoint)
    _public_key_pem: str | None = None

    def __init__(self, **data):
        super().__init__(**data)
        # Fetch public key from JWKS endpoint
        if not self._public_key_pem:
            public_key_pem = fetch_public_key_from_jwks(self.JWKS_URL)
            if public_key_pem:
                self._public_key_pem = public_key_pem
            else:
                # Fallback: try to continue without it, will fail at JWT verification
                pass

    @property
    def public_key_pem(self) -> str | None:
        """Get the public key PEM."""
        if not self._public_key_pem:
            public_key_pem = fetch_public_key_from_jwks(self.JWKS_URL)
            if public_key_pem:
                self._public_key_pem = public_key_pem
        return self._public_key_pem


settings = Settings()
