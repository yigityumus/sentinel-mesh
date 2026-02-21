from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # v1: HS256 (simple). Later you can switch to RSA/EdDSA + JWKS.
    JWT_SECRET: str = "dev-change-me"
    JWT_ALG: str = "HS256"
    ACCESS_TOKEN_TTL_MIN: int = 15

    DATABASE_URL: str = "sqlite:////data/auth.db"

    LOG_SERVICE_URL: str = "http://log:8003"


settings = Settings()
