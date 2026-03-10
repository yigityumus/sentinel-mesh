from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str = "postgresql+psycopg://sentinel:sentinelpass@postgres:5432/sentinel"

    # Detection Rule: Brute Force Login
    BRUTE_FORCE_THRESHOLD: int = 5
    BRUTE_FORCE_WINDOW_SECONDS: int = 120

    # Detection Rule: Invalid Token Burst
    TOKEN_BURST_THRESHOLD: int = 10
    TOKEN_BURST_WINDOW_SECONDS: int = 120

    # Detection Rule: Admin Probing
    ADMIN_PROBING_THRESHOLD: int = 5
    ADMIN_PROBING_WINDOW_SECONDS: int = 120


settings = Settings()
