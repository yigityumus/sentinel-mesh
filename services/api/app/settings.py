from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    JWT_SECRET: str = "dev-change-me"
    JWT_ALG: str = "HS256"

    LOG_SERVICE_URL: str = "http://log:8003"


settings = Settings()
