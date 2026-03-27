"""
app/core/config.py

Application configuration loaded from environment variables.
No credentials are hardcoded — all sensitive values must be set in a .env file.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # MikroTik REST API
    mikrotik_host: str = "192.168.88.1"
    mikrotik_port: int = 443
    mikrotik_user: str = "admin"
    mikrotik_password: str = ""
    mikrotik_verify_ssl: bool = False  # Set to True in production with valid cert

    # OpenAI
    openai_api_key: str
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str | None = None

    # Application behaviour
    dry_run: bool = False  # When True, no real commands are sent to the router
    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def mikrotik_base_url(self) -> str:
        scheme = "https" if self.mikrotik_port == 443 else "http"
        return f"{scheme}://{self.mikrotik_host}:{self.mikrotik_port}/rest"


# Singleton — import this throughout the app
settings = Settings()
