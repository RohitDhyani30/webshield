"""
Central configuration for WebShield.
Loaded from environment variables (see .env.example).
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    APP_ENV: str = os.getenv("APP_ENV", "development")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./webshield.db")

    MAX_PAGES: int = int(os.getenv("MAX_PAGES", 50))
    MAX_DEPTH: int = int(os.getenv("MAX_DEPTH", 3))
    REQUEST_DELAY_SECONDS: float = float(os.getenv("REQUEST_DELAY_SECONDS", 0.5))
    REQUEST_TIMEOUT_SECONDS: int = int(os.getenv("REQUEST_TIMEOUT_SECONDS", 10))
    USER_AGENT: str = os.getenv("USER_AGENT", "WebShield-DAST-Scanner/1.0")

    REQUIRE_CONSENT: bool = os.getenv("REQUIRE_CONSENT", "true").lower() == "true"

    # Risk scoring weights (severity -> numeric weight)
    SEVERITY_WEIGHTS = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 1,
    }


settings = Settings()
