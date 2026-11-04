"""
Configuration module for CyberThreat AI System.
Loads settings from environment variables with sensible defaults.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root
PROJECT_ROOT = Path(__file__).parent.parent
load_dotenv(PROJECT_ROOT / ".env")


class Config:
    """Application configuration loaded from environment."""

    # Paths & Writable Data Locations
    PROJECT_ROOT = PROJECT_ROOT
    
    # Resolves appropriate writable data directory across dev and packaged Windows environments
    _custom_data_dir = os.getenv("CYBERTHREAT_DATA_DIR")
    if _custom_data_dir:
        DATA_DIR = Path(_custom_data_dir)
    elif os.getenv("ENVIRONMENT") == "production" and os.getenv("LOCALAPPDATA"):
        DATA_DIR = Path(os.getenv("LOCALAPPDATA")) / "CyberThreatAI" / "data"
    else:
        DATA_DIR = PROJECT_ROOT / "data"
        
    DB_PATH = DATA_DIR / "cyberthreat.db"
    DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DB_PATH}")

    # Server
    SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
    SERVER_PORT = int(os.getenv("SERVER_PORT", "8000"))
    SERVER_URL = os.getenv("SERVER_URL", "http://127.0.0.1:8000")
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

    # Correlation & Incidents
    CORRELATION_TIME_WINDOW = int(os.getenv("CORRELATION_TIME_WINDOW", "600"))  # seconds
    INCIDENT_RISK_THRESHOLD = float(os.getenv("INCIDENT_RISK_THRESHOLD", "30"))

    # Sync
    SYNC_INTERVAL = int(os.getenv("SYNC_INTERVAL", "30"))  # seconds
    SYNC_RETRY_MAX = int(os.getenv("SYNC_RETRY_MAX", "3"))

    # Risk thresholds: [monitor, increase_monitoring, reauth, restrict]
    _thresholds = os.getenv("RISK_THRESHOLDS", "30,60,80,100")
    RISK_THRESHOLDS = [int(t) for t in _thresholds.split(",")]

    # LLM
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "local")
    LLM_API_KEY = os.getenv("LLM_API_KEY", "")

    # Frontend
    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")

    # CORS Configuration
    _cors_env = os.getenv("CORS_ORIGINS")
    if _cors_env:
        CORS_ORIGINS = [origin.strip() for origin in _cors_env.split(",") if origin.strip()]
    elif ENVIRONMENT == "production":
        CORS_ORIGINS = ["*"]
    else:
        CORS_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000", "*"]

    @classmethod
    def ensure_data_dir(cls):
        """Create data directory if it doesn't exist."""
        cls.DATA_DIR.mkdir(parents=True, exist_ok=True)


config = Config()

DATABASE_PATH = str(config.DB_PATH)
SERVER_HOST = config.SERVER_HOST
SERVER_PORT = config.SERVER_PORT
SERVER_URL = config.SERVER_URL
CORS_ORIGINS = config.CORS_ORIGINS
CORRELATION_TIME_WINDOW = config.CORRELATION_TIME_WINDOW
INCIDENT_RISK_THRESHOLD = config.INCIDENT_RISK_THRESHOLD
ISOLATION_FOREST_CONTAMINATION = 0.1
ISOLATION_FOREST_ESTIMATORS = 100
