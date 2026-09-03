"""
Configuration settings for HawkEye SOC backend.
"""

import os


class Settings:
    """
    Centralized application configuration.
    Values can later be overridden via environment variables.
    """

    # General
    APP_NAME: str = "HawkEye SOC"
    ENV: str = os.getenv("ENV", "development")

    # CORS
    FRONTEND_ORIGIN: str = os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")

    # Correlation & Pipeline
    CORRELATION_WINDOW_MINUTES: int = int(os.getenv("CORRELATION_WINDOW_MINUTES", "30"))

    # Machine Learning
    MODEL_PATH: str = os.getenv(
        "MODEL_PATH",
        os.path.join(os.path.dirname(__file__), "ml", "root_cause_model.pkl"),
    )
    SKLEARN_VERSION: str = "1.5.2"

    # Data
    # Path to the CSV dataset used for alert/incident data (loaded by services layer).
    ALERTS_CSV_PATH: str = os.getenv(
        "ALERTS_CSV_PATH",
        os.path.join(os.path.dirname(__file__), "data", "alerts.csv"),
    )
    INCIDENTS_CSV_PATH: str = os.getenv(
        "INCIDENTS_CSV_PATH",
        os.path.join(os.path.dirname(__file__), "data", "incidents.csv"),
    )


settings = Settings()
