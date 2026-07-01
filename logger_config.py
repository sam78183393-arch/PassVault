"""
SecureVault - Logging Configuration
-----------------------------------
This module configures logging for the SecureVault application.
Logs are written to logs/securevault.log and include:
- Application start
- User actions
- Errors
- Warnings
"""

import logging
from pathlib import Path

LOG_FILE = Path("logs/securevault.log")


def setup_logger() -> logging.Logger:
    """
    Configure and return a logger instance.

    Returns:
        logging.Logger: Configured logger.
    """
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("SecureVault")
    logger.setLevel(logging.DEBUG)

    # Prevent duplicate handlers if setup_logger is called multiple times
    if not logger.handlers:
        file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
        console_handler = logging.StreamHandler()

        formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )

        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger


if __name__ == "__main__":
    # Example usage
    logger = setup_logger()
    logger.info("Application started")
    logger.warning("This is a warning example")
    logger.error("This is an error example")
