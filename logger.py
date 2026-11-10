"""Logging setup: console + rotating file handler."""
import logging
from pathlib import Path

from config import CONFIG


def setup_logger(name: str = "sqli_detector") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:  # avoid duplicate handlers on repeated calls
        return logger

    logger.setLevel(CONFIG.log_level)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    CONFIG.log_file.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(CONFIG.log_file, encoding="utf-8")
    file_handler.setFormatter(fmt)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger
