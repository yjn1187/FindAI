from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .config import Settings


def configure_logging(settings: Settings) -> Path:
    """Configure console and real-time rotating file logging for FindAI/Uvicorn."""

    log_path = settings.log_path.expanduser().resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d %(levelname)-8s %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    root.setLevel(level)

    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(formatter)

    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=settings.log_max_bytes,
        backupCount=settings.log_backup_count,
        encoding="utf-8",
        delay=False,
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    root.addHandler(console)
    root.addHandler(file_handler)

    # Uvicorn normally installs its own handlers. main.py disables that default
    # configuration so access and server logs use the same rotating file.
    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(logger_name)
        logger.handlers.clear()
        logger.setLevel(level)
        logger.propagate = True

    logging.captureWarnings(True)
    logging.getLogger(__name__).info(
        "Logging initialized path=%s level=%s max_bytes=%d backups=%d",
        log_path,
        logging.getLevelName(level),
        settings.log_max_bytes,
        settings.log_backup_count,
    )
    return log_path

