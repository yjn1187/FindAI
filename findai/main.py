from __future__ import annotations

import uvicorn

from .config import Settings
from .logging_config import configure_logging


def main() -> None:
    settings = Settings.from_env()
    configure_logging(settings)
    uvicorn.run(
        "findai.app:create_app",
        host=settings.host,
        port=settings.port,
        reload=False,
        factory=True,
        log_config=None,
        access_log=True,
    )


if __name__ == "__main__":
    main()
