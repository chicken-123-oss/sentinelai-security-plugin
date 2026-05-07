from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 8787
    db_path: Path = Path("data/sentinelai.sqlite3")
    data_dir: Path = Path("data")
    admin_email: str = "admin@example.com"
    admin_password: str = "sentinelai"
    admin_token: str = "dev-owner-token"
    auditor_token: str = "dev-auditor-token"
    ingest_token: str = "dev-ingest-token"
    allow_system_actions: bool = False
    allowed_origins: tuple[str, ...] = ()
    frame_ancestors: str = "'self'"

    @classmethod
    def from_env(
        cls,
        host: str | None = None,
        port: int | None = None,
        db_path: str | Path | None = None,
        data_dir: str | Path | None = None,
    ) -> "Settings":
        configured_data_dir = Path(data_dir or os.getenv("SENTINELAI_DATA_DIR", "data"))
        configured_db_path = Path(db_path or os.getenv("SENTINELAI_DB_PATH", configured_data_dir / "sentinelai.sqlite3"))
        return cls(
            host=host or os.getenv("SENTINELAI_HOST", "127.0.0.1"),
            port=int(port or os.getenv("SENTINELAI_PORT", "8787")),
            db_path=configured_db_path,
            data_dir=configured_data_dir,
            admin_email=os.getenv("SENTINELAI_ADMIN_EMAIL", "admin@example.com"),
            admin_password=os.getenv("SENTINELAI_ADMIN_PASSWORD", "sentinelai"),
            admin_token=os.getenv("SENTINELAI_ADMIN_TOKEN", "dev-owner-token"),
            auditor_token=os.getenv("SENTINELAI_AUDITOR_TOKEN", "dev-auditor-token"),
            ingest_token=os.getenv("SENTINELAI_INGEST_TOKEN", "dev-ingest-token"),
            allow_system_actions=os.getenv("SENTINELAI_ENABLE_SYSTEM_ACTIONS", "").lower() in {"1", "true", "yes"},
            allowed_origins=_split_csv(os.getenv("SENTINELAI_ALLOWED_ORIGINS", "")),
            frame_ancestors=os.getenv("SENTINELAI_FRAME_ANCESTORS", "'self'"),
        )


def _split_csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())
