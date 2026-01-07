"""Application bootstrap helpers for the Qt-based VPN desktop UI."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

from PySide6.QtWidgets import QApplication

from utils.config_loader import Config
from utils.logger import setup_logger
from vpn_server.access_control import AccessControl
from vpn_server.server import VPNServer

from .main_window import MainWindow
from .services import LogService, ServerService, UserService


DEFAULT_CONFIG = "config/vpn_config.json"
DEFAULT_DB = "config/access_control.db"


def _ensure_parent_dir(path: Optional[str]) -> None:
    if not path:
        return
    directory = Path(path).expanduser().resolve().parent
    directory.mkdir(parents=True, exist_ok=True)


def _create_access_control(config_data: dict) -> AccessControl:
    security_config = config_data.get("security", {})
    db_path = security_config.get("access_control_db", DEFAULT_DB)
    jwt_secret = security_config.get("jwt_secret")
    token_expiry = security_config.get("token_expiry", 3600)

    _ensure_parent_dir(db_path)

    return AccessControl(
        db_path=db_path,
        jwt_secret=jwt_secret,
        token_expiry=token_expiry,
    )


def build_services(config_path: str, log_level: Optional[str] = None):
    config = Config(config_path)
    config_data = config.to_dict()

    logging_config = config_data.get("logging", {})
    resolved_log_level = log_level or logging_config.get("level", "INFO")
    log_file = logging_config.get("file")

    setup_logger(
        name="vpn_ui",
        level=resolved_log_level,
        log_file=log_file,
        max_bytes=logging_config.get("max_size_mb", 10) * 1024 * 1024,
        backup_count=logging_config.get("backup_count", 5),
    )

    server = VPNServer(config_data)
    access_control = _create_access_control(config_data)
    log_service = LogService(log_file)
    server_service = ServerService(server)
    user_service = UserService(access_control)

    return server_service, user_service, log_service


def run_ui(config_path: str = DEFAULT_CONFIG, log_level: Optional[str] = None) -> int:
    app = QApplication.instance() or QApplication(sys.argv)

    server_service, user_service, log_service = build_services(config_path, log_level)

    window = MainWindow(server_service, user_service, log_service)
    window.show()

    exit_code = app.exec()

    try:
        server_service.stop_server()
    finally:
        access_control = user_service._access  # type: ignore[attr-defined]
        try:
            getattr(access_control, "conn", None) and access_control.conn.close()
        except Exception:
            pass

    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="VPN Desktop Management UI")
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG,
        help="Path to the VPN configuration file",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        help="Override log level for the UI (defaults to config value)",
    )
    args = parser.parse_args(argv)

    return run_ui(config_path=args.config, log_level=args.log_level)


if __name__ == "__main__":
    sys.exit(main())
