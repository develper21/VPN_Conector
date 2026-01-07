"""Service layer bridging core VPN components with the Qt UI."""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from PySide6.QtCore import QObject, Signal, QTimer

from vpn_server.server import VPNServer
from vpn_server.access_control import AccessControl, User


@dataclass
class UserRecord:
    """Lightweight data transfer object representing a VPN user."""

    username: str
    is_active: bool
    is_admin: bool
    created_at: float
    last_login: Optional[float]
    metadata: Dict[str, Any]

    @classmethod
    def from_user(cls, user: User) -> "UserRecord":
        return cls(
            username=user.username,
            is_active=user.is_active,
            is_admin=user.is_admin,
            created_at=user.created_at,
            last_login=user.last_login,
            metadata=dict(user.metadata or {}),
        )


class ServerService(QObject):
    """Encapsulates lifecycle management and telemetry for the VPN server."""

    status_changed = Signal(dict)
    tunnels_changed = Signal(list)

    def __init__(
        self,
        server: VPNServer,
        poll_interval_ms: int = 2000,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self._logger = logging.getLogger(__name__ + ".ServerService")
        self._server = server
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(poll_interval_ms)
        self._poll_timer.timeout.connect(self.refresh_status)

    def start_polling(self) -> None:
        if not self._poll_timer.isActive():
            self._poll_timer.start()
            self.refresh_status()

    def stop_polling(self) -> None:
        if self._poll_timer.isActive():
            self._poll_timer.stop()

    def start_server(self) -> None:
        if getattr(self._server, "_running", False):
            self._logger.info("Server already running")
            return

        def _runner() -> None:
            try:
                self._server.start()
            except Exception:  # pragma: no cover - surfaced in UI
                self._logger.exception("Failed to start VPN server")
            finally:
                self.refresh_status()

        threading.Thread(target=_runner, daemon=True).start()

    def stop_server(self) -> None:
        if not getattr(self._server, "_running", False):
            return
        try:
            self._server.stop()
        finally:
            self.refresh_status()

    def refresh_status(self) -> None:
        status = {
            "running": getattr(self._server, "_running", False),
            "host": getattr(self._server, "host", "-"),
            "port": getattr(self._server, "port", "-"),
            "protocol": getattr(self._server, "protocol", "-"),
            "clients": len(getattr(self._server, "_sessions", {})),
        }
        self.status_changed.emit(status)

        tunnel_manager = getattr(self._server, "tunnel_manager", None)
        if tunnel_manager:
            tunnels = tunnel_manager.list_tunnels()
            self.tunnels_changed.emit(tunnels)
        else:
            self.tunnels_changed.emit([])


class UserService(QObject):
    """Provides user management helpers backed by AccessControl."""

    users_changed = Signal(list)

    def __init__(
        self,
        access_control: AccessControl,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self._logger = logging.getLogger(__name__ + ".UserService")
        self._access = access_control

    def list_users(self) -> List[UserRecord]:
        users = [UserRecord.from_user(user) for user in self._access.list_users(limit=1000)]
        self.users_changed.emit([user.__dict__ for user in users])
        return users

    def create_user(
        self,
        username: str,
        password: Optional[str] = None,
        is_active: bool = True,
        is_admin: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> tuple[bool, str]:
        success, _user, message = self._access.create_user(
            username=username,
            password=password,
            is_active=is_active,
            is_admin=is_admin,
            metadata=metadata,
        )
        if success:
            self.list_users()
        else:
            self._logger.warning("User creation failed for %s: %s", username, message)
        return success, message

    def update_user(
        self,
        username: str,
        password: Optional[str] = None,
        is_active: Optional[bool] = None,
        is_admin: Optional[bool] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> tuple[bool, str]:
        success, _user, message = self._access.update_user(
            username=username,
            password=password,
            is_active=is_active,
            is_admin=is_admin,
            metadata=metadata,
        )
        if success:
            self.list_users()
        else:
            self._logger.warning("User update failed for %s: %s", username, message)
        return success, message

    def delete_user(self, username: str) -> tuple[bool, str]:
        success, message = self._access.delete_user(username)
        if success:
            self.list_users()
        else:
            self._logger.warning("User deletion failed for %s: %s", username, message)
        return success, message


class LogService(QObject):
    """Simple helper to read the rotating VPN log file."""

    logs_updated = Signal(str)

    def __init__(
        self,
        log_path: Optional[str],
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self._logger = logging.getLogger(__name__ + ".LogService")
        self._log_path = Path(log_path) if log_path else None
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(5000)
        self._poll_timer.timeout.connect(self.emit_latest)

    def start_polling(self) -> None:
        if self._poll_timer.isActive():
            return
        self._poll_timer.start()
        self.emit_latest()

    def stop_polling(self) -> None:
        if self._poll_timer.isActive():
            self._poll_timer.stop()

    def emit_latest(self, max_lines: int = 200) -> None:
        content = self.read_recent(max_lines=max_lines)
        self.logs_updated.emit(content)

    def read_recent(self, max_lines: int = 200) -> str:
        if not self._log_path:
            return "Log file not configured."

        if not self._log_path.exists():
            return f"Log file not found at {self._log_path}"

        try:
            with self._log_path.open("r", encoding="utf-8") as handle:
                lines = handle.readlines()
        except OSError as exc:
            self._logger.error("Unable to read log file: %s", exc)
            return f"Failed to read log file: {exc}"

        if max_lines:
            lines = lines[-max_lines:]
        return "".join(lines)


__all__ = [
    "ServerService",
    "UserService",
    "LogService",
    "UserRecord",
]
