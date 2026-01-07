"""Qt main window for the VPN desktop management application."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .dialogs import UserDialog
from .services import LogService, ServerService, UserRecord, UserService
from .widgets import UserTable


class DashboardPage(QWidget):
    """Displays VPN server run-state and active tunnels."""

    def __init__(self, server_service: ServerService, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._service = server_service

        # Status summary
        self.status_label = QLabel("Server status: Unknown", self)
        self.status_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        self.start_button = QPushButton("Start Server", self)
        self.stop_button = QPushButton("Stop Server", self)
        self.refresh_button = QPushButton("Refresh", self)

        button_bar = QHBoxLayout()
        button_bar.addWidget(self.start_button)
        button_bar.addWidget(self.stop_button)
        button_bar.addWidget(self.refresh_button)
        button_bar.addStretch()

        # Tunnels list
        tunnels_group = QGroupBox("Active Tunnels", self)
        tunnels_layout = QVBoxLayout()
        self.tunnel_list = QListWidget(self)
        tunnels_layout.addWidget(self.tunnel_list)
        tunnels_group.setLayout(tunnels_layout)

        layout = QVBoxLayout()
        layout.addWidget(self.status_label)
        layout.addLayout(button_bar)
        layout.addWidget(tunnels_group)
        layout.addStretch()
        self.setLayout(layout)

        # Wiring
        self.start_button.clicked.connect(self._service.start_server)
        self.stop_button.clicked.connect(self._service.stop_server)
        self.refresh_button.clicked.connect(self._service.refresh_status)

        self._service.status_changed.connect(self._on_status_changed)
        self._service.tunnels_changed.connect(self._on_tunnels_changed)

    @Slot(dict)
    def _on_status_changed(self, status: dict) -> None:
        running = status.get("running")
        label = "Running" if running else "Stopped"
        host = status.get("host", "-")
        port = status.get("port", "-")
        protocol = status.get("protocol", "-")
        clients = status.get("clients", 0)

        self.status_label.setText(
            f"Server status: <b>{label}</b> — {host}:{port} ({protocol.upper() if isinstance(protocol, str) else protocol}) — Clients: {clients}"
        )

        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(bool(running))

    @Slot(list)
    def _on_tunnels_changed(self, tunnels: list) -> None:
        self.tunnel_list.clear()
        if not tunnels:
            self.tunnel_list.addItem("No active tunnels")
            return

        for tunnel in tunnels:
            item = QListWidgetItem(
                f"{tunnel['client_id']} — {tunnel['virtual_ip']} ⇔ {tunnel['public_ip']}:{tunnel['public_port']} — Last: {tunnel['last_active']}"
            )
            self.tunnel_list.addItem(item)


class UsersPage(QWidget):
    """User management surface backed by AccessControl."""

    def __init__(self, user_service: UserService, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._service = user_service

        self.table = UserTable(self)

        self.add_button = QPushButton("Add", self)
        self.edit_button = QPushButton("Edit", self)
        self.delete_button = QPushButton("Delete", self)
        self.refresh_button = QPushButton("Refresh", self)

        button_bar = QHBoxLayout()
        button_bar.addWidget(self.add_button)
        button_bar.addWidget(self.edit_button)
        button_bar.addWidget(self.delete_button)
        button_bar.addStretch()
        button_bar.addWidget(self.refresh_button)

        layout = QVBoxLayout()
        layout.addLayout(button_bar)
        layout.addWidget(self.table)
        self.setLayout(layout)

        self.add_button.clicked.connect(self._on_add_user)
        self.edit_button.clicked.connect(self._on_edit_user)
        self.delete_button.clicked.connect(self._on_delete_user)
        self.refresh_button.clicked.connect(self._service.list_users)

        self._service.users_changed.connect(self._on_users_changed)

    @Slot(list)
    def _on_users_changed(self, users: list) -> None:
        records = [UserRecord(**data) for data in users]
        self.table.update_users(records)

    def _selected_user(self) -> Optional[UserRecord]:
        return self.table.current_user()

    def _on_add_user(self) -> None:
        dialog = UserDialog(self)
        if dialog.exec() == QDialog.Accepted:
            payload = dialog.get_payload()
            success, message = self._service.create_user(**payload)
            if not success:
                QMessageBox.warning(self, "User Creation", message)

    def _on_edit_user(self) -> None:
        user = self._selected_user()
        if not user:
            QMessageBox.information(self, "Edit User", "Please select a user.")
            return
        dialog = UserDialog(self, user=user)
        if dialog.exec() == QDialog.Accepted:
            payload = dialog.get_payload()
            success, message = self._service.update_user(**payload)
            if not success:
                QMessageBox.warning(self, "User Update", message)

    def _on_delete_user(self) -> None:
        user = self._selected_user()
        if not user:
            QMessageBox.information(self, "Delete User", "Please select a user.")
            return

        confirm = QMessageBox.question(
            self,
            "Delete User",
            f"Are you sure you want to delete '{user.username}'?",
        )
        if confirm == QMessageBox.Yes:
            success, message = self._service.delete_user(user.username)
            if not success:
                QMessageBox.warning(self, "User Deletion", message)


class LogsPage(QWidget):
    """Read-only log viewer."""

    def __init__(self, log_service: LogService, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._service = log_service

        self.refresh_button = QPushButton("Refresh", self)
        self.log_view = QTextEdit(self)
        self.log_view.setReadOnly(True)
        self.log_view.setLineWrapMode(QTextEdit.NoWrap)

        layout = QVBoxLayout()
        layout.addWidget(self.refresh_button)
        layout.addWidget(self.log_view)
        self.setLayout(layout)

        self.refresh_button.clicked.connect(self._service.emit_latest)
        self._service.logs_updated.connect(self._on_logs_updated)

    @Slot(str)
    def _on_logs_updated(self, text: str) -> None:
        self.log_view.setPlainText(text)
        self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())


class MainWindow(QMainWindow):
    """Primary window wiring together all pages and services."""

    def __init__(
        self,
        server_service: ServerService,
        user_service: UserService,
        log_service: LogService,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._server_service = server_service
        self._user_service = user_service
        self._log_service = log_service

        self.setWindowTitle("VPN Desktop Manager")
        self.resize(1024, 640)

        self.tabs = QTabWidget(self)
        self.dashboard_page = DashboardPage(server_service, self)
        self.users_page = UsersPage(user_service, self)
        self.logs_page = LogsPage(log_service, self)

        self.tabs.addTab(self.dashboard_page, "Dashboard")
        self.tabs.addTab(self.users_page, "Users")
        self.tabs.addTab(self.logs_page, "Logs")

        central = QWidget(self)
        layout = QGridLayout()
        layout.addWidget(self.tabs, 0, 0)
        central.setLayout(layout)
        self.setCentralWidget(central)

    def showEvent(self, event) -> None:  # noqa: D401,N802
        super().showEvent(event)
        self._server_service.start_polling()
        self._user_service.list_users()
        self._log_service.start_polling()

    def closeEvent(self, event) -> None:  # noqa: D401,N802
        self._server_service.stop_polling()
        self._log_service.stop_polling()
        super().closeEvent(event)


__all__ = ["MainWindow", "DashboardPage", "UsersPage", "LogsPage"]
