"""Qt dialogs used in the VPN desktop manager."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
)

from .services import UserRecord


class UserDialog(QDialog):
    """Dialog for creating or editing a VPN user account."""

    def __init__(self, parent=None, user: Optional[UserRecord] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit User" if user else "Add User")
        self._user = user

        self.username_edit = QLineEdit(self)
        self.password_edit = QLineEdit(self)
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.confirm_edit = QLineEdit(self)
        self.confirm_edit.setEchoMode(QLineEdit.Password)
        self.active_checkbox = QCheckBox("Active", self)
        self.admin_checkbox = QCheckBox("Administrator", self)

        form = QFormLayout()

        self.username_edit.setText(user.username if user else "")
        if user:
            self.username_edit.setEnabled(False)
        form.addRow("Username", self.username_edit)

        form.addRow("Password", self.password_edit)
        form.addRow("Confirm", self.confirm_edit)

        self.active_checkbox.setChecked(user.is_active if user else True)
        self.admin_checkbox.setChecked(user.is_admin if user else False)
        form.addRow("Status", self.active_checkbox)
        form.addRow("Role", self.admin_checkbox)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        button_box.accepted.connect(self._on_accept)
        button_box.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.addLayout(form)
        layout.addWidget(button_box)
        self.setLayout(layout)

    def _on_accept(self) -> None:
        if not self.username_edit.text().strip():
            QMessageBox.warning(self, "Validation", "Username is required.")
            return

        password = self.password_edit.text()
        confirm = self.confirm_edit.text()

        # On edit, password can be left blank to keep unchanged
        if self._user is None or password or confirm:
            if len(password) < 4:
                QMessageBox.warning(self, "Validation", "Password must be at least 4 characters.")
                return
            if password != confirm:
                QMessageBox.warning(self, "Validation", "Passwords do not match.")
                return

        self.accept()

    def get_payload(self) -> dict:
        password = self.password_edit.text()
        if not password:
            password = None
        return {
            "username": self.username_edit.text().strip(),
            "password": password,
            "is_active": self.active_checkbox.isChecked(),
            "is_admin": self.admin_checkbox.isChecked(),
        }


__all__ = ["UserDialog"]
