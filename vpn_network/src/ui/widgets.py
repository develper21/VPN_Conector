"""Reusable Qt widgets for the VPN manager UI."""

from __future__ import annotations

from typing import List

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex
from PySide6.QtWidgets import QHeaderView, QTableView

from .services import UserRecord


class UserTableModel(QAbstractTableModel):
    HEADERS = ["Username", "Active", "Admin", "Created", "Last Login"]

    def __init__(self, users: List[UserRecord] | None = None, parent=None) -> None:
        super().__init__(parent)
        self._users: List[UserRecord] = users or []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._users)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.HEADERS)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):  # noqa: N802
        if not index.isValid() or not (0 <= index.row() < len(self._users)):
            return None

        user = self._users[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            if col == 0:
                return user.username
            if col == 1:
                return "Yes" if user.is_active else "No"
            if col == 2:
                return "Yes" if user.is_admin else "No"
            if col == 3:
                return _format_timestamp(user.created_at)
            if col == 4:
                return _format_timestamp(user.last_login)
        elif role == Qt.TextAlignmentRole:
            if col == 0:
                return Qt.AlignLeft | Qt.AlignVCenter
            return Qt.AlignCenter
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):  # noqa: N802
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            if 0 <= section < len(self.HEADERS):
                return self.HEADERS[section]
        else:
            return section + 1
        return None

    def update(self, users: List[UserRecord]) -> None:
        self.beginResetModel()
        self._users = users
        self.endResetModel()

    def user_at(self, row: int) -> UserRecord | None:
        if 0 <= row < len(self._users):
            return self._users[row]
        return None


class UserTable(QTableView):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableView.SelectRows)
        self.setSelectionMode(QTableView.SingleSelection)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.verticalHeader().setVisible(False)
        self.setSortingEnabled(False)
        self.setModel(UserTableModel())

    def update_users(self, users: List[UserRecord]) -> None:
        model: UserTableModel = self.model()  # type: ignore[assignment]
        model.update(users)

    def current_user(self) -> UserRecord | None:
        index = self.currentIndex()
        if index.isValid():
            model: UserTableModel = self.model()  # type: ignore[assignment]
            return model.user_at(index.row())
        return None


def _format_timestamp(timestamp: float | None) -> str:
    if not timestamp:
        return "—"
    from datetime import datetime

    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


__all__ = ["UserTable", "UserTableModel"]
