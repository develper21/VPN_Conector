#!/usr/bin/env python3
"""
Enhanced UI Features for VPN Application
Modern interface components with server location map, speed graphs, and one-click selection.
Uses PySide6 for cross-platform desktop GUI with advanced visualization.
"""
import json
import logging
import math
import sys
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from pathlib import Path

try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QLabel, QFrame, QScrollArea, QTabWidget,
        QGridLayout, QComboBox, QSlider, QProgressBar,
        QSplitter, QGroupBox, QTextEdit, QSpinBox,
        QCheckBox, QStatusBar, QMenuBar, QToolBar,
        QAction, QMessageBox, QDialog, QDialogButtonBox
    )
    from PySide6.QtCore import (
        Qt, QTimer, QThread, Signal, QPointF, QRectF,
        QSize, pyqtSignal, QPropertyAnimation, QEasingCurve
    )
    from PySide6.QtGui import (
        QPainter, QColor, QPen, QBrush, QFont, QPalette,
        QPixmap, QIcon, QLinearGradient, QRadialGradient,
        QMouseEvent, QWheelEvent, QPaintEvent
    )
    from PySide6.QtCharts import (
        QChart, QChartView, QLineSeries, QValueAxis,
        QAreaSeries, QScatterSeries, QSplineSeries
    )
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

from utils.logger import setup_logger


@dataclass
class ServerInfo:
    """Server information for UI display."""
    id: str
    name: str
    country: str
    city: str
    latitude: float
    longitude: float
    load: float  # 0-100
    ping: float  # milliseconds
    speed: float  # Mbps
    protocol: str  # openvpn, wireguard, etc.
    is_favorite: bool = False
    is_premium: bool = False


@dataclass
class ConnectionStats:
    """Connection statistics for visualization."""
    timestamp: float
    download_speed: float
    upload_speed: float
    ping: float
    connected: bool


class ServerMapWidget(QWidget):
    """Interactive world map widget for server selection."""
    
    server_selected = Signal(str)  # Server ID
    server_hovered = Signal(str)   # Server ID
    
    def __init__(self):
        super().__init__()
        self.logger = setup_logger("server_map", "INFO")
        
        # Map properties
        self.servers: Dict[str, ServerInfo] = {}
        self.selected_server: Optional[str] = None
        self.hovered_server: Optional[str] = None
        self.zoom_level = 1.0
        self.pan_offset = QPointF(0, 0)
        self.is_panning = False
        self.last_mouse_pos = QPointF()
        
        # Map dimensions
        self.map_width = 800
        self.map_height = 400
        
        # Colors
        self.bg_color = QColor(20, 30, 48)
        self.land_color = QColor(46, 64, 83)
        self.water_color = QColor(30, 45, 68)
        self.server_colors = {
            'optimal': QColor(76, 175, 80),    # Green
            'good': QColor(33, 150, 243),     # Blue
            'moderate': QColor(255, 193, 7),   # Yellow
            'poor': QColor(244, 67, 54)       # Red
        }
        
        self.setMinimumSize(600, 300)
        self.setMouseTracking(True)
        self.setFocusPolicy(Qt.StrongFocus)
    
    def add_server(self, server: ServerInfo) -> None:
        """Add a server to the map."""
        self.servers[server.id] = server
        self.update()
    
    def remove_server(self, server_id: str) -> None:
        """Remove a server from the map."""
        if server_id in self.servers:
            del self.servers[server_id]
            self.update()
    
    def select_server(self, server_id: str) -> None:
        """Select a server on the map."""
        self.selected_server = server_id
        self.server_selected.emit(server_id)
        self.update()
    
    def get_server_at_pos(self, pos: QPointF) -> Optional[str]:
        """Get server ID at mouse position."""
        for server_id, server in self.servers.items():
            server_pos = self._lat_lon_to_pos(server.latitude, server.longitude)
            distance = math.sqrt((pos.x() - server_pos.x())**2 + (pos.y() - server_pos.y())**2)
            
            if distance < 15:  # 15 pixel radius
                return server_id
        return None
    
    def _lat_lon_to_pos(self, lat: float, lon: float) -> QPointF:
        """Convert latitude/longitude to map position."""
        # Simple equirectangular projection
        x = (lon + 180) * (self.map_width / 360)
        y = (90 - lat) * (self.map_height / 180)
        
        # Apply zoom and pan
        x = x * self.zoom_level + self.pan_offset.x()
        y = y * self.zoom_level + self.pan_offset.y()
        
        return QPointF(x, y)
    
    def paintEvent(self, event: QPaintEvent) -> None:
        """Paint the map and servers."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw background
        painter.fillRect(self.rect(), self.bg_color)
        
        # Draw water
        painter.fillRect(self.rect(), self.water_color)
        
        # Draw simplified continents (would use actual map data in production)
        self._draw_continents(painter)
        
        # Draw servers
        self._draw_servers(painter)
        
        # Draw connection lines
        if self.selected_server:
            self._draw_connection_line(painter)
    
    def _draw_continents(self, painter: QPainter) -> None:
        """Draw simplified continent shapes."""
        painter.setBrush(QBrush(self.land_color))
        painter.setPen(QPen(Qt.NoPen))
        
        # Simplified continent rectangles (would use real map data)
        continents = [
            # North America
            QRectF(150 * self.zoom_level + self.pan_offset.x(), 
                   100 * self.zoom_level + self.pan_offset.y(),
                   200 * self.zoom_level, 150 * self.zoom_level),
            # Europe
            QRectF(400 * self.zoom_level + self.pan_offset.x(),
                   80 * self.zoom_level + self.pan_offset.y(),
                   100 * self.zoom_level, 80 * self.zoom_level),
            # Asia
            QRectF(500 * self.zoom_level + self.pan_offset.x(),
                   100 * self.zoom_level + self.pan_offset.y(),
                   200 * self.zoom_level, 150 * self.zoom_level),
        ]
        
        for continent in continents:
            painter.drawRoundedRect(continent, 10, 10)
    
    def _draw_servers(self, painter: QPainter) -> None:
        """Draw server markers on the map."""
        for server_id, server in self.servers.items():
            pos = self._lat_lon_to_pos(server.latitude, server.longitude)
            
            # Determine color based on performance
            if server.load < 30 and server.ping < 100:
                color = self.server_colors['optimal']
            elif server.load < 60 and server.ping < 200:
                color = self.server_colors['good']
            elif server.load < 80:
                color = self.server_colors['moderate']
            else:
                color = self.server_colors['poor']
            
            # Draw server marker
            if server_id == self.selected_server:
                # Selected server - larger circle
                painter.setBrush(QBrush(color))
                painter.setPen(QPen(Qt.white, 2))
                painter.drawEllipse(pos, 12, 12)
                
                # Draw selection ring
                painter.setPen(QPen(Qt.white, 1, Qt.DashLine))
                painter.drawEllipse(pos, 18, 18)
            elif server_id == self.hovered_server:
                # Hovered server - medium circle
                painter.setBrush(QBrush(color))
                painter.setPen(QPen(Qt.white, 2))
                painter.drawEllipse(pos, 10, 10)
            else:
                # Normal server - small circle
                painter.setBrush(QBrush(color))
                painter.setPen(QPen(Qt.white, 1))
                painter.drawEllipse(pos, 8, 8)
            
            # Draw server name
            painter.setPen(QPen(Qt.white))
            painter.setFont(QFont("Arial", 8))
            text_rect = QRectF(pos.x() - 30, pos.y() + 15, 60, 20)
            painter.drawText(text_rect, Qt.AlignCenter, server.city)
    
    def _draw_connection_line(self, painter: QPainter) -> None:
        """Draw line to selected server."""
        if self.selected_server and self.selected_server in self.servers:
            server = self.servers[self.selected_server]
            server_pos = self._lat_lon_to_pos(server.latitude, server.longitude)
            
            # Draw connection line from center to server
            center = QPointF(self.width() / 2, self.height() / 2)
            
            # Animated gradient line
            gradient = QLinearGradient(center, server_pos)
            gradient.setColorAt(0, QColor(76, 175, 80, 100))
            gradient.setColorAt(1, QColor(76, 175, 80, 50))
            
            painter.setPen(QPen(QBrush(gradient), 3, Qt.SolidLine))
            painter.drawLine(center, server_pos)
    
    def mousePressEvent(self, event: QMouseEvent) -> None:
        """Handle mouse press events."""
        if event.button() == Qt.LeftButton:
            server_id = self.get_server_at_pos(event.position())
            if server_id:
                self.select_server(server_id)
            else:
                self.is_panning = True
                self.last_mouse_pos = event.position()
        
        super().mousePressEvent(event)
    
    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        """Handle mouse move events."""
        if self.is_panning:
            # Pan the map
            delta = event.position() - self.last_mouse_pos
            self.pan_offset += delta
            self.last_mouse_pos = event.position()
            self.update()
        else:
            # Check for server hover
            server_id = self.get_server_at_pos(event.position())
            if server_id != self.hovered_server:
                self.hovered_server = server_id
                if server_id:
                    self.server_hovered.emit(server_id)
                self.update()
        
        super().mouseMoveEvent(event)
    
    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        """Handle mouse release events."""
        if event.button() == Qt.LeftButton:
            self.is_panning = False
        
        super().mouseReleaseEvent(event)
    
    def wheelEvent(self, event: QWheelEvent) -> None:
        """Handle mouse wheel for zooming."""
        delta = event.angleDelta().y()
        if delta > 0:
            self.zoom_level = min(3.0, self.zoom_level * 1.1)
        else:
            self.zoom_level = max(0.5, self.zoom_level / 1.1)
        
        self.update()
        super().wheelEvent(event)


class SpeedGraphWidget(QWidget):
    """Real-time speed graph widget."""
    
    def __init__(self):
        super().__init__()
        self.logger = setup_logger("speed_graph", "INFO")
        
        # Data storage
        self.download_data: List[Tuple[float, float]] = []  # (timestamp, speed)
        self.upload_data: List[Tuple[float, float]] = []
        self.max_data_points = 100
        
        # Graph properties
        self.max_speed = 100  # Mbps
        self.time_window = 60  # seconds
        self.update_interval = 1000  # milliseconds
        
        # Colors
        self.bg_color = QColor(20, 30, 48)
        self.grid_color = QColor(46, 64, 83)
        self.download_color = QColor(76, 175, 80)
        self.upload_color = QColor(33, 150, 243)
        self.text_color = QColor(255, 255, 255)
        
        # Update timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_graph)
        self.timer.start(self.update_interval)
        
        self.setMinimumSize(400, 200)
    
    def add_speed_data(self, download_speed: float, upload_speed: float) -> None:
        """Add new speed data point."""
        current_time = time.time()
        
        self.download_data.append((current_time, download_speed))
        self.upload_data.append((current_time, upload_speed))
        
        # Remove old data
        cutoff_time = current_time - self.time_window
        self.download_data = [(t, s) for t, s in self.download_data if t > cutoff_time]
        self.upload_data = [(t, s) for t, s in self.upload_data if t > cutoff_time]
        
        # Update max speed
        all_speeds = [s for _, s in self.download_data + self.upload_data]
        if all_speeds:
            self.max_speed = max(all_speeds) * 1.2
        
        self.update()
    
    def update_graph(self) -> None:
        """Update the graph display."""
        self.update()
    
    def paintEvent(self, event: QPaintEvent) -> None:
        """Paint the speed graph."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw background
        painter.fillRect(self.rect(), self.bg_color)
        
        # Draw grid
        self._draw_grid(painter)
        
        # Draw speed lines
        self._draw_speed_lines(painter)
        
        # Draw labels
        self._draw_labels(painter)
    
    def _draw_grid(self, painter: QPainter) -> None:
        """Draw background grid."""
        painter.setPen(QPen(self.grid_color, 1))
        
        # Horizontal lines
        for i in range(5):
            y = self.height() * (i + 1) / 6
            painter.drawLine(0, y, self.width(), y)
        
        # Vertical lines
        for i in range(6):
            x = self.width() * i / 6
            painter.drawLine(x, 0, x, self.height())
    
    def _draw_speed_lines(self, painter: QPainter) -> None:
        """Draw download and upload speed lines."""
        if not self.download_data and not self.upload_data:
            return
        
        # Draw download line
        if len(self.download_data) > 1:
            painter.setPen(QPen(self.download_color, 2))
            self._draw_line(painter, self.download_data)
        
        # Draw upload line
        if len(self.upload_data) > 1:
            painter.setPen(QPen(self.upload_color, 2))
            self._draw_line(painter, self.upload_data)
    
    def _draw_line(self, painter: QPainter, data: List[Tuple[float, float]]) -> None:
        """Draw a line graph from data points."""
        if len(data) < 2:
            return
        
        current_time = time.time()
        time_range = self.time_window
        
        points = []
        for timestamp, speed in data:
            x = self.width() * (1 - (current_time - timestamp) / time_range)
            y = self.height() - (speed / self.max_speed) * self.height() * 0.9
            points.append(QPointF(x, y))
        
        # Draw the line
        for i in range(len(points) - 1):
            painter.drawLine(points[i], points[i + 1])
    
    def _draw_labels(self, painter: QPainter) -> None:
        """Draw axis labels."""
        painter.setPen(QPen(self.text_color))
        painter.setFont(QFont("Arial", 8))
        
        # Y-axis labels (speed)
        for i in range(6):
            speed = self.max_speed * (5 - i) / 5
            y = self.height() * (i + 1) / 6
            painter.drawText(5, y + 3, f"{speed:.0f} Mbps")
        
        # X-axis labels (time)
        current_time = time.time()
        for i in range(6):
            time_offset = self.time_window * (5 - i) / 5
            x = self.width() * i / 6
            time_str = f"{time_offset:.0f}s"
            painter.drawText(x - 15, self.height() - 5, time_str)


class ServerListWidget(QWidget):
    """Server list with one-click selection and smart recommendations."""
    
    server_selected = Signal(str)
    server_favorited = Signal(str, bool)
    
    def __init__(self):
        super().__init__()
        self.logger = setup_logger("server_list", "INFO")
        
        # Server data
        self.servers: List[ServerInfo] = []
        self.filtered_servers: List[ServerInfo] = []
        self.selected_server: Optional[str] = None
        
        # UI components
        self.setup_ui()
        
        # Colors
        self.bg_color = QColor(20, 30, 48)
        self.item_colors = {
            'optimal': QColor(76, 175, 80),
            'good': QColor(33, 150, 243),
            'moderate': QColor(255, 193, 7),
            'poor': QColor(244, 67, 54)
        }
    
    def setup_ui(self) -> None:
        """Setup the UI layout."""
        layout = QVBoxLayout(self)
        
        # Search and filter bar
        search_layout = QHBoxLayout()
        
        self.search_box = QComboBox()
        self.search_box.setEditable(True)
        self.search_box.setPlaceholderText("Search servers...")
        self.search_box.currentTextChanged.connect(self.filter_servers)
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Servers", "Optimal", "Favorites", "Recent"])
        self.filter_combo.currentTextChanged.connect(self.filter_servers)
        
        search_layout.addWidget(self.search_box)
        search_layout.addWidget(self.filter_combo)
        layout.addLayout(search_layout)
        
        # Server list (scroll area)
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        
        self.server_list_widget = QWidget()
        self.server_list_layout = QVBoxLayout(self.server_list_widget)
        self.server_list_layout.addStretch()
        
        self.scroll_area.setWidget(self.server_list_widget)
        layout.addWidget(self.scroll_area)
        
        # Quick connect buttons
        quick_layout = QHBoxLayout()
        
        self.quick_connect_btn = QPushButton("Quick Connect")
        self.quick_connect_btn.clicked.connect(self.quick_connect)
        self.quick_connect_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        
        self.optimal_server_btn = QPushButton("Optimal Server")
        self.optimal_server_btn.clicked.connect(self.connect_optimal)
        self.optimal_server_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        
        quick_layout.addWidget(self.quick_connect_btn)
        quick_layout.addWidget(self.optimal_server_btn)
        layout.addLayout(quick_layout)
    
    def add_server(self, server: ServerInfo) -> None:
        """Add a server to the list."""
        self.servers.append(server)
        self.filtered_servers = self.servers.copy()
        self.update_server_list()
    
    def remove_server(self, server_id: str) -> None:
        """Remove a server from the list."""
        self.servers = [s for s in self.servers if s.id != server_id]
        self.filter_servers()
    
    def filter_servers(self) -> None:
        """Filter servers based on search and filter criteria."""
        search_text = self.search_box.currentText().lower()
        filter_type = self.filter_combo.currentText()
        
        self.filtered_servers = []
        
        for server in self.servers:
            # Apply search filter
            if search_text and search_text not in server.name.lower() and \
               search_text not in server.country.lower() and \
               search_text not in server.city.lower():
                continue
            
            # Apply type filter
            if filter_type == "Optimal":
                if not (server.load < 30 and server.ping < 100):
                    continue
            elif filter_type == "Favorites":
                if not server.is_favorite:
                    continue
            elif filter_type == "Recent":
                # Would need recent connection tracking
                continue
            
            self.filtered_servers.append(server)
        
        self.update_server_list()
    
    def update_server_list(self) -> None:
        """Update the server list display."""
        # Clear existing items
        for i in reversed(range(self.server_list_layout.count() - 1)):
            item = self.server_list_layout.itemAt(i)
            if item and item.widget():
                item.widget().deleteLater()
        
        # Add server items
        for server in self.filtered_servers:
            server_widget = self.create_server_widget(server)
            self.server_list_layout.insertWidget(self.server_list_layout.count() - 1, server_widget)
    
    def create_server_widget(self, server: ServerInfo) -> QWidget:
        """Create a widget for a single server."""
        widget = QFrame()
        widget.setFrameStyle(QFrame.Box)
        widget.setStyleSheet("""
            QFrame {
                background-color: #2E4053;
                border: 1px solid #4A5568;
                border-radius: 5px;
                padding: 5px;
                margin: 2px;
            }
            QFrame:hover {
                background-color: #3A4A5C;
                border-color: #4CAF50;
            }
        """)
        
        layout = QHBoxLayout(widget)
        
        # Server info
        info_layout = QVBoxLayout()
        
        name_label = QLabel(f"{server.city}, {server.country}")
        name_label.setStyleSheet("font-weight: bold; color: white;")
        info_layout.addWidget(name_label)
        
        details_label = QLabel(f"Load: {server.load:.0f}% | Ping: {server.ping:.0f}ms | Speed: {server.speed:.0f}Mbps")
        details_label.setStyleSheet("color: #B0BEC5; font-size: 10px;")
        info_layout.addWidget(details_label)
        
        layout.addLayout(info_layout)
        layout.addStretch()
        
        # Performance indicator
        perf_color = self._get_performance_color(server)
        perf_indicator = QLabel()
        perf_indicator.setFixedSize(12, 12)
        perf_indicator.setStyleSheet(f"""
            QLabel {{
                background-color: {perf_color.name()};
                border-radius: 6px;
            }}
        """)
        layout.addWidget(perf_indicator)
        
        # Connect button
        connect_btn = QPushButton("Connect")
        connect_btn.clicked.connect(lambda: self.select_server(server.id))
        connect_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 5px 15px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        layout.addWidget(connect_btn)
        
        # Favorite button
        favorite_btn = QPushButton("★" if server.is_favorite else "☆")
        favorite_btn.clicked.connect(lambda: self.toggle_favorite(server.id))
        favorite_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #FFD700;
                border: none;
                font-size: 16px;
                padding: 5px;
            }
            QPushButton:hover {
                color: #FFA500;
            }
        """)
        layout.addWidget(favorite_btn)
        
        return widget
    
    def _get_performance_color(self, server: ServerInfo) -> QColor:
        """Get performance color for server."""
        if server.load < 30 and server.ping < 100:
            return self.item_colors['optimal']
        elif server.load < 60 and server.ping < 200:
            return self.item_colors['good']
        elif server.load < 80:
            return self.item_colors['moderate']
        else:
            return self.item_colors['poor']
    
    def select_server(self, server_id: str) -> None:
        """Select a server."""
        self.selected_server = server_id
        self.server_selected.emit(server_id)
    
    def toggle_favorite(self, server_id: str) -> None:
        """Toggle server favorite status."""
        for server in self.servers:
            if server.id == server_id:
                server.is_favorite = not server.is_favorite
                self.server_favorited.emit(server_id, server.is_favorite)
                self.update_server_list()
                break
    
    def quick_connect(self) -> None:
        """Connect to the best available server."""
        optimal_servers = [s for s in self.servers 
                         if s.load < 30 and s.ping < 100]
        
        if optimal_servers:
            # Sort by load and ping
            optimal_servers.sort(key=lambda s: (s.load, s.ping))
            self.select_server(optimal_servers[0].id)
        elif self.servers:
            # Fallback to best available
            self.servers.sort(key=lambda s: (s.load, s.ping))
            self.select_server(self.servers[0].id)
    
    def connect_optimal(self) -> None:
        """Connect to the optimal server based on current location."""
        # Would implement location-based optimal server selection
        self.quick_connect()


class EnhancedVPNGUI(QMainWindow):
    """Enhanced VPN GUI with all advanced features."""
    
    def __init__(self):
        super().__init__()
        self.logger = setup_logger("enhanced_ui", "INFO")
        
        if not GUI_AVAILABLE:
            self.logger.error("GUI libraries not available")
            sys.exit(1)
        
        # UI components
        self.server_map = None
        self.speed_graph = None
        self.server_list = None
        self.status_bar = None
        
        # Connection state
        self.is_connected = False
        self.current_server = None
        
        # Setup UI
        self.setup_ui()
        self.setup_menu()
        self.setup_status_bar()
        
        # Load sample data
        self.load_sample_servers()
        
        # Update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_status)
        self.update_timer.start(1000)  # Update every second
    
    def setup_ui(self) -> None:
        """Setup the main UI layout."""
        self.setWindowTitle("Enhanced VPN Client")
        self.setGeometry(100, 100, 1200, 800)
        
        # Set dark theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #141E30;
                color: white;
            }
            QWidget {
                background-color: #1E2A38;
                color: white;
            }
            QLabel {
                color: white;
            }
            QPushButton {
                background-color: #2E4053;
                color: white;
                border: 1px solid #4A5568;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #3A4A5C;
            }
        """)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        tab_widget = QTabWidget()
        
        # Server Map tab
        map_tab = QWidget()
        map_layout = QVBoxLayout(map_tab)
        
        self.server_map = ServerMapWidget()
        self.server_map.server_selected.connect(self.on_server_selected)
        map_layout.addWidget(self.server_map)
        
        tab_widget.addTab(map_tab, "Server Map")
        
        # Server List tab
        list_tab = QWidget()
        list_layout = QVBoxLayout(list_tab)
        
        self.server_list = ServerListWidget()
        self.server_list.server_selected.connect(self.on_server_selected)
        list_layout.addWidget(self.server_list)
        
        tab_widget.addTab(list_tab, "Server List")
        
        # Speed Graph tab
        speed_tab = QWidget()
        speed_layout = QVBoxLayout(speed_tab)
        
        self.speed_graph = SpeedGraphWidget()
        speed_layout.addWidget(self.speed_graph)
        
        # Speed statistics
        stats_widget = QGroupBox("Connection Statistics")
        stats_layout = QHBoxLayout(stats_widget)
        
        self.download_label = QLabel("Download: 0 Mbps")
        self.upload_label = QLabel("Upload: 0 Mbps")
        self.ping_label = QLabel("Ping: 0 ms")
        
        stats_layout.addWidget(self.download_label)
        stats_layout.addWidget(self.upload_label)
        stats_layout.addWidget(self.ping_label)
        
        speed_layout.addWidget(stats_widget)
        tab_widget.addTab(speed_tab, "Speed Monitor")
        
        main_layout.addWidget(tab_widget)
        
        # Connection controls
        control_layout = QHBoxLayout()
        
        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self.toggle_connection)
        self.connect_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #666666;
            }
        """)
        
        self.disconnect_btn = QPushButton("Disconnect")
        self.disconnect_btn.clicked.connect(self.disconnect_vpn)
        self.disconnect_btn.setEnabled(False)
        self.disconnect_btn.setStyleSheet("""
            QPushButton {
                background-color: #F44336;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #D32F2F;
            }
        """)
        
        control_layout.addStretch()
        control_layout.addWidget(self.connect_btn)
        control_layout.addWidget(self.disconnect_btn)
        
        main_layout.addLayout(control_layout)
    
    def setup_menu(self) -> None:
        """Setup the menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        settings_action = QAction("Settings", self)
        settings_action.triggered.connect(self.show_settings)
        file_menu.addAction(settings_action)
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # View menu
        view_menu = menubar.addMenu("View")
        
        refresh_action = QAction("Refresh Servers", self)
        refresh_action.triggered.connect(self.refresh_servers)
        view_menu.addAction(refresh_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        speed_test_action = QAction("Speed Test", self)
        speed_test_action.triggered.connect(self.run_speed_test)
        tools_menu.addAction(speed_test_action)
    
    def setup_status_bar(self) -> None:
        """Setup the status bar."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        self.status_label = QLabel("Disconnected")
        self.status_bar.addWidget(self.status_label)
        
        self.server_label = QLabel("No server selected")
        self.status_bar.addWidget(self.server_label)
    
    def load_sample_servers(self) -> None:
        """Load sample server data."""
        sample_servers = [
            ServerInfo("us_ny_1", "US New York 1", "United States", "New York", 40.7128, -74.0060, 25, 45, 85, "openvpn"),
            ServerInfo("us_la_1", "US Los Angeles 1", "United States", "Los Angeles", 34.0522, -118.2437, 35, 65, 92, "wireguard"),
            ServerInfo("uk_london_1", "UK London 1", "United Kingdom", "London", 51.5074, -0.1278, 45, 85, 78, "openvpn"),
            ServerInfo("de_frankfurt_1", "Germany Frankfurt 1", "Germany", "Frankfurt", 50.1109, 8.6821, 60, 120, 65, "wireguard"),
            ServerInfo("jp_tokyo_1", "Japan Tokyo 1", "Japan", "Tokyo", 35.6762, 139.6503, 70, 150, 45, "openvpn"),
            ServerInfo("au_sydney_1", "Australia Sydney 1", "Australia", "Sydney", -33.8688, 151.2093, 40, 180, 55, "wireguard"),
        ]
        
        for server in sample_servers:
            if self.server_map:
                self.server_map.add_server(server)
            if self.server_list:
                self.server_list.add_server(server)
    
    def on_server_selected(self, server_id: str) -> None:
        """Handle server selection."""
        self.current_server = server_id
        
        # Update UI
        if self.server_list:
            servers = self.server_list.servers
            server = next((s for s in servers if s.id == server_id), None)
            if server:
                self.server_label.setText(f"Selected: {server.city}, {server.country}")
    
    def toggle_connection(self) -> None:
        """Toggle VPN connection."""
        if not self.is_connected:
            self.connect_vpn()
        else:
            self.disconnect_vpn()
    
    def connect_vpn(self) -> None:
        """Connect to VPN."""
        if not self.current_server:
            QMessageBox.warning(self, "No Server Selected", "Please select a server first.")
            return
        
        self.is_connected = True
        self.connect_btn.setEnabled(False)
        self.disconnect_btn.setEnabled(True)
        self.status_label.setText("Connecting...")
        
        # Simulate connection
        QTimer.singleShot(2000, self.on_connected)
    
    def disconnect_vpn(self) -> None:
        """Disconnect from VPN."""
        self.is_connected = False
        self.connect_btn.setEnabled(True)
        self.disconnect_btn.setEnabled(False)
        self.status_label.setText("Disconnected")
        
        # Clear speed graph
        if self.speed_graph:
            self.speed_graph.download_data.clear()
            self.speed_graph.upload_data.clear()
    
    def on_connected(self) -> None:
        """Handle successful connection."""
        self.status_label.setText("Connected")
        
        # Start simulating speed data
        self.simulate_speed_data()
    
    def simulate_speed_data(self) -> None:
        """Simulate speed data for demonstration."""
        import random
        
        download = random.uniform(20, 80)
        upload = random.uniform(5, 30)
        
        if self.speed_graph:
            self.speed_graph.add_speed_data(download, upload)
        
        if self.download_label:
            self.download_label.setText(f"Download: {download:.1f} Mbps")
        if self.upload_label:
            self.upload_label.setText(f"Upload: {upload:.1f} Mbps")
        if self.ping_label:
            ping = random.uniform(30, 100)
            self.ping_label.setText(f"Ping: {ping:.0f} ms")
        
        # Continue simulation
        if self.is_connected:
            QTimer.singleShot(1000, self.simulate_speed_data)
    
    def update_status(self) -> None:
        """Update status display."""
        # Would update with real status from VPN backend
        pass
    
    def refresh_servers(self) -> None:
        """Refresh server list."""
        self.status_label.setText("Refreshing servers...")
        QTimer.singleShot(1000, lambda: self.status_label.setText("Servers refreshed"))
    
    def run_speed_test(self) -> None:
        """Run speed test."""
        QMessageBox.information(self, "Speed Test", "Speed test feature would be implemented here.")
    
    def show_settings(self) -> None:
        """Show settings dialog."""
        QMessageBox.information(self, "Settings", "Settings dialog would be implemented here.")


def main():
    """Main entry point for enhanced UI."""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Enhanced VPN Client")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("VPN Security Project")
    
    # Create and show main window
    window = EnhancedVPNGUI()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
