#!/usr/bin/env python3
"""
Advanced Connection Speed Graph Widget
Real-time speed visualization with multiple graph types, historical data, and performance analysis.
Features interactive graphs, statistical analysis, and detailed metrics display.
"""
import json
import logging
import math
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from pathlib import Path
from collections import deque

try:
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel,
        QPushButton, QFrame, QComboBox, QCheckBox,
        QGroupBox, QScrollArea, QGridLayout,
        QSpinBox, QSlider, QTabWidget
    )
    from PySide6.QtCore import (
        Qt, QTimer, QThread, Signal, QPointF, QRectF,
        QSize, pyqtSignal, QPropertyAnimation, QEasingCurve
    )
    from PySide6.QtGui import (
        QPainter, QColor, QPen, QBrush, QFont, QPalette,
        QPixmap, QIcon, QLinearGradient, QRadialGradient,
        QMouseEvent, QWheelEvent, QPaintEvent, QPolygonF
    )
    from PySide6.QtCharts import (
        QChart, QChartView, QLineSeries, QValueAxis,
        QAreaSeries, QScatterSeries, QSplineSeries,
        QBarSeries, QBarSet, QPieSeries, QPieSlice
    )
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

from utils.logger import setup_logger


@dataclass
class SpeedDataPoint:
    """Single speed data point."""
    timestamp: float
    download_speed: float  # Mbps
    upload_speed: float    # Mbps
    ping: float          # milliseconds
    packet_loss: float   # percentage
    jitter: float       # milliseconds
    connected: bool


@dataclass
class SpeedStatistics:
    """Statistical analysis of speed data."""
    avg_download: float
    avg_upload: float
    max_download: float
    max_upload: float
    min_download: float
    min_upload: float
    avg_ping: float
    max_ping: float
    min_ping: float
    total_data_downloaded: float  # MB
    total_data_uploaded: float    # MB
    connection_uptime: float     # seconds
    data_points: int


class AdvancedSpeedGraphWidget(QWidget):
    """Advanced speed graph with multiple visualization modes."""
    
    # Signals
    speed_alert = Signal(str, float)  # Alert type, value
    graph_mode_changed = Signal(str)   # New graph mode
    
    def __init__(self):
        super().__init__()
        self.logger = setup_logger("advanced_speed_graph", "INFO")
        
        # Data storage
        self.speed_data: deque = deque(maxlen=1000)  # Real-time data
        self.historical_data: List[SpeedDataPoint] = []  # Historical data
        self.daily_stats: Dict[str, SpeedStatistics] = {}  # Daily statistics
        
        # Graph properties
        self.graph_mode = "realtime"  # realtime, historical, comparison, statistics
        self.time_range = 300  # seconds (5 minutes for realtime)
        self.max_speed = 100  # Mbps (auto-adjusting)
        self.update_interval = 1000  # milliseconds
        self.smoothing_factor = 0.3  # Data smoothing
        
        # Display options
        self.show_download = True
        self.show_upload = True
        self.show_ping = True
        self.show_grid = True
        self.show_annotations = True
        self.smooth_data = True
        
        # Colors and styling
        self.setup_colors()
        
        # Animation properties
        self.animation_phase = 0
        self.pulse_animation = 0
        
        # Performance thresholds
        self.thresholds = {
            'download_warning': 10,   # Mbps
            'download_critical': 5,    # Mbps
            'upload_warning': 5,       # Mbps
            'upload_critical': 2,       # Mbps
            'ping_warning': 150,        # ms
            'ping_critical': 300         # ms
        }
        
        # Setup UI
        self.setup_ui()
        
        # Update timers
        self.setup_timers()
        
        self.setMinimumSize(600, 400)
    
    def setup_colors(self) -> None:
        """Setup color scheme for graphs."""
        # Speed colors
        self.download_color = QColor(76, 175, 80)    # Green
        self.upload_color = QColor(33, 150, 243)       # Blue
        self.ping_color = QColor(255, 152, 0)         # Orange
        self.packet_loss_color = QColor(244, 67, 54)   # Red
        self.jitter_color = QColor(156, 39, 176)       # Purple
        
        # Background colors
        self.bg_color = QColor(20, 30, 48)
        self.grid_color = QColor(46, 64, 83, 100)
        self.text_color = QColor(255, 255, 255)
        self.axis_color = QColor(100, 120, 140)
        
        # Alert colors
        self.warning_color = QColor(255, 193, 7)
        self.critical_color = QColor(244, 67, 54)
        self.success_color = QColor(76, 175, 80)
    
    def setup_ui(self) -> None:
        """Setup the user interface."""
        layout = QVBoxLayout(self)
        
        # Control panel
        control_panel = self.create_control_panel()
        layout.addWidget(control_panel)
        
        # Graph display area
        self.graph_widget = QWidget()
        self.graph_widget.setStyleSheet(f"background-color: {self.bg_color.name()};")
        layout.addWidget(self.graph_widget)
        
        # Statistics panel
        stats_panel = self.create_statistics_panel()
        layout.addWidget(stats_panel)
    
    def create_control_panel(self) -> QWidget:
        """Create the control panel."""
        panel = QFrame()
        panel.setFrameStyle(QFrame.Box)
        panel.setStyleSheet("""
            QFrame {
                background-color: #2E4053;
                border: 1px solid #4A5568;
                border-radius: 5px;
                padding: 5px;
            }
        """)
        
        layout = QHBoxLayout(panel)
        
        # Graph mode selector
        mode_label = QLabel("Graph Mode:")
        mode_label.setStyleSheet("color: white; font-weight: bold;")
        layout.addWidget(mode_label)
        
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Real-time", "Historical", "Comparison", "Statistics"])
        self.mode_combo.currentTextChanged.connect(self.change_graph_mode)
        layout.addWidget(self.mode_combo)
        
        # Time range selector
        range_label = QLabel("Time Range:")
        range_label.setStyleSheet("color: white; font-weight: bold;")
        layout.addWidget(range_label)
        
        self.range_combo = QComboBox()
        self.range_combo.addItems(["1 min", "5 min", "15 min", "1 hour", "6 hours", "24 hours"])
        self.range_combo.currentTextChanged.connect(self.change_time_range)
        layout.addWidget(self.range_combo)
        
        # Display options
        self.download_check = QCheckBox("Download")
        self.download_check.setChecked(True)
        self.download_check.toggled.connect(self.toggle_download)
        layout.addWidget(self.download_check)
        
        self.upload_check = QCheckBox("Upload")
        self.upload_check.setChecked(True)
        self.upload_check.toggled.connect(self.toggle_upload)
        layout.addWidget(self.upload_check)
        
        self.ping_check = QCheckBox("Ping")
        self.ping_check.setChecked(True)
        self.ping_check.toggled.connect(self.toggle_ping)
        layout.addWidget(self.ping_check)
        
        self.grid_check = QCheckBox("Grid")
        self.grid_check.setChecked(True)
        self.grid_check.toggled.connect(self.toggle_grid)
        layout.addWidget(self.grid_check)
        
        layout.addStretch()
        
        # Export button
        export_btn = QPushButton("Export Data")
        export_btn.clicked.connect(self.export_data)
        export_btn.setStyleSheet("""
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
        layout.addWidget(export_btn)
        
        return panel
    
    def create_statistics_panel(self) -> QWidget:
        """Create the statistics display panel."""
        panel = QFrame()
        panel.setFrameStyle(QFrame.Box)
        panel.setStyleSheet("""
            QFrame {
                background-color: #2E4053;
                border: 1px solid #4A5568;
                border-radius: 5px;
                padding: 5px;
            }
        """)
        
        layout = QGridLayout(panel)
        
        # Create statistics labels
        self.stats_labels = {}
        
        stats_items = [
            ("avg_download", "Avg Download:", "0 Mbps"),
            ("avg_upload", "Avg Upload:", "0 Mbps"),
            ("max_download", "Max Download:", "0 Mbps"),
            ("max_upload", "Max Upload:", "0 Mbps"),
            ("avg_ping", "Avg Ping:", "0 ms"),
            ("min_ping", "Min Ping:", "0 ms"),
            ("total_downloaded", "Total Downloaded:", "0 MB"),
            ("total_uploaded", "Total Uploaded:", "0 MB"),
            ("uptime", "Connection Time:", "0:00:00"),
            ("data_points", "Data Points:", "0")
        ]
        
        for i, (key, label, default) in enumerate(stats_items):
            row = i // 2
            col = (i % 2) * 3
            
            # Label
            label_widget = QLabel(label)
            label_widget.setStyleSheet("color: #B0BEC5; font-weight: bold;")
            layout.addWidget(label_widget, row, col)
            
            # Value
            value_widget = QLabel(default)
            value_widget.setStyleSheet("color: white; font-size: 12px;")
            layout.addWidget(value_widget, row, col + 1)
            
            self.stats_labels[key] = value_widget
        
        return panel
    
    def setup_timers(self) -> None:
        """Setup update timers."""
        # Data update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_graph)
        self.update_timer.start(self.update_interval)
        
        # Animation timer
        self.animation_timer = QTimer()
        self.animation_timer.timeout.connect(self.update_animations)
        self.animation_timer.start(50)  # 20 FPS
        
        # Statistics update timer
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_statistics)
        self.stats_timer.start(5000)  # Update every 5 seconds
    
    def add_speed_data(self, download_speed: float, upload_speed: float, 
                     ping: float = 0, packet_loss: float = 0, 
                     jitter: float = 0, connected: bool = True) -> None:
        """Add new speed data point."""
        current_time = time.time()
        
        data_point = SpeedDataPoint(
            timestamp=current_time,
            download_speed=download_speed,
            upload_speed=upload_speed,
            ping=ping,
            packet_loss=packet_loss,
            jitter=jitter,
            connected=connected
        )
        
        self.speed_data.append(data_point)
        self.historical_data.append(data_point)
        
        # Adjust max speed if needed
        self.max_speed = max(self.max_speed, download_speed, upload_speed) * 1.2
        
        # Check thresholds
        self.check_thresholds(data_point)
        
        # Update graph
        self.graph_widget.update()
    
    def check_thresholds(self, data: SpeedDataPoint) -> None:
        """Check performance thresholds and emit alerts."""
        if data.download_speed < self.thresholds['download_critical']:
            self.speed_alert.emit("critical_download", data.download_speed)
        elif data.download_speed < self.thresholds['download_warning']:
            self.speed_alert.emit("warning_download", data.download_speed)
        
        if data.upload_speed < self.thresholds['upload_critical']:
            self.speed_alert.emit("critical_upload", data.upload_speed)
        elif data.upload_speed < self.thresholds['upload_warning']:
            self.speed_alert.emit("warning_upload", data.upload_speed)
        
        if data.ping > self.thresholds['ping_critical']:
            self.speed_alert.emit("critical_ping", data.ping)
        elif data.ping > self.thresholds['ping_warning']:
            self.speed_alert.emit("warning_ping", data.ping)
    
    def update_graph(self) -> None:
        """Update the graph display."""
        self.graph_widget.update()
    
    def update_animations(self) -> None:
        """Update animations."""
        self.animation_phase += 0.1
        self.pulse_animation = (math.sin(self.animation_phase) + 1) / 2
        
        self.graph_widget.update()
    
    def update_statistics(self) -> None:
        """Update statistics display."""
        if not self.speed_data:
            return
        
        # Calculate statistics
        stats = self.calculate_statistics()
        
        # Update labels
        self.stats_labels["avg_download"].setText(f"{stats.avg_download:.1f} Mbps")
        self.stats_labels["avg_upload"].setText(f"{stats.avg_upload:.1f} Mbps")
        self.stats_labels["max_download"].setText(f"{stats.max_download:.1f} Mbps")
        self.stats_labels["max_upload"].setText(f"{stats.max_upload:.1f} Mbps")
        self.stats_labels["avg_ping"].setText(f"{stats.avg_ping:.0f} ms")
        self.stats_labels["min_ping"].setText(f"{stats.min_ping:.0f} ms")
        self.stats_labels["total_downloaded"].setText(f"{stats.total_data_downloaded:.1f} MB")
        self.stats_labels["total_uploaded"].setText(f"{stats.total_data_uploaded:.1f} MB")
        
        # Format uptime
        hours = int(stats.connection_uptime // 3600)
        minutes = int((stats.connection_uptime % 3600) // 60)
        seconds = int(stats.connection_uptime % 60)
        self.stats_labels["uptime"].setText(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
        self.stats_labels["data_points"].setText(str(stats.data_points))
    
    def calculate_statistics(self) -> SpeedStatistics:
        """Calculate statistics from current data."""
        if not self.speed_data:
            return SpeedStatistics(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        
        connected_data = [d for d in self.speed_data if d.connected]
        
        if not connected_data:
            return SpeedStatistics(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        
        download_speeds = [d.download_speed for d in connected_data]
        upload_speeds = [d.upload_speed for d in connected_data]
        pings = [d.ping for d in connected_data if d.ping > 0]
        
        # Calculate basic statistics
        avg_download = sum(download_speeds) / len(download_speeds)
        avg_upload = sum(upload_speeds) / len(upload_speeds)
        max_download = max(download_speeds)
        max_upload = max(upload_speeds)
        min_download = min(download_speeds)
        min_upload = min(upload_speeds)
        
        # Ping statistics
        if pings:
            avg_ping = sum(pings) / len(pings)
            max_ping = max(pings)
            min_ping = min(pings)
        else:
            avg_ping = max_ping = min_ping = 0
        
        # Calculate total data (simplified)
        time_span = connected_data[-1].timestamp - connected_data[0].timestamp
        total_downloaded = avg_download * time_span / 8  # Convert to MB
        total_uploaded = avg_upload * time_span / 8
        
        return SpeedStatistics(
            avg_download=avg_download,
            avg_upload=avg_upload,
            max_download=max_download,
            max_upload=max_upload,
            min_download=min_download,
            min_upload=min_upload,
            avg_ping=avg_ping,
            max_ping=max_ping,
            min_ping=min_ping,
            total_data_downloaded=total_downloaded,
            total_data_uploaded=total_uploaded,
            connection_uptime=time_span,
            data_points=len(connected_data)
        )
    
    def paintEvent(self, event: QPaintEvent) -> None:
        """Paint the speed graph."""
        painter = QPainter(self.graph_widget)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Get drawing area
        rect = self.graph_widget.rect()
        
        # Draw background
        painter.fillRect(rect, self.bg_color)
        
        # Draw based on current mode
        if self.graph_mode == "realtime":
            self._draw_realtime_graph(painter, rect)
        elif self.graph_mode == "historical":
            self._draw_historical_graph(painter, rect)
        elif self.graph_mode == "comparison":
            self._draw_comparison_graph(painter, rect)
        elif self.graph_mode == "statistics":
            self._draw_statistics_view(painter, rect)
    
    def _draw_realtime_graph(self, painter: QPainter, rect: QRectF) -> None:
        """Draw real-time speed graph."""
        if not self.speed_data:
            self._draw_no_data_message(painter, rect)
            return
        
        # Draw grid
        if self.show_grid:
            self._draw_grid(painter, rect)
        
        # Draw axes
        self._draw_axes(painter, rect)
        
        # Draw speed lines
        if self.show_download:
            self._draw_speed_line(painter, rect, "download", self.download_color)
        
        if self.show_upload:
            self._draw_speed_line(painter, rect, "upload", self.upload_color)
        
        if self.show_ping:
            self._draw_ping_line(painter, rect)
        
        # Draw threshold lines
        self._draw_threshold_lines(painter, rect)
        
        # Draw current values
        self._draw_current_values(painter, rect)
    
    def _draw_speed_line(self, painter: QPainter, rect: QRectF, 
                        speed_type: str, color: QColor) -> None:
        """Draw a speed line graph."""
        if speed_type == "download":
            data = [(d.timestamp, d.download_speed) for d in self.speed_data if d.connected]
        else:  # upload
            data = [(d.timestamp, d.upload_speed) for d in self.speed_data if d.connected]
        
        if len(data) < 2:
            return
        
        # Filter data by time range
        current_time = time.time()
        cutoff_time = current_time - self.time_range
        filtered_data = [(t, s) for t, s in data if t > cutoff_time]
        
        if len(filtered_data) < 2:
            return
        
        # Apply smoothing if enabled
        if self.smooth_data:
            filtered_data = self._smooth_data(filtered_data)
        
        # Convert to screen coordinates
        points = []
        for timestamp, speed in filtered_data:
            x = rect.left() + (timestamp - cutoff_time) / self.time_range * rect.width()
            y = rect.bottom() - (speed / self.max_speed) * rect.height() * 0.9
            points.append(QPointF(x, y))
        
        # Draw area under curve
        if len(points) > 2:
            area_points = points.copy()
            area_points.append(QPointF(points[-1].x(), rect.bottom()))
            area_points.append(QPointF(points[0].x(), rect.bottom()))
            
            area_color = QColor(color)
            area_color.setAlpha(50)
            painter.setBrush(QBrush(area_color))
            painter.setPen(Qt.NoPen)
            
            polygon = QPolygonF([QPointF(p.x(), p.y()) for p in area_points])
            painter.drawPolygon(polygon)
        
        # Draw line
        pen = QPen(color, 2)
        painter.setPen(pen)
        
        for i in range(len(points) - 1):
            painter.drawLine(points[i], points[i + 1])
        
        # Draw data points
        painter.setBrush(QBrush(color))
        painter.setPen(QPen(Qt.white, 1))
        
        for point in points[::5]:  # Draw every 5th point to avoid clutter
            painter.drawEllipse(point, 3, 3)
    
    def _draw_ping_line(self, painter: QPainter, rect: QRectF) -> None:
        """Draw ping line on secondary axis."""
        ping_data = [(d.timestamp, d.ping) for d in self.speed_data 
                    if d.connected and d.ping > 0]
        
        if len(ping_data) < 2:
            return
        
        # Filter data
        current_time = time.time()
        cutoff_time = current_time - self.time_range
        filtered_data = [(t, p) for t, p in ping_data if t > cutoff_time]
        
        if len(filtered_data) < 2:
            return
        
        # Convert to screen coordinates (ping uses right axis)
        points = []
        max_ping = 300  # Maximum ping for scaling
        
        for timestamp, ping in filtered_data:
            x = rect.left() + (timestamp - cutoff_time) / self.time_range * rect.width()
            y = rect.bottom() - (ping / max_ping) * rect.height() * 0.9
            points.append(QPointF(x, y))
        
        # Draw ping line
        pen = QPen(self.ping_color, 2, Qt.DashLine)
        painter.setPen(pen)
        
        for i in range(len(points) - 1):
            painter.drawLine(points[i], points[i + 1])
    
    def _draw_grid(self, painter: QPainter, rect: QRectF) -> None:
        """Draw background grid."""
        painter.setPen(QPen(self.grid_color, 1))
        
        # Horizontal lines
        for i in range(6):
            y = rect.top() + rect.height() * i / 5
            painter.drawLine(rect.left(), y, rect.right(), y)
        
        # Vertical lines
        for i in range(11):
            x = rect.left() + rect.width() * i / 10
            painter.drawLine(x, rect.top(), x, rect.bottom())
    
    def _draw_axes(self, painter: QPainter, rect: QRectF) -> None:
        """Draw graph axes."""
        painter.setPen(QPen(self.axis_color, 2))
        
        # X-axis
        painter.drawLine(rect.left(), rect.bottom(), rect.right(), rect.bottom())
        
        # Y-axis (left - speed)
        painter.drawLine(rect.left(), rect.top(), rect.left(), rect.bottom())
        
        # Y-axis (right - ping)
        painter.drawLine(rect.right(), rect.top(), rect.right(), rect.bottom())
        
        # Draw axis labels
        painter.setPen(QPen(self.text_color, 1))
        painter.setFont(QFont("Arial", 8))
        
        # Y-axis labels (speed)
        for i in range(6):
            speed = self.max_speed * (5 - i) / 5
            y = rect.top() + rect.height() * i / 5
            painter.drawText(rect.left() - 40, y + 3, f"{speed:.0f} Mbps")
        
        # Y-axis labels (ping)
        for i in range(6):
            ping = 300 * (5 - i) / 5
            y = rect.top() + rect.height() * i / 5
            painter.drawText(rect.right() + 5, y + 3, f"{ping:.0f} ms")
        
        # X-axis labels (time)
        current_time = time.time()
        for i in range(11):
            time_offset = self.time_range * (10 - i) / 10
            x = rect.left() + rect.width() * i / 10
            
            if time_offset < 60:
                label = f"{time_offset:.0f}s"
            else:
                label = f"{time_offset/60:.1f}m"
            
            painter.drawText(x - 15, rect.bottom() + 15, label)
    
    def _draw_threshold_lines(self, painter: QPainter, rect: QRectF) -> None:
        """Draw performance threshold lines."""
        # Download warning threshold
        y = rect.bottom() - (self.thresholds['download_warning'] / self.max_speed) * rect.height() * 0.9
        painter.setPen(QPen(self.warning_color, 1, Qt.DashLine))
        painter.drawLine(rect.left(), y, rect.right(), y)
        
        # Download critical threshold
        y = rect.bottom() - (self.thresholds['download_critical'] / self.max_speed) * rect.height() * 0.9
        painter.setPen(QPen(self.critical_color, 1, Qt.DashLine))
        painter.drawLine(rect.left(), y, rect.right(), y)
    
    def _draw_current_values(self, painter: QPainter, rect: QRectF) -> None:
        """Draw current speed values."""
        if not self.speed_data:
            return
        
        latest_data = self.speed_data[-1]
        
        if not latest_data.connected:
            return
        
        # Create value display box
        box_rect = QRectF(rect.right() - 150, rect.top() + 10, 140, 80)
        
        # Background
        painter.setBrush(QBrush(QColor(0, 0, 0, 150)))
        painter.setPen(QPen(self.text_color, 1))
        painter.drawRoundedRect(box_rect, 5, 5)
        
        # Text
        painter.setFont(QFont("Arial", 10, QFont.Bold))
        painter.setPen(QPen(self.text_color, 1))
        
        y_offset = 20
        if self.show_download:
            painter.drawText(box_rect.left() + 10, box_rect.top() + y_offset, 
                           f"↓ {latest_data.download_speed:.1f} Mbps")
            y_offset += 20
        
        if self.show_upload:
            painter.drawText(box_rect.left() + 10, box_rect.top() + y_offset, 
                           f"↑ {latest_data.upload_speed:.1f} Mbps")
            y_offset += 20
        
        if self.show_ping and latest_data.ping > 0:
            painter.drawText(box_rect.left() + 10, box_rect.top() + y_offset, 
                           f"◷ {latest_data.ping:.0f} ms")
    
    def _draw_no_data_message(self, painter: QPainter, rect: QRectF) -> None:
        """Draw message when no data is available."""
        painter.setPen(QPen(self.text_color, 1))
        painter.setFont(QFont("Arial", 14, QFont.Bold))
        
        text = "No speed data available"
        text_rect = QRectF(rect.left(), rect.top(), rect.width(), rect.height())
        painter.drawText(text_rect, Qt.AlignCenter, text)
    
    def _smooth_data(self, data: List[Tuple[float, float]]) -> List[Tuple[float, float]]:
        """Apply exponential smoothing to data."""
        if len(data) < 2:
            return data
        
        smoothed = []
        smoothed.append(data[0])
        
        for i in range(1, len(data)):
            smoothed_value = (self.smoothing_factor * data[i][1] + 
                           (1 - self.smoothing_factor) * smoothed[-1][1])
            smoothed.append((data[i][0], smoothed_value))
        
        return smoothed
    
    def change_graph_mode(self, mode: str) -> None:
        """Change graph display mode."""
        self.graph_mode = mode.lower().replace(" ", "_")
        self.graph_mode_changed.emit(self.graph_mode)
        self.graph_widget.update()
    
    def change_time_range(self, range_text: str) -> None:
        """Change time range for graph."""
        range_map = {
            "1 min": 60,
            "5 min": 300,
            "15 min": 900,
            "1 hour": 3600,
            "6 hours": 21600,
            "24 hours": 86400
        }
        
        self.time_range = range_map.get(range_text, 300)
        self.graph_widget.update()
    
    def toggle_download(self, checked: bool) -> None:
        """Toggle download speed display."""
        self.show_download = checked
        self.graph_widget.update()
    
    def toggle_upload(self, checked: bool) -> None:
        """Toggle upload speed display."""
        self.show_upload = checked
        self.graph_widget.update()
    
    def toggle_ping(self, checked: bool) -> None:
        """Toggle ping display."""
        self.show_ping = checked
        self.graph_widget.update()
    
    def toggle_grid(self, checked: bool) -> None:
        """Toggle grid display."""
        self.show_grid = checked
        self.graph_widget.update()
    
    def export_data(self) -> None:
        """Export speed data to file."""
        try:
            filename = f"speed_data_{int(time.time())}.json"
            
            export_data = {
                'export_timestamp': time.time(),
                'time_range': self.time_range,
                'max_speed': self.max_speed,
                'data_points': [
                    {
                        'timestamp': d.timestamp,
                        'download_speed': d.download_speed,
                        'upload_speed': d.upload_speed,
                        'ping': d.ping,
                        'packet_loss': d.packet_loss,
                        'jitter': d.jitter,
                        'connected': d.connected
                    }
                    for d in self.speed_data
                ],
                'statistics': self.calculate_statistics().__dict__
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.info(f"Speed data exported to {filename}")
            
        except Exception as e:
            self.logger.error(f"Failed to export speed data: {e}")
    
    def clear_data(self) -> None:
        """Clear all speed data."""
        self.speed_data.clear()
        self.historical_data.clear()
        self.graph_widget.update()
        self.update_statistics()
    
    def set_thresholds(self, thresholds: Dict[str, float]) -> None:
        """Set performance thresholds."""
        self.thresholds.update(thresholds)
        self.graph_widget.update()
    
    def get_current_speeds(self) -> Optional[Tuple[float, float]]:
        """Get current download and upload speeds."""
        if self.speed_data:
            latest = self.speed_data[-1]
            if latest.connected:
                return latest.download_speed, latest.upload_speed
        return None


# Example usage
if __name__ == "__main__":
    import sys
    from PySide6.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    
    # Create advanced speed graph
    speed_graph = AdvancedSpeedGraphWidget()
    speed_graph.show()
    
    # Simulate speed data
    def simulate_data():
        import random
        download = random.uniform(20, 80)
        upload = random.uniform(5, 30)
        ping = random.uniform(30, 150)
        speed_graph.add_speed_data(download, upload, ping)
    
    # Add simulation timer
    sim_timer = QTimer()
    sim_timer.timeout.connect(simulate_data)
    sim_timer.start(1000)  # Add data every second
    
    sys.exit(app.exec())
