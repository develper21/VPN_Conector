#!/usr/bin/env python3
"""
Advanced Server Location Map Widget
Interactive world map with server locations, performance indicators, and selection features.
Enhanced version with detailed server information and advanced interactions.
"""
import json
import logging
import math
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from pathlib import Path

try:
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel,
        QPushButton, QFrame, QScrollArea, QToolTip,
        QGraphicsOpacityEffect
    )
    from PySide6.QtCore import (
        Qt, QTimer, QThread, Signal, QPointF, QRectF,
        QSize, pyqtSignal, QPropertyAnimation, QEasingCurve,
        QParallelAnimationGroup
    )
    from PySide6.QtGui import (
        QPainter, QColor, QPen, QBrush, QFont, QPalette,
        QPixmap, QIcon, QLinearGradient, QRadialGradient,
        QMouseEvent, QWheelEvent, QPaintEvent, QPolygonF
    )
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

from utils.logger import setup_logger


@dataclass
class MapServer:
    """Enhanced server information for map display."""
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
    region: str = ""
    users_connected: int = 0
    max_users: int = 1000
    uptime: float = 99.9  # percentage


class AdvancedServerMapWidget(QWidget):
    """Advanced interactive server map with enhanced features."""
    
    # Signals
    server_selected = Signal(str)  # Server ID
    server_hovered = Signal(str)   # Server ID
    region_selected = Signal(str)  # Region name
    connection_requested = Signal(str)  # Server ID for immediate connection
    
    def __init__(self):
        super().__init__()
        self.logger = setup_logger("advanced_server_map", "INFO")
        
        # Server data
        self.servers: Dict[str, MapServer] = {}
        self.regions: Dict[str, List[str]] = {}  # Region -> Server IDs
        self.selected_server: Optional[str] = None
        self.hovered_server: Optional[str] = None
        self.selected_region: Optional[str] = None
        
        # Map properties
        self.zoom_level = 1.0
        self.pan_offset = QPointF(0, 0)
        self.is_panning = False
        self.last_mouse_pos = QPointF()
        self.animation_progress = 0.0
        
        # Visual properties
        self.map_width = 1200
        self.map_height = 600
        self.show_server_labels = True
        self.show_performance_indicators = True
        self.show_connection_lines = True
        self.animate_servers = True
        
        # Colors and styling
        self.setup_colors()
        
        # Animation timers
        self.animation_timer = QTimer()
        self.animation_timer.timeout.connect(self.update_animations)
        self.animation_timer.start(50)  # 20 FPS
        
        # Server animations
        self.server_animations: Dict[str, Dict] = {}
        
        # Map data (simplified - would use real geographic data)
        self.continents = self._load_continent_data()
        self.country_borders = self._load_country_data()
        
        self.setMinimumSize(800, 400)
        self.setMouseTracking(True)
        self.setFocusPolicy(Qt.StrongFocus)
        
        # Initialize animations
        self._initialize_server_animations()
    
    def setup_colors(self) -> None:
        """Setup color scheme for the map."""
        # Background and map colors
        self.bg_color = QColor(15, 23, 42)  # Dark blue
        self.ocean_color = QColor(20, 35, 60)  # Ocean blue
        self.land_color = QColor(46, 64, 83)  # Land color
        self.border_color = QColor(74, 85, 104)  # Border color
        
        # Server performance colors
        self.server_colors = {
            'excellent': QColor(76, 175, 80),    # Green
            'good': QColor(33, 150, 243),       # Blue
            'moderate': QColor(255, 193, 7),    # Yellow
            'poor': QColor(244, 67, 54),       # Red
            'maintenance': QColor(156, 39, 176)   # Purple
        }
        
        # UI colors
        self.selection_color = QColor(255, 255, 255)  # White
        self.hover_color = QColor(255, 235, 59)       # Yellow
        self.connection_color = QColor(76, 175, 80, 150)  # Green with alpha
        
        # Region colors
        self.region_colors = [
            QColor(255, 152, 0, 50),   # Orange
            QColor(156, 39, 176, 50),  # Purple
            QColor(3, 169, 244, 50),   # Light Blue
            QColor(0, 150, 136, 50),    # Teal
            QColor(233, 30, 99, 50),    # Pink
        ]
    
    def _load_continent_data(self) -> List[Dict]:
        """Load simplified continent data."""
        return [
            {
                'name': 'North America',
                'bounds': QRectF(150, 100, 250, 200),
                'color': QColor(52, 73, 94)
            },
            {
                'name': 'South America',
                'bounds': QRectF(200, 350, 100, 150),
                'color': QColor(46, 64, 83)
            },
            {
                'name': 'Europe',
                'bounds': QRectF(450, 80, 150, 120),
                'color': QColor(52, 73, 94)
            },
            {
                'name': 'Africa',
                'bounds': QRectF(450, 250, 120, 180),
                'color': QColor(46, 64, 83)
            },
            {
                'name': 'Asia',
                'bounds': QRectF(600, 100, 300, 200),
                'color': QColor(52, 73, 94)
            },
            {
                'name': 'Oceania',
                'bounds': QRectF(750, 400, 150, 100),
                'color': QColor(46, 64, 83)
            }
        ]
    
    def _load_country_data(self) -> List[Dict]:
        """Load simplified country border data."""
        # This would contain actual country polygon data
        return []
    
    def add_server(self, server: MapServer) -> None:
        """Add a server to the map."""
        self.servers[server.id] = server
        
        # Add to region
        if server.region not in self.regions:
            self.regions[server.region] = []
        self.regions[server.region].append(server.id)
        
        # Initialize animation
        self._initialize_server_animation(server.id)
        
        self.update()
    
    def remove_server(self, server_id: str) -> None:
        """Remove a server from the map."""
        if server_id in self.servers:
            server = self.servers[server_id]
            
            # Remove from region
            if server.region in self.regions:
                self.regions[server.region].remove(server_id)
                if not self.regions[server.region]:
                    del self.regions[server.region]
            
            del self.servers[server_id]
            
            # Remove animation
            if server_id in self.server_animations:
                del self.server_animations[server_id]
            
            self.update()
    
    def select_server(self, server_id: str) -> None:
        """Select a server on the map."""
        if server_id in self.servers:
            self.selected_server = server_id
            self.server_selected.emit(server_id)
            
            # Animate selection
            self._animate_server_selection(server_id)
            
            self.update()
    
    def get_server_at_pos(self, pos: QPointF) -> Optional[str]:
        """Get server ID at mouse position."""
        for server_id, server in self.servers.items():
            server_pos = self._lat_lon_to_pos(server.latitude, server.longitude)
            distance = math.sqrt((pos.x() - server_pos.x())**2 + (pos.y() - server_pos.y())**2)
            
            # Check server hit box (larger for selected server)
            hit_radius = 20 if server_id == self.selected_server else 12
            if distance < hit_radius:
                return server_id
        return None
    
    def get_region_at_pos(self, pos: QPointF) -> Optional[str]:
        """Get region at mouse position."""
        for continent in self.continents:
            if continent['bounds'].contains(pos):
                return continent['name']
        return None
    
    def _lat_lon_to_pos(self, lat: float, lon: float) -> QPointF:
        """Convert latitude/longitude to map position with proper projection."""
        # Web Mercator projection
        x = (lon + 180) * (self.map_width / 360)
        
        # Latitude conversion with proper scaling
        lat_rad = math.radians(lat)
        y = self.map_height / 2 - (self.map_width * math.log(math.tan(math.pi/4 + lat_rad/2)) / (2 * math.pi))
        
        # Apply zoom and pan
        x = x * self.zoom_level + self.pan_offset.x()
        y = y * self.zoom_level + self.pan_offset.y()
        
        return QPointF(x, y)
    
    def _initialize_server_animations(self) -> None:
        """Initialize animations for all servers."""
        for server_id in self.servers:
            self._initialize_server_animation(server_id)
    
    def _initialize_server_animation(self, server_id: str) -> None:
        """Initialize animation for a specific server."""
        self.server_animations[server_id] = {
            'pulse_phase': 0,
            'pulse_speed': 0.05 + (hash(server_id) % 10) * 0.01,
            'selection_animation': 0,
            'hover_animation': 0,
            'connection_animation': 0
        }
    
    def update_animations(self) -> None:
        """Update all animations."""
        self.animation_progress += 0.05
        
        for server_id, animation in self.server_animations.items():
            # Pulse animation
            animation['pulse_phase'] += animation['pulse_speed']
            if animation['pulse_phase'] > 2 * math.pi:
                animation['pulse_phase'] -= 2 * math.pi
            
            # Selection animation
            if server_id == self.selected_server:
                animation['selection_animation'] = min(1.0, animation['selection_animation'] + 0.1)
            else:
                animation['selection_animation'] = max(0.0, animation['selection_animation'] - 0.1)
            
            # Hover animation
            if server_id == self.hovered_server:
                animation['hover_animation'] = min(1.0, animation['hover_animation'] + 0.2)
            else:
                animation['hover_animation'] = max(0.0, animation['hover_animation'] - 0.2)
        
        self.update()
    
    def _animate_server_selection(self, server_id: str) -> None:
        """Animate server selection."""
        if server_id in self.server_animations:
            self.server_animations[server_id]['selection_animation'] = 0.0
    
    def paintEvent(self, event: QPaintEvent) -> None:
        """Paint the advanced map."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw background
        painter.fillRect(self.rect(), self.bg_color)
        
        # Draw ocean
        painter.fillRect(self.rect(), self.ocean_color)
        
        # Draw continents
        self._draw_continents(painter)
        
        # Draw regions
        if self.selected_region:
            self._draw_region_highlight(painter)
        
        # Draw connection lines
        if self.show_connection_lines and self.selected_server:
            self._draw_connection_lines(painter)
        
        # Draw servers
        self._draw_servers(painter)
        
        # Draw server labels
        if self.show_server_labels:
            self._draw_server_labels(painter)
        
        # Draw performance indicators
        if self.show_performance_indicators:
            self._draw_performance_indicators(painter)
        
        # Draw legend
        self._draw_legend(painter)
    
    def _draw_continents(self, painter: QPainter) -> None:
        """Draw continent shapes."""
        for continent in self.continents:
            # Apply zoom and pan to bounds
            bounds = continent['bounds']
            scaled_bounds = QRectF(
                bounds.left() * self.zoom_level + self.pan_offset.x(),
                bounds.top() * self.zoom_level + self.pan_offset.y(),
                bounds.width() * self.zoom_level,
                bounds.height() * self.zoom_level
            )
            
            # Draw continent
            painter.setBrush(QBrush(continent['color']))
            painter.setPen(QPen(self.border_color, 1))
            painter.drawRoundedRect(scaled_bounds, 15, 15)
            
            # Draw continent name
            painter.setPen(QPen(Qt.white, 1))
            painter.setFont(QFont("Arial", 10, QFont.Bold))
            text_rect = QRectF(
                scaled_bounds.center().x() - 50,
                scaled_bounds.center().y() - 10,
                100, 20
            )
            painter.drawText(text_rect, Qt.AlignCenter, continent['name'])
    
    def _draw_region_highlight(self, painter: QPainter) -> None:
        """Draw highlight for selected region."""
        if self.selected_region in self.regions:
            # Find servers in region
            region_servers = [self.servers[sid] for sid in self.regions[self.selected_region] 
                            if sid in self.servers]
            
            if region_servers:
                # Calculate bounding box
                positions = [self._lat_lon_to_pos(s.latitude, s.longitude) 
                           for s in region_servers]
                
                if positions:
                    min_x = min(p.x() for p in positions)
                    max_x = max(p.x() for p in positions)
                    min_y = min(p.y() for p in positions)
                    max_y = max(p.y() for p in positions)
                    
                    # Draw region highlight
                    highlight_rect = QRectF(min_x - 20, min_y - 20, 
                                         max_x - min_x + 40, max_y - min_y + 40)
                    
                    painter.setBrush(QBrush(QColor(76, 175, 80, 30)))
                    painter.setPen(QPen(QColor(76, 175, 80, 100), 2, Qt.DashLine))
                    painter.drawRoundedRect(highlight_rect, 10, 10)
    
    def _draw_connection_lines(self, painter: QPainter) -> None:
        """Draw connection lines to selected server."""
        if self.selected_server and self.selected_server in self.servers:
            server = self.servers[self.selected_server]
            server_pos = self._lat_lon_to_pos(server.latitude, server.longitude)
            
            # Draw connection lines from other servers
            for other_id, other_server in self.servers.items():
                if other_id != self.selected_server:
                    other_pos = self._lat_lon_to_pos(other_server.latitude, other_server.longitude)
                    
                    # Calculate line properties based on performance
                    if other_id in self.server_animations:
                        animation = self.server_animations[other_id]
                        alpha = int(50 + 30 * math.sin(animation['pulse_phase']))
                    else:
                        alpha = 50
                    
                    # Draw connection line
                    line_color = QColor(100, 150, 200, alpha)
                    painter.setPen(QPen(line_color, 1))
                    painter.drawLine(other_pos, server_pos)
    
    def _draw_servers(self, painter: QPainter) -> None:
        """Draw server markers with animations."""
        for server_id, server in self.servers.items():
            pos = self._lat_lon_to_pos(server.latitude, server.longitude)
            
            # Get animation state
            animation = self.server_animations.get(server_id, {})
            
            # Determine base color
            base_color = self._get_server_performance_color(server)
            
            # Apply animations
            size = 12
            if server_id == self.selected_server:
                size += 8 * animation.get('selection_animation', 0)
            if server_id == self.hovered_server:
                size += 4 * animation.get('hover_animation', 0)
            
            # Draw server marker
            self._draw_server_marker(painter, pos, base_color, size, server, animation)
    
    def _draw_server_marker(self, painter: QPainter, pos: QPointF, color: QColor, 
                           size: float, server: MapServer, animation: Dict) -> None:
        """Draw an individual server marker."""
        # Draw outer glow for selected servers
        if server.id == self.selected_server:
            glow_size = size + 10 + 5 * math.sin(animation.get('pulse_phase', 0))
            glow_color = QColor(color)
            glow_color.setAlpha(50)
            
            painter.setBrush(QBrush(glow_color))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(pos, glow_size, glow_size)
        
        # Draw main server circle
        painter.setBrush(QBrush(color))
        painter.setPen(QPen(Qt.white, 2))
        painter.drawEllipse(pos, size, size)
        
        # Draw inner circle for load indicator
        load_size = size * (1 - server.load / 100)
        if load_size > 0:
            painter.setBrush(QBrush(Qt.white))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(pos, load_size, load_size)
        
        # Draw premium indicator
        if server.is_premium:
            painter.setPen(QPen(QColor(255, 215, 0), 2))
            painter.setBrush(Qt.NoBrush)
            painter.drawEllipse(pos, size + 3, size + 3)
        
        # Draw favorite indicator
        if server.is_favorite:
            star_pos = QPointF(pos.x() + size, pos.y() - size)
            painter.setPen(QPen(QColor(255, 215, 0), 2))
            painter.setBrush(QBrush(QColor(255, 215, 0)))
            self._draw_star(painter, star_pos, 5)
    
    def _draw_star(self, painter: QPainter, pos: QPointF, size: float) -> None:
        """Draw a star shape."""
        points = []
        for i in range(10):
            angle = math.pi * i / 5
            if i % 2 == 0:
                r = size
            else:
                r = size * 0.5
            
            x = pos.x() + r * math.cos(angle - math.pi / 2)
            y = pos.y() + r * math.sin(angle - math.pi / 2)
            points.append(QPointF(x, y))
        
        painter.drawPolygon(QPolygonF(points))
    
    def _draw_server_labels(self, painter: QPainter) -> None:
        """Draw server name labels."""
        painter.setPen(QPen(Qt.white, 1))
        painter.setFont(QFont("Arial", 8))
        
        for server in self.servers.values():
            pos = self._lat_lon_to_pos(server.latitude, server.longitude)
            
            # Draw server name
            text = f"{server.city}"
            text_rect = QRectF(pos.x() - 40, pos.y() + 20, 80, 15)
            painter.drawText(text_rect, Qt.AlignCenter, text)
            
            # Draw server stats
            stats_text = f"{server.load:.0f}% | {server.ping:.0f}ms"
            stats_rect = QRectF(pos.x() - 40, pos.y() + 35, 80, 12)
            painter.setFont(QFont("Arial", 7))
            painter.drawText(stats_rect, Qt.AlignCenter, stats_text)
    
    def _draw_performance_indicators(self, painter: QPainter) -> None:
        """Draw performance indicators for servers."""
        for server in self.servers.values():
            pos = self._lat_lon_to_pos(server.latitude, server.longitude)
            
            # Draw performance arc
            if server.load < 100:
                start_angle = 0
                span_angle = int(360 * (1 - server.load / 100))
                
                painter.setPen(QPen(self._get_server_performance_color(server), 3))
                painter.setBrush(Qt.NoBrush)
                painter.drawArc(QRectF(pos.x() - 18, pos.y() - 18, 36, 36),
                             start_angle * 16, span_angle * 16)
    
    def _draw_legend(self, painter: QPainter) -> None:
        """Draw map legend."""
        legend_x = 20
        legend_y = self.height() - 120
        
        # Draw legend background
        legend_rect = QRectF(legend_x - 10, legend_y - 10, 150, 100)
        painter.setBrush(QBrush(QColor(0, 0, 0, 150)))
        painter.setPen(QPen(Qt.white, 1))
        painter.drawRoundedRect(legend_rect, 5, 5)
        
        # Draw legend title
        painter.setPen(QPen(Qt.white, 1))
        painter.setFont(QFont("Arial", 9, QFont.Bold))
        painter.drawText(legend_x, legend_y, "Server Performance")
        
        # Draw performance indicators
        performance_items = [
            ("Excellent", self.server_colors['excellent']),
            ("Good", self.server_colors['good']),
            ("Moderate", self.server_colors['moderate']),
            ("Poor", self.server_colors['poor'])
        ]
        
        painter.setFont(QFont("Arial", 8))
        for i, (label, color) in enumerate(performance_items):
            y_pos = legend_y + 20 + i * 15
            
            # Draw color box
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.NoPen)
            painter.drawRect(legend_x, y_pos, 10, 10)
            
            # Draw label
            painter.setPen(QPen(Qt.white, 1))
            painter.drawText(legend_x + 15, y_pos + 8, label)
    
    def _get_server_performance_color(self, server: MapServer) -> QColor:
        """Get performance color for server based on metrics."""
        # Combined performance score
        load_score = server.load / 100
        ping_score = min(server.ping / 200, 1.0)  # Normalize to 0-1
        combined_score = (load_score + ping_score) / 2
        
        if combined_score < 0.3:
            return self.server_colors['excellent']
        elif combined_score < 0.5:
            return self.server_colors['good']
        elif combined_score < 0.7:
            return self.server_colors['moderate']
        else:
            return self.server_colors['poor']
    
    def mousePressEvent(self, event: QMouseEvent) -> None:
        """Handle mouse press events."""
        if event.button() == Qt.LeftButton:
            server_id = self.get_server_at_pos(event.position())
            if server_id:
                self.select_server(server_id)
                # Double-click for immediate connection
                if event.type() == event.MouseButtonDblClick:
                    self.connection_requested.emit(server_id)
            else:
                # Check for region selection
                region = self.get_region_at_pos(event.position())
                if region:
                    self.selected_region = region
                    self.region_selected.emit(region)
                else:
                    # Start panning
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
                if server_id and server_id in self.servers:
                    server = self.servers[server_id]
                    self._show_server_tooltip(event.position(), server)
                    self.server_hovered.emit(server_id)
                else:
                    QToolTip.hideText()
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
            self.zoom_level = min(5.0, self.zoom_level * 1.1)
        else:
            self.zoom_level = max(0.3, self.zoom_level / 1.1)
        
        self.update()
        super().wheelEvent(event)
    
    def _show_server_tooltip(self, pos: QPointF, server: MapServer) -> None:
        """Show detailed server tooltip."""
        tooltip_text = f"""
        <b>{server.city}, {server.country}</b><br>
        Load: {server.load:.1f}%<br>
        Ping: {server.ping:.0f}ms<br>
        Speed: {server.speed:.0f} Mbps<br>
        Protocol: {server.protocol.upper()}<br>
        Users: {server.users_connected}/{server.max_users}<br>
        Uptime: {server.uptime:.1f}%<br>
        {'⭐ Premium' if server.is_premium else '⚡ Standard'}<br>
        {'★ Favorite' if server.is_favorite else ''}
        """
        
        global_pos = self.mapToGlobal(pos.toPoint())
        QToolTip.showText(global_pos, tooltip_text.strip())
    
    def set_show_labels(self, show: bool) -> None:
        """Toggle server label display."""
        self.show_server_labels = show
        self.update()
    
    def set_show_performance_indicators(self, show: bool) -> None:
        """Toggle performance indicator display."""
        self.show_performance_indicators = show
        self.update()
    
    def set_show_connection_lines(self, show: bool) -> None:
        """Toggle connection line display."""
        self.show_connection_lines = show
        self.update()
    
    def reset_view(self) -> None:
        """Reset map view to default."""
        self.zoom_level = 1.0
        self.pan_offset = QPointF(0, 0)
        self.selected_region = None
        self.update()
    
    def zoom_to_server(self, server_id: str) -> None:
        """Zoom to a specific server."""
        if server_id in self.servers:
            server = self.servers[server_id]
            server_pos = self._lat_lon_to_pos(server.latitude, server.longitude)
            
            # Center on server
            self.pan_offset = QPointF(
                self.width() / 2 - server_pos.x(),
                self.height() / 2 - server_pos.y()
            )
            
            # Zoom in
            self.zoom_level = 2.0
            
            self.update()
    
    def get_servers_in_region(self, region: str) -> List[MapServer]:
        """Get all servers in a specific region."""
        if region in self.regions:
            return [self.servers[sid] for sid in self.regions[region] 
                   if sid in self.servers]
        return []
    
    def get_optimal_servers(self, max_servers: int = 5) -> List[MapServer]:
        """Get optimal servers based on performance."""
        # Sort by combined performance score
        scored_servers = []
        for server in self.servers.values():
            score = (100 - server.load) + (200 - server.ping) + server.speed
            scored_servers.append((score, server))
        
        scored_servers.sort(key=lambda x: x[0], reverse=True)
        return [server for _, server in scored_servers[:max_servers]]


# Example usage
if __name__ == "__main__":
    import sys
    from PySide6.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    
    # Create advanced server map
    server_map = AdvancedServerMapWidget()
    server_map.show()
    
    # Add sample servers
    sample_servers = [
        MapServer("us_ny_1", "US New York 1", "United States", "New York", 
                 40.7128, -74.0060, 25, 45, 85, "openvpn", 
                 False, True, "North America", 450, 1000, 99.9),
        MapServer("uk_london_1", "UK London 1", "United Kingdom", "London", 
                 51.5074, -0.1278, 45, 85, 78, "wireguard", 
                 True, False, "Europe", 320, 1000, 99.5),
        MapServer("jp_tokyo_1", "Japan Tokyo 1", "Japan", "Tokyo", 
                 35.6762, 139.6503, 70, 150, 45, "openvpn", 
                 False, True, "Asia", 280, 1000, 98.8),
    ]
    
    for server in sample_servers:
        server_map.add_server(server)
    
    sys.exit(app.exec())
