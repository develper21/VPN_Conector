#!/usr/bin/env python3
"""
One-Click Server Selection with Smart Recommendations
Intelligent server selection algorithm with performance analysis, location-based recommendations,
and user preference learning.
"""
import json
import logging
import math
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from pathlib import Path
from collections import defaultdict, deque

try:
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel,
        QPushButton, QFrame, QScrollArea, QGridLayout,
        QGroupBox, QTabWidget, QProgressBar,
        QLineEdit, QTextEdit, QComboBox, QCheckBox,
        QSpinBox, QSlider, QListWidget, QListWidgetItem
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
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

from utils.logger import setup_logger


@dataclass
class ServerMetrics:
    """Detailed server performance metrics."""
    server_id: str
    name: str
    country: str
    city: str
    latitude: float
    longitude: float
    load: float  # 0-100
    ping: float  # milliseconds
    download_speed: float  # Mbps
    upload_speed: float  # Mbps
    reliability: float  # 0-100
    uptime: float  # percentage
    user_count: int
    max_users: int
    protocol: str
    is_premium: bool
    region: str
    
    # Dynamic metrics
    recent_pings: deque
    recent_speeds: deque
    connection_success_rate: float
    average_session_duration: float
    
    def __post_init__(self):
        if not hasattr(self, 'recent_pings') or self.recent_pings is None:
            self.recent_pings = deque(maxlen=100)
        if not hasattr(self, 'recent_speeds') or self.recent_speeds is None:
            self.recent_speeds = deque(maxlen=50)


@dataclass
class UserPreferences:
    """User preferences for server selection."""
    preferred_protocols: List[str]
    preferred_regions: List[str]
    max_ping_threshold: float
    min_speed_threshold: float
    avoid_high_load: bool
    prefer_reliable: bool
    favorite_servers: List[str]
    blocked_servers: List[str]
    recent_connections: List[str]
    connection_history: Dict[str, List[float]]  # server_id -> [timestamps]


@dataclass
class RecommendationScore:
    """Server recommendation score with breakdown."""
    server_id: str
    total_score: float
    performance_score: float
    location_score: float
    load_score: float
    reliability_score: float
    user_preference_score: float
    recommendation_reason: str


class SmartServerSelector(QWidget):
    """Intelligent server selection with one-click connection."""
    
    # Signals
    server_selected = Signal(str)  # Server ID
    server_recommended = Signal(str, float, str)  # Server ID, score, reason
    quick_connect_requested = Signal()  # One-click connect
    
    def __init__(self):
        super().__init__()
        self.logger = setup_logger("smart_server_selector", "INFO")
        
        # Data storage
        self.servers: Dict[str, ServerMetrics] = {}
        self.user_preferences = UserPreferences(
            preferred_protocols=["openvpn", "wireguard"],
            preferred_regions=[],
            max_ping_threshold=200,
            min_speed_threshold=10,
            avoid_high_load=True,
            prefer_reliable=True,
            favorite_servers=[],
            blocked_servers=[],
            recent_connections=[],
            connection_history={}
        )
        
        # Recommendation engine
        self.recommendation_weights = {
            'performance': 0.3,
            'location': 0.2,
            'load': 0.2,
            'reliability': 0.2,
            'user_preference': 0.1
        }
        
        # UI state
        self.selected_server: Optional[str] = None
        self.recommendations: List[RecommendationScore] = []
        self.current_filter = "all"
        
        # Colors and styling
        self.setup_colors()
        
        # Setup UI
        self.setup_ui()
        
        # Load data
        self.load_user_preferences()
        self.load_sample_servers()
        
        # Update recommendations
        self.update_recommendations()
        
        # Setup update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_server_metrics)
        self.update_timer.start(5000)  # Update every 5 seconds
    
    def setup_colors(self) -> None:
        """Setup color scheme."""
        self.bg_color = QColor(20, 30, 48)
        self.card_color = QColor(46, 64, 83)
        self.accent_color = QColor(76, 175, 80)
        self.warning_color = QColor(255, 152, 0)
        self.error_color = QColor(244, 67, 54)
        self.text_color = QColor(255, 255, 255)
        self.text_secondary = QColor(176, 190, 197)
    
    def setup_ui(self) -> None:
        """Setup the user interface."""
        layout = QVBoxLayout(self)
        
        # Quick connect section
        quick_connect_section = self.create_quick_connect_section()
        layout.addWidget(quick_connect_section)
        
        # Recommendations section
        recommendations_section = self.create_recommendations_section()
        layout.addWidget(recommendations_section)
        
        # Server list section
        server_list_section = self.create_server_list_section()
        layout.addWidget(server_list_section)
        
        # Preferences section
        preferences_section = self.create_preferences_section()
        layout.addWidget(preferences_section)
    
    def create_quick_connect_section(self) -> QWidget:
        """Create the quick connect section."""
        section = QFrame()
        section.setFrameStyle(QFrame.Box)
        section.setStyleSheet("""
            QFrame {
                background-color: #2E4053;
                border: 1px solid #4A5568;
                border-radius: 8px;
                padding: 15px;
                margin: 5px;
            }
        """)
        
        layout = QVBoxLayout(section)
        
        # Title
        title = QLabel("Quick Connect")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: white; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # Quick connect buttons
        buttons_layout = QHBoxLayout()
        
        # Smart Connect button
        self.smart_connect_btn = QPushButton("🚀 Smart Connect")
        self.smart_connect_btn.clicked.connect(self.smart_connect)
        self.smart_connect_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        buttons_layout.addWidget(self.smart_connect_btn)
        
        # Optimal Server button
        self.optimal_server_btn = QPushButton("⚡ Optimal Server")
        self.optimal_server_btn.clicked.connect(self.connect_optimal)
        self.optimal_server_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        buttons_layout.addWidget(self.optimal_server_btn)
        
        # Recent Server button
        self.recent_server_btn = QPushButton("🕐 Recent Server")
        self.recent_server_btn.clicked.connect(self.connect_recent)
        self.recent_server_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
        """)
        buttons_layout.addWidget(self.recent_server_btn)
        
        buttons_layout.addStretch()
        layout.addLayout(buttons_layout)
        
        # Current connection info
        self.connection_info_label = QLabel("Not connected")
        self.connection_info_label.setStyleSheet("color: #B0BEC5; font-size: 12px; margin-top: 10px;")
        layout.addWidget(self.connection_info_label)
        
        return section
    
    def create_recommendations_section(self) -> QWidget:
        """Create the recommendations section."""
        section = QFrame()
        section.setFrameStyle(QFrame.Box)
        section.setStyleSheet("""
            QFrame {
                background-color: #2E4053;
                border: 1px solid #4A5568;
                border-radius: 8px;
                padding: 15px;
                margin: 5px;
            }
        """)
        
        layout = QVBoxLayout(section)
        
        # Title
        title = QLabel("Recommended Servers")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: white; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # Recommendations list
        self.recommendations_list = QListWidget()
        self.recommendations_list.setStyleSheet("""
            QListWidget {
                background-color: #1E2A38;
                border: 1px solid #4A5568;
                border-radius: 4px;
                padding: 5px;
            }
            QListWidget::item {
                background-color: #2E4053;
                border: 1px solid #4A5568;
                border-radius: 4px;
                padding: 8px;
                margin: 2px;
            }
            QListWidget::item:hover {
                background-color: #3A4A5C;
                border-color: #4CAF50;
            }
            QListWidget::item:selected {
                background-color: #4CAF50;
                border-color: #45a049;
            }
        """)
        self.recommendations_list.itemDoubleClicked.connect(self.on_recommendation_selected)
        layout.addWidget(self.recommendations_list)
        
        return section
    
    def create_server_list_section(self) -> QWidget:
        """Create the server list section."""
        section = QFrame()
        section.setFrameStyle(QFrame.Box)
        section.setStyleSheet("""
            QFrame {
                background-color: #2E4053;
                border: 1px solid #4A5568;
                border-radius: 8px;
                padding: 15px;
                margin: 5px;
            }
        """)
        
        layout = QVBoxLayout(section)
        
        # Search and filter
        filter_layout = QHBoxLayout()
        
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search servers...")
        self.search_box.textChanged.connect(self.filter_servers)
        self.search_box.setStyleSheet("""
            QLineEdit {
                background-color: #1E2A38;
                border: 1px solid #4A5568;
                border-radius: 4px;
                padding: 8px;
                color: white;
                font-size: 12px;
            }
        """)
        filter_layout.addWidget(self.search_box)
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Servers", "Favorites", "Recent", "Optimal", "Region"])
        self.filter_combo.currentTextChanged.connect(self.filter_servers)
        self.filter_combo.setStyleSheet("""
            QComboBox {
                background-color: #1E2A38;
                border: 1px solid #4A5568;
                border-radius: 4px;
                padding: 8px;
                color: white;
                font-size: 12px;
            }
        """)
        filter_layout.addWidget(self.filter_combo)
        
        layout.addLayout(filter_layout)
        
        # Server list
        self.server_list = QListWidget()
        self.server_list.setStyleSheet("""
            QListWidget {
                background-color: #1E2A38;
                border: 1px solid #4A5568;
                border-radius: 4px;
                padding: 5px;
            }
            QListWidget::item {
                background-color: #2E4053;
                border: 1px solid #4A5568;
                border-radius: 4px;
                padding: 10px;
                margin: 2px;
            }
            QListWidget::item:hover {
                background-color: #3A4A5C;
                border-color: #2196F3;
            }
            QListWidget::item:selected {
                background-color: #2196F3;
                border-color: #1976D2;
            }
        """)
        self.server_list.itemDoubleClicked.connect(self.on_server_selected)
        layout.addWidget(self.server_list)
        
        return section
    
    def create_preferences_section(self) -> QWidget:
        """Create the preferences section."""
        section = QFrame()
        section.setFrameStyle(QFrame.Box)
        section.setStyleSheet("""
            QFrame {
                background-color: #2E4053;
                border: 1px solid #4A5568;
                border-radius: 8px;
                padding: 15px;
                margin: 5px;
            }
        """)
        
        layout = QVBoxLayout(section)
        
        # Title
        title = QLabel("Selection Preferences")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: white; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # Preference controls
        prefs_layout = QGridLayout()
        
        # Max ping threshold
        ping_label = QLabel("Max Ping (ms):")
        ping_label.setStyleSheet("color: white;")
        prefs_layout.addWidget(ping_label, 0, 0)
        
        self.ping_spinbox = QSpinBox()
        self.ping_spinbox.setRange(50, 1000)
        self.ping_spinbox.setValue(self.user_preferences.max_ping_threshold)
        self.ping_spinbox.valueChanged.connect(self.update_preferences)
        self.ping_spinbox.setStyleSheet("""
            QSpinBox {
                background-color: #1E2A38;
                border: 1px solid #4A5568;
                border-radius: 4px;
                padding: 5px;
                color: white;
            }
        """)
        prefs_layout.addWidget(self.ping_spinbox, 0, 1)
        
        # Min speed threshold
        speed_label = QLabel("Min Speed (Mbps):")
        speed_label.setStyleSheet("color: white;")
        prefs_layout.addWidget(speed_label, 1, 0)
        
        self.speed_spinbox = QSpinBox()
        self.speed_spinbox.setRange(1, 1000)
        self.speed_spinbox.setValue(self.user_preferences.min_speed_threshold)
        self.speed_spinbox.valueChanged.connect(self.update_preferences)
        self.speed_spinbox.setStyleSheet("""
            QSpinBox {
                background-color: #1E2A38;
                border: 1px solid #4A5568;
                border-radius: 4px;
                padding: 5px;
                color: white;
            }
        """)
        prefs_layout.addWidget(self.speed_spinbox, 1, 1)
        
        # Avoid high load
        self.avoid_load_check = QCheckBox("Avoid High Load Servers")
        self.avoid_load_check.setChecked(self.user_preferences.avoid_high_load)
        self.avoid_load_check.toggled.connect(self.update_preferences)
        self.avoid_load_check.setStyleSheet("color: white;")
        prefs_layout.addWidget(self.avoid_load_check, 2, 0, 1, 2)
        
        layout.addLayout(prefs_layout)
        
        return section
    
    def load_user_preferences(self) -> None:
        """Load user preferences from file."""
        try:
            prefs_file = Path("config/user_preferences.json")
            if prefs_file.exists():
                with open(prefs_file, 'r') as f:
                    prefs_data = json.load(f)
                
                # Update preferences
                for key, value in prefs_data.items():
                    if hasattr(self.user_preferences, key):
                        setattr(self.user_preferences, key, value)
                
                self.logger.info("User preferences loaded")
            
        except Exception as e:
            self.logger.error(f"Failed to load user preferences: {e}")
    
    def save_user_preferences(self) -> None:
        """Save user preferences to file."""
        try:
            prefs_file = Path("config/user_preferences.json")
            prefs_file.parent.mkdir(parents=True, exist_ok=True)
            
            prefs_data = {
                'preferred_protocols': self.user_preferences.preferred_protocols,
                'preferred_regions': self.user_preferences.preferred_regions,
                'max_ping_threshold': self.user_preferences.max_ping_threshold,
                'min_speed_threshold': self.user_preferences.min_speed_threshold,
                'avoid_high_load': self.user_preferences.avoid_high_load,
                'prefer_reliable': self.user_preferences.prefer_reliable,
                'favorite_servers': self.user_preferences.favorite_servers,
                'blocked_servers': self.user_preferences.blocked_servers,
                'recent_connections': self.user_preferences.recent_connections[-10:],  # Keep last 10
                'connection_history': {k: list(v)[-10:] for k, v in self.user_preferences.connection_history.items()}
            }
            
            with open(prefs_file, 'w') as f:
                json.dump(prefs_data, f, indent=2)
            
            self.logger.info("User preferences saved")
            
        except Exception as e:
            self.logger.error(f"Failed to save user preferences: {e}")
    
    def load_sample_servers(self) -> None:
        """Load sample server data."""
        sample_servers = [
            ServerMetrics(
                server_id="us_ny_1", name="US New York 1", country="United States", city="New York",
                latitude=40.7128, longitude=-74.0060, load=25, ping=45, 
                download_speed=85, upload_speed=42, reliability=98.5, uptime=99.9,
                user_count=450, max_users=1000, protocol="openvpn", is_premium=True,
                region="North America", recent_pings=deque([45, 47, 43, 46, 44], maxlen=100),
                recent_speeds=deque([85, 87, 83, 86, 84], maxlen=50),
                connection_success_rate=0.98, average_session_duration=3600
            ),
            ServerMetrics(
                server_id="uk_london_1", name="UK London 1", country="United Kingdom", city="London",
                latitude=51.5074, longitude=-0.1278, load=45, ping=85,
                download_speed=78, upload_speed=38, reliability=97.2, uptime=99.5,
                user_count=620, max_users=1000, protocol="wireguard", is_premium=False,
                region="Europe", recent_pings=deque([85, 87, 83, 86, 84], maxlen=100),
                recent_speeds=deque([78, 80, 76, 79, 77], maxlen=50),
                connection_success_rate=0.96, average_session_duration=2700
            ),
            ServerMetrics(
                server_id="de_frankfurt_1", name="Germany Frankfurt 1", country="Germany", city="Frankfurt",
                latitude=50.1109, longitude=8.6821, load=65, ping=120,
                download_speed=65, upload_speed=32, reliability=95.8, uptime=98.8,
                user_count=780, max_users=1000, protocol="openvpn", is_premium=True,
                region="Europe", recent_pings=deque([120, 122, 118, 121, 119], maxlen=100),
                recent_speeds=deque([65, 67, 63, 66, 64], maxlen=50),
                connection_success_rate=0.94, average_session_duration=2400
            ),
            ServerMetrics(
                server_id="jp_tokyo_1", name="Japan Tokyo 1", country="Japan", city="Tokyo",
                latitude=35.6762, longitude=139.6503, load=35, ping=150,
                download_speed=92, upload_speed=48, reliability=99.1, uptime=99.7,
                user_count=320, max_users=1000, protocol="wireguard", is_premium=True,
                region="Asia", recent_pings=deque([150, 152, 148, 151, 149], maxlen=100),
                recent_speeds=deque([92, 94, 90, 93, 91], maxlen=50),
                connection_success_rate=0.99, average_session_duration=4200
            ),
            ServerMetrics(
                server_id="au_sydney_1", name="Australia Sydney 1", country="Australia", city="Sydney",
                latitude=-33.8688, longitude=151.2093, load=55, ping=180,
                download_speed=58, upload_speed=28, reliability=94.5, uptime=98.2,
                user_count=280, max_users=800, protocol="openvpn", is_premium=False,
                region="Oceania", recent_pings=deque([180, 182, 178, 181, 179], maxlen=100),
                recent_speeds=deque([58, 60, 56, 59, 57], maxlen=50),
                connection_success_rate=0.92, average_session_duration=1800
            )
        ]
        
        for server in sample_servers:
            self.servers[server.server_id] = server
    
    def update_recommendations(self) -> None:
        """Update server recommendations."""
        self.recommendations = []
        
        for server_id, server in self.servers.items():
            if server_id in self.user_preferences.blocked_servers:
                continue
            
            # Calculate recommendation score
            score = self.calculate_recommendation_score(server)
            self.recommendations.append(score)
        
        # Sort by score
        self.recommendations.sort(key=lambda x: x.total_score, reverse=True)
        
        # Update UI
        self.update_recommendations_list()
    
    def calculate_recommendation_score(self, server: ServerMetrics) -> RecommendationScore:
        """Calculate recommendation score for a server."""
        # Performance score (0-100)
        performance_score = self._calculate_performance_score(server)
        
        # Location score (0-100)
        location_score = self._calculate_location_score(server)
        
        # Load score (0-100)
        load_score = self._calculate_load_score(server)
        
        # Reliability score (0-100)
        reliability_score = self._calculate_reliability_score(server)
        
        # User preference score (0-100)
        user_preference_score = self._calculate_user_preference_score(server)
        
        # Weighted total score
        total_score = (
            performance_score * self.recommendation_weights['performance'] +
            location_score * self.recommendation_weights['location'] +
            load_score * self.recommendation_weights['load'] +
            reliability_score * self.recommendation_weights['reliability'] +
            user_preference_score * self.recommendation_weights['user_preference']
        )
        
        # Generate recommendation reason
        reason = self._generate_recommendation_reason(server, performance_score, 
                                               location_score, load_score, 
                                               reliability_score, user_preference_score)
        
        return RecommendationScore(
            server_id=server.server_id,
            total_score=total_score,
            performance_score=performance_score,
            location_score=location_score,
            load_score=load_score,
            reliability_score=reliability_score,
            user_preference_score=user_preference_score,
            recommendation_reason=reason
        )
    
    def _calculate_performance_score(self, server: ServerMetrics) -> float:
        """Calculate performance score."""
        # Speed score
        speed_score = min(100, (server.download_speed / 100) * 50)
        
        # Ping score (inverse - lower ping is better)
        ping_score = max(0, 100 - (server.ping / 300) * 50)
        
        return speed_score + ping_score
    
    def _calculate_location_score(self, server: ServerMetrics) -> float:
        """Calculate location-based score."""
        # Would use user's actual location in production
        # For now, prefer servers in preferred regions
        if server.region in self.user_preferences.preferred_regions:
            return 100
        elif self.user_preferences.preferred_regions:
            return 50  # Neutral if user has preferences but server not in them
        else:
            return 80  # Good default if no preferences
    
    def _calculate_load_score(self, server: ServerMetrics) -> float:
        """Calculate load score."""
        if self.user_preferences.avoid_high_load:
            # Penalize high load servers more heavily
            if server.load < 30:
                return 100
            elif server.load < 60:
                return 70
            elif server.load < 80:
                return 40
            else:
                return 10
        else:
            # Standard load scoring
            return max(0, 100 - server.load)
    
    def _calculate_reliability_score(self, server: ServerMetrics) -> float:
        """Calculate reliability score."""
        # Combine reliability and uptime
        reliability_component = server.reliability
        uptime_component = server.uptime
        
        # Connection success rate
        success_component = server.connection_success_rate * 100
        
        return (reliability_component + uptime_component + success_component) / 3
    
    def _calculate_user_preference_score(self, ServerMetrics) -> float:
        """Calculate user preference score."""
        score = 50  # Base score
        
        # Protocol preference
        if server.protocol in self.user_preferences.preferred_protocols:
            score += 20
        
        # Favorite server
        if server.server_id in self.user_preferences.favorite_servers:
            score += 30
        
        # Recent connections
        if server.server_id in self.user_preferences.recent_connections:
            score += 10
        
        # Premium preference (if user tends to connect to premium servers)
        recent_premium_count = sum(1 for sid in self.user_preferences.recent_connections 
                                if sid in self.servers and self.servers[sid].is_premium)
        if recent_premium_count > len(self.user_preferences.recent_connections) / 2:
            if server.is_premium:
                score += 10
            else:
                score -= 10
        
        return min(100, score)
    
    def _generate_recommendation_reason(self, server: ServerMetrics, performance_score: float,
                                   location_score: float, load_score: float,
                                   reliability_score: float, user_preference_score: float) -> str:
        """Generate human-readable recommendation reason."""
        reasons = []
        
        if performance_score > 80:
            reasons.append("Excellent performance")
        elif performance_score > 60:
            reasons.append("Good performance")
        
        if location_score > 80:
            reasons.append("In preferred region")
        
        if load_score > 80:
            reasons.append("Low server load")
        
        if reliability_score > 90:
            reasons.append("Highly reliable")
        
        if user_preference_score > 80:
            reasons.append("Matches your preferences")
        
        if server.is_premium:
            reasons.append("Premium server")
        
        if not reasons:
            reasons.append("Available server")
        
        return " • ".join(reasons[:3])  # Limit to top 3 reasons
    
    def update_recommendations_list(self) -> None:
        """Update the recommendations list UI."""
        self.recommendations_list.clear()
        
        for i, rec in enumerate(self.recommendations[:10]):  # Top 10 recommendations
            server = self.servers[rec.server_id]
            
            item_text = f"{server.city}, {server.country}"
            if server.is_premium:
                item_text += " ⭐"
            
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, rec.server_id)
            
            # Set color based on score
            if rec.total_score > 80:
                item.setForeground(QColor(76, 175, 80))  # Green
            elif rec.total_score > 60:
                item.setForeground(QColor(33, 150, 243))  # Blue
            elif rec.total_score > 40:
                item.setForeground(QColor(255, 152, 0))  # Orange
            else:
                item.setForeground(QColor(244, 67, 54))  # Red
            
            self.recommendations_list.addItem(item)
    
    def smart_connect(self) -> None:
        """Smart connect to the best server."""
        if not self.recommendations:
            self.update_recommendations()
        
        if self.recommendations:
            best_server = self.recommendations[0]
            self.connect_to_server(best_server.server_id)
            self.quick_connect_requested.emit()
    
    def connect_optimal(self) -> None:
        """Connect to the optimal server based on current metrics."""
        # Find server with best combination of low ping and high speed
        optimal_server = None
        best_score = -1
        
        for server in self.servers.values():
            if server.server_id in self.user_preferences.blocked_servers:
                continue
            
            # Calculate optimal score (ping + speed balance)
            ping_score = max(0, 100 - server.ping / 2)  # Normalize ping
            speed_score = min(100, server.download_speed)
            optimal_score = ping_score + speed_score
            
            if optimal_score > best_score:
                best_score = optimal_score
                optimal_server = server
        
        if optimal_server:
            self.connect_to_server(optimal_server.server_id)
    
    def connect_recent(self) -> None:
        """Connect to the most recently used server."""
        if self.user_preferences.recent_connections:
            recent_server_id = self.user_preferences.recent_connections[0]
            self.connect_to_server(recent_server_id)
    
    def connect_to_server(self, server_id: str) -> None:
        """Connect to a specific server."""
        if server_id not in self.servers:
            return
        
        self.selected_server = server_id
        self.server_selected.emit(server_id)
        
        # Update recent connections
        if server_id in self.user_preferences.recent_connections:
            self.user_preferences.recent_connections.remove(server_id)
        self.user_preferences.recent_connections.insert(0, server_id)
        
        # Update connection history
        if server_id not in self.user_preferences.connection_history:
            self.user_preferences.connection_history[server_id] = []
        self.user_preferences.connection_history[server_id].append(time.time())
        
        # Save preferences
        self.save_user_preferences()
        
        # Update UI
        server = self.servers[server_id]
        self.connection_info_label.setText(
            f"Connecting to {server.city}, {server.country}..."
        )
    
    def on_recommendation_selected(self, item: QListWidgetItem) -> None:
        """Handle recommendation selection."""
        server_id = item.data(Qt.UserRole)
        if server_id:
            self.connect_to_server(server_id)
    
    def on_server_selected(self, item: QListWidgetItem) -> None:
        """Handle server selection."""
        server_id = item.data(Qt.UserRole)
        if server_id:
            self.connect_to_server(server_id)
    
    def filter_servers(self) -> None:
        """Filter servers based on search and filter criteria."""
        search_text = self.search_box.text().lower()
        filter_type = self.filter_combo.currentText().lower()
        
        filtered_servers = []
        
        for server_id, server in self.servers.items():
            # Skip blocked servers
            if server_id in self.user_preferences.blocked_servers:
                continue
            
            # Apply search filter
            if search_text:
                if (search_text not in server.name.lower() and
                    search_text not in server.country.lower() and
                    search_text not in server.city.lower()):
                    continue
            
            # Apply type filter
            if filter_type == "favorites":
                if server_id not in self.user_preferences.favorite_servers:
                    continue
            elif filter_type == "recent":
                if server_id not in self.user_preferences.recent_connections:
                    continue
            elif filter_type == "optimal":
                # Check if server meets optimal criteria
                if server.load > 50 or server.ping > 150:
                    continue
            
            filtered_servers.append(server)
        
        # Update server list
        self.update_server_list(filtered_servers)
    
    def update_server_list(self, servers: List[ServerMetrics]) -> None:
        """Update the server list UI."""
        self.server_list.clear()
        
        for server in servers:
            item_text = f"{server.city}, {server.country}"
            
            # Add status indicators
            if server.is_premium:
                item_text += " ⭐"
            if server.server_id in self.user_preferences.favorite_servers:
                item_text += " ★"
            
            # Add performance indicators
            if server.load < 30 and server.ping < 100:
                item_text += " 🟢"  # Green
            elif server.load < 60 and server.ping < 200:
                item_text += " 🟡"  # Yellow
            else:
                item_text += " 🔴"  # Red
            
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, server.server_id)
            
            # Add tooltip with detailed info
            tooltip = f"""
            <b>{server.city}, {server.country}</b><br>
            Load: {server.load:.1f}%<br>
            Ping: {server.ping:.0f}ms<br>
            Download: {server.download_speed:.0f} Mbps<br>
            Upload: {server.upload_speed:.0f} Mbps<br>
            Reliability: {server.reliability:.1f}%<br>
            Users: {server.user_count}/{server.max_users}<br>
            Protocol: {server.protocol.upper()}
            """
            item.setToolTip(tooltip.strip())
            
            self.server_list.addItem(item)
    
    def update_preferences(self) -> None:
        """Update user preferences from UI."""
        self.user_preferences.max_ping_threshold = self.ping_spinbox.value()
        self.user_preferences.min_speed_threshold = self.speed_spinbox.value()
        self.user_preferences.avoid_high_load = self.avoid_load_check.isChecked()
        
        # Save and update recommendations
        self.save_user_preferences()
        self.update_recommendations()
    
    def update_server_metrics(self) -> None:
        """Update server metrics (simulated)."""
        import random
        
        for server in self.servers.values():
            # Simulate metric changes
            server.load = max(0, min(100, server.load + random.uniform(-5, 5)))
            server.ping = max(10, server.ping + random.uniform(-10, 10))
            server.user_count = max(0, min(server.max_users, 
                                           server.user_count + random.randint(-50, 50)))
            
            # Update recent metrics
            server.recent_pings.append(server.ping)
            server.recent_speeds.append(server.download_speed)
        
        # Update recommendations
        self.update_recommendations()
    
    def get_server_recommendations(self, limit: int = 5) -> List[RecommendationScore]:
        """Get top server recommendations."""
        return self.recommendations[:limit]
    
    def add_server_to_favorites(self, server_id: str) -> None:
        """Add a server to favorites."""
        if server_id not in self.user_preferences.favorite_servers:
            self.user_preferences.favorite_servers.append(server_id)
            self.save_user_preferences()
            self.update_recommendations()
    
    def remove_server_from_favorites(self, server_id: str) -> None:
        """Remove a server from favorites."""
        if server_id in self.user_preferences.favorite_servers:
            self.user_preferences.favorite_servers.remove(server_id)
            self.save_user_preferences()
            self.update_recommendations()
    
    def block_server(self, server_id: str) -> None:
        """Block a server."""
        if server_id not in self.user_preferences.blocked_servers:
            self.user_preferences.blocked_servers.append(server_id)
            self.save_user_preferences()
            self.update_recommendations()


# Example usage
if __name__ == "__main__":
    import sys
    from PySide6.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    
    # Create smart server selector
    selector = SmartServerSelector()
    selector.show()
    
    sys.exit(app.exec())
