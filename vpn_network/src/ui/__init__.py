#!/usr/bin/env python3
"""
Enhanced UI Package for VPN
Modern interface components with server location map, speed graphs, and one-click selection.
"""

from .enhanced_ui import EnhancedVPNGUI
from .server_map_widget import AdvancedServerMapWidget, MapServer
from .speed_graph_widget import AdvancedSpeedGraphWidget, SpeedDataPoint, SpeedStatistics
from .server_selector import SmartServerSelector, ServerMetrics, RecommendationScore

__all__ = [
    'EnhancedVPNGUI',
    'AdvancedServerMapWidget',
    'MapServer',
    'AdvancedSpeedGraphWidget',
    'SpeedDataPoint',
    'SpeedStatistics',
    'SmartServerSelector',
    'ServerMetrics',
    'RecommendationScore'
]

VERSION = "1.0.0"
