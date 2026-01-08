"""
Server Registry Module for VPN Security Project.
This module maintains a persistent registry of VPN servers with
metadata, statistics, and historical data.
"""
import os
import json
import time
import sqlite3
import threading
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from contextlib import contextmanager

from discovery.server_discovery import VPNServer, ServerStatus
from utils.logger import LoggableMixin


@dataclass
class ServerMetrics:
    """Server performance metrics."""
    server_id: str
    timestamp: float
    response_time: float  # milliseconds
    bandwidth_mbps: float
    packet_loss: float  # 0.0 to 1.0
    uptime: float  # 0.0 to 1.0
    cpu_usage: float  # 0.0 to 1.0
    memory_usage: float  # 0.0 to 1.0
    active_connections: int
    error_rate: float  # 0.0 to 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class ServerHistory:
    """Historical data for a server."""
    server_id: str
    first_seen: float
    last_seen: float
    total_uptime: float  # total seconds online
    total_downtime: float  # total seconds offline
    connection_count: int
    successful_connections: int
    failed_connections: int
    average_response_time: float
    peak_bandwidth: float
    last_error: Optional[str] = None
    last_error_time: Optional[float] = None
    
    @property
    def success_rate(self) -> float:
        """Calculate connection success rate."""
        if self.connection_count == 0:
            return 0.0
        return self.successful_connections / self.connection_count
    
    @property
    def uptime_percentage(self) -> float:
        """Calculate uptime percentage."""
        total_time = self.total_uptime + self.total_downtime
        if total_time == 0:
            return 0.0
        return (self.total_uptime / total_time) * 100.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data['success_rate'] = self.success_rate
        data['uptime_percentage'] = self.uptime_percentage
        return data


class ServerRegistry(LoggableMixin):
    """Persistent server registry with SQLite backend."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.registry_config = config.get('registry', {})
        
        # Database configuration
        self.db_path = self.registry_config.get('database_path', 'data/vpn_servers.db')
        self.auto_cleanup = self.registry_config.get('auto_cleanup', True)
        self.retention_days = self.registry_config.get('retention_days', 30)
        
        # Memory cache
        self._servers_cache: Dict[str, VPNServer] = {}
        self._history_cache: Dict[str, ServerHistory] = {}
        self._cache_lock = threading.RLock()
        
        # Initialize database
        self._init_database()
        
        # Load existing servers
        self._load_servers()
        
        # Start cleanup thread if enabled
        if self.auto_cleanup:
            self._start_cleanup_thread()
    
    def _init_database(self):
        """Initialize SQLite database with required tables."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Servers table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS servers (
                    server_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    region TEXT NOT NULL,
                    country TEXT NOT NULL,
                    city TEXT NOT NULL,
                    latitude REAL NOT NULL,
                    longitude REAL NOT NULL,
                    load REAL DEFAULT 0.0,
                    status TEXT NOT NULL,
                    last_checked REAL DEFAULT 0.0,
                    response_time REAL DEFAULT 0.0,
                    bandwidth_mbps REAL DEFAULT 0.0,
                    max_clients INTEGER DEFAULT 100,
                    current_clients INTEGER DEFAULT 0,
                    supported_ciphers TEXT,  -- JSON array
                    features TEXT,  -- JSON object
                    public_key TEXT,
                    certificate_fingerprint TEXT,
                    created_at REAL DEFAULT (strftime('%s', 'now')),
                    updated_at REAL DEFAULT (strftime('%s', 'now'))
                )
            ''')
            
            # Server metrics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS server_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    response_time REAL NOT NULL,
                    bandwidth_mbps REAL NOT NULL,
                    packet_loss REAL NOT NULL,
                    uptime REAL NOT NULL,
                    cpu_usage REAL NOT NULL,
                    memory_usage REAL NOT NULL,
                    active_connections INTEGER NOT NULL,
                    error_rate REAL NOT NULL,
                    FOREIGN KEY (server_id) REFERENCES servers (server_id)
                )
            ''')
            
            # Server history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS server_history (
                    server_id TEXT PRIMARY KEY,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    total_uptime REAL DEFAULT 0.0,
                    total_downtime REAL DEFAULT 0.0,
                    connection_count INTEGER DEFAULT 0,
                    successful_connections INTEGER DEFAULT 0,
                    failed_connections INTEGER DEFAULT 0,
                    average_response_time REAL DEFAULT 0.0,
                    peak_bandwidth REAL DEFAULT 0.0,
                    last_error TEXT,
                    last_error_time REAL,
                    FOREIGN KEY (server_id) REFERENCES servers (server_id)
                )
            ''')
            
            # Create indexes for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_servers_status ON servers (status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_servers_protocol ON servers (protocol)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_servers_region ON servers (region)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON server_metrics (timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_server_id ON server_metrics (server_id)')
            
            conn.commit()
    
    @contextmanager
    def _get_db_connection(self):
        """Get database connection with proper error handling."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row
            yield conn
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            self.logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def _load_servers(self):
        """Load all servers from database into cache."""
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Load servers
            cursor.execute('SELECT * FROM servers')
            for row in cursor.fetchall():
                server = self._row_to_server(row)
                self._servers_cache[server.server_id] = server
            
            # Load history
            cursor.execute('SELECT * FROM server_history')
            for row in cursor.fetchall():
                history = self._row_to_history(row)
                self._history_cache[history.server_id] = history
        
        self.logger.info(f"Loaded {len(self._servers_cache)} servers from registry")
    
    def _row_to_server(self, row: sqlite3.Row) -> VPNServer:
        """Convert database row to VPNServer object."""
        supported_ciphers = json.loads(row['supported_ciphers']) if row['supported_ciphers'] else []
        features = json.loads(row['features']) if row['features'] else {}
        
        return VPNServer(
            server_id=row['server_id'],
            hostname=row['hostname'],
            ip_address=row['ip_address'],
            port=row['port'],
            protocol=row['protocol'],
            region=row['region'],
            country=row['country'],
            city=row['city'],
            latitude=row['latitude'],
            longitude=row['longitude'],
            load=row['load'],
            status=ServerStatus[row['status']],
            last_checked=row['last_checked'],
            response_time=row['response_time'],
            bandwidth_mbps=row['bandwidth_mbps'],
            max_clients=row['max_clients'],
            current_clients=row['current_clients'],
            supported_ciphers=supported_ciphers,
            features=features,
            public_key=row['public_key'],
            certificate_fingerprint=row['certificate_fingerprint']
        )
    
    def _row_to_history(self, row: sqlite3.Row) -> ServerHistory:
        """Convert database row to ServerHistory object."""
        return ServerHistory(
            server_id=row['server_id'],
            first_seen=row['first_seen'],
            last_seen=row['last_seen'],
            total_uptime=row['total_uptime'],
            total_downtime=row['total_downtime'],
            connection_count=row['connection_count'],
            successful_connections=row['successful_connections'],
            failed_connections=row['failed_connections'],
            average_response_time=row['average_response_time'],
            peak_bandwidth=row['peak_bandwidth'],
            last_error=row['last_error'],
            last_error_time=row['last_error_time']
        )
    
    def register_server(self, server: VPNServer) -> bool:
        """Register or update a server in the registry."""
        try:
            with self._cache_lock:
                current_time = time.time()
                server.last_checked = current_time
                
                # Update cache
                self._servers_cache[server.server_id] = server
                
                # Update or insert in database
                with self._get_db_connection() as conn:
                    cursor = conn.cursor()
                    
                    cursor.execute('''
                        INSERT OR REPLACE INTO servers (
                            server_id, hostname, ip_address, port, protocol,
                            region, country, city, latitude, longitude,
                            load, status, last_checked, response_time,
                            bandwidth_mbps, max_clients, current_clients,
                            supported_ciphers, features, public_key,
                            certificate_fingerprint, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        server.server_id, server.hostname, server.ip_address,
                        server.port, server.protocol, server.region,
                        server.country, server.city, server.latitude,
                        server.longitude, server.load, server.status.name,
                        server.last_checked, server.response_time,
                        server.bandwidth_mbps, server.max_clients,
                        server.current_clients, json.dumps(server.supported_ciphers),
                        json.dumps(server.features), server.public_key,
                        server.certificate_fingerprint, current_time
                    ))
                    
                    # Update history
                    self._update_server_history(server.server_id, current_time)
                    
                    conn.commit()
                
                self.logger.debug(f"Registered server: {server.server_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to register server {server.server_id}: {e}")
            return False
    
    def _update_server_history(self, server_id: str, timestamp: float):
        """Update server history record."""
        history = self._history_cache.get(server_id)
        
        if history is None:
            # Create new history record
            history = ServerHistory(
                server_id=server_id,
                first_seen=timestamp,
                last_seen=timestamp,
                connection_count=0,
                successful_connections=0,
                failed_connections=0,
                average_response_time=0.0,
                peak_bandwidth=0.0
            )
            self._history_cache[server_id] = history
        else:
            # Update existing record
            history.last_seen = timestamp
        
        # Save to database
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO server_history (
                    server_id, first_seen, last_seen, total_uptime,
                    total_downtime, connection_count, successful_connections,
                    failed_connections, average_response_time, peak_bandwidth,
                    last_error, last_error_time
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                history.server_id, history.first_seen, history.last_seen,
                history.total_uptime, history.total_downtime,
                history.connection_count, history.successful_connections,
                history.failed_connections, history.average_response_time,
                history.peak_bandwidth, history.last_error, history.last_error_time
            ))
    
    def record_connection_attempt(self, server_id: str, success: bool, 
                                response_time: float = 0.0, error: str = None):
        """Record a connection attempt to a server."""
        try:
            with self._cache_lock:
                history = self._history_cache.get(server_id)
                if not history:
                    return
                
                # Update connection statistics
                history.connection_count += 1
                if success:
                    history.successful_connections += 1
                    # Update average response time
                    if response_time > 0:
                        total_time = history.average_response_time * (history.successful_connections - 1) + response_time
                        history.average_response_time = total_time / history.successful_connections
                else:
                    history.failed_connections += 1
                    history.last_error = error
                    history.last_error_time = time.time()
                
                # Update database
                with self._get_db_connection() as conn:
                    cursor = conn.cursor()
                    
                    cursor.execute('''
                        UPDATE server_history
                        SET connection_count = ?, successful_connections = ?,
                            failed_connections = ?, average_response_time = ?,
                            last_error = ?, last_error_time = ?
                        WHERE server_id = ?
                    ''', (
                        history.connection_count, history.successful_connections,
                        history.failed_connections, history.average_response_time,
                        history.last_error, history.last_error_time, server_id
                    ))
                    
                    conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to record connection attempt: {e}")
    
    def add_metrics(self, metrics: ServerMetrics):
        """Add performance metrics for a server."""
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO server_metrics (
                        server_id, timestamp, response_time, bandwidth_mbps,
                        packet_loss, uptime, cpu_usage, memory_usage,
                        active_connections, error_rate
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metrics.server_id, metrics.timestamp, metrics.response_time,
                    metrics.bandwidth_mbps, metrics.packet_loss, metrics.uptime,
                    metrics.cpu_usage, metrics.memory_usage,
                    metrics.active_connections, metrics.error_rate
                ))
                
                conn.commit()
                
                # Update server cache with latest metrics
                with self._cache_lock:
                    server = self._servers_cache.get(metrics.server_id)
                    if server:
                        server.response_time = metrics.response_time
                        server.bandwidth_mbps = metrics.bandwidth_mbps
                        server.current_clients = metrics.active_connections
                        server.load = metrics.cpu_usage  # Use CPU as load indicator
                
        except Exception as e:
            self.logger.error(f"Failed to add metrics: {e}")
    
    def get_server(self, server_id: str) -> Optional[VPNServer]:
        """Get a server by ID."""
        with self._cache_lock:
            return self._servers_cache.get(server_id)
    
    def get_all_servers(self) -> List[VPNServer]:
        """Get all registered servers."""
        with self._cache_lock:
            return list(self._servers_cache.values())
    
    def get_servers_by_status(self, status: ServerStatus) -> List[VPNServer]:
        """Get servers by status."""
        with self._cache_lock:
            return [s for s in self._servers_cache.values() if s.status == status]
    
    def get_servers_by_protocol(self, protocol: str) -> List[VPNServer]:
        """Get servers by protocol."""
        with self._cache_lock:
            return [s for s in self._servers_cache.values() 
                   if s.protocol == protocol or s.protocol == 'both']
    
    def get_servers_by_region(self, region: str) -> List[VPNServer]:
        """Get servers by region."""
        with self._cache_lock:
            return [s for s in self._servers_cache.values() 
                   if s.region.lower() == region.lower()]
    
    def get_best_servers(self, count: int = 5, protocol: str = None, 
                        region: str = None) -> List[VPNServer]:
        """Get best servers based on performance metrics."""
        with self._cache_lock:
            candidates = list(self._servers_cache.values())
        
        # Apply filters
        if protocol:
            candidates = [s for s in candidates if s.protocol == protocol or s.protocol == 'both']
        
        if region:
            candidates = [s for s in candidates if s.region.lower() == region.lower()]
        
        # Filter by online status
        candidates = [s for s in candidates if s.status == ServerStatus.ONLINE]
        
        # Sort by performance (load, response time, success rate)
        def server_score(server: VPNServer) -> float:
            history = self._history_cache.get(server.server_id)
            success_rate = history.success_rate if history else 0.0
            
            # Lower score is better
            return (server.load * 0.4 + 
                   (server.response_time / 1000) * 0.3 +  # Convert to seconds
                   (1 - success_rate) * 0.3)
        
        candidates.sort(key=server_score)
        
        return candidates[:count]
    
    def get_server_history(self, server_id: str) -> Optional[ServerHistory]:
        """Get historical data for a server."""
        with self._cache_lock:
            return self._history_cache.get(server_id)
    
    def get_server_metrics(self, server_id: str, hours: int = 24) -> List[ServerMetrics]:
        """Get metrics for a server within the last N hours."""
        try:
            cutoff_time = time.time() - (hours * 3600)
            
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM server_metrics
                    WHERE server_id = ? AND timestamp >= ?
                    ORDER BY timestamp DESC
                ''', (server_id, cutoff_time))
                
                metrics = []
                for row in cursor.fetchall():
                    metric = ServerMetrics(
                        server_id=row['server_id'],
                        timestamp=row['timestamp'],
                        response_time=row['response_time'],
                        bandwidth_mbps=row['bandwidth_mbps'],
                        packet_loss=row['packet_loss'],
                        uptime=row['uptime'],
                        cpu_usage=row['cpu_usage'],
                        memory_usage=row['memory_usage'],
                        active_connections=row['active_connections'],
                        error_rate=row['error_rate']
                    )
                    metrics.append(metric)
                
                return metrics
                
        except Exception as e:
            self.logger.error(f"Failed to get server metrics: {e}")
            return []
    
    def remove_server(self, server_id: str) -> bool:
        """Remove a server from the registry."""
        try:
            with self._cache_lock:
                # Remove from cache
                self._servers_cache.pop(server_id, None)
                self._history_cache.pop(server_id, None)
                
                # Remove from database
                with self._get_db_connection() as conn:
                    cursor = conn.cursor()
                    
                    cursor.execute('DELETE FROM servers WHERE server_id = ?', (server_id,))
                    cursor.execute('DELETE FROM server_metrics WHERE server_id = ?', (server_id,))
                    cursor.execute('DELETE FROM server_history WHERE server_id = ?', (server_id,))
                    
                    conn.commit()
                
                self.logger.info(f"Removed server: {server_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to remove server {server_id}: {e}")
            return False
    
    def get_registry_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        with self._cache_lock:
            total_servers = len(self._servers_cache)
            online_servers = len([s for s in self._servers_cache.values() if s.status == ServerStatus.ONLINE])
            offline_servers = len([s for s in self._servers_cache.values() if s.status == ServerStatus.OFFLINE])
            
            # Protocol distribution
            protocols = {}
            for server in self._servers_cache.values():
                protocols[server.protocol] = protocols.get(server.protocol, 0) + 1
            
            # Region distribution
            regions = {}
            for server in self._servers_cache.values():
                regions[server.region] = regions.get(server.region, 0) + 1
        
        return {
            'total_servers': total_servers,
            'online_servers': online_servers,
            'offline_servers': offline_servers,
            'protocols': protocols,
            'regions': regions,
            'database_path': self.db_path,
            'retention_days': self.retention_days
        }
    
    def _start_cleanup_thread(self):
        """Start background cleanup thread."""
        def cleanup_worker():
            while True:
                try:
                    self._cleanup_old_data()
                    time.sleep(24 * 3600)  # Run daily
                except Exception as e:
                    self.logger.error(f"Cleanup thread error: {e}")
                    time.sleep(3600)  # Retry in 1 hour
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
        self.logger.info("Started cleanup thread")
    
    def _cleanup_old_data(self):
        """Clean up old data based on retention policy."""
        try:
            cutoff_time = time.time() - (self.retention_days * 24 * 3600)
            
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Clean up old metrics
                cursor.execute('DELETE FROM server_metrics WHERE timestamp < ?', (cutoff_time,))
                metrics_deleted = cursor.rowcount
                
                conn.commit()
                
                if metrics_deleted > 0:
                    self.logger.info(f"Cleaned up {metrics_deleted} old metric records")
                
        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")
    
    def export_registry(self, filepath: str):
        """Export registry to JSON file."""
        try:
            with self._cache_lock:
                servers_data = [server.to_dict() for server in self._servers_cache.values()]
                history_data = [history.to_dict() for history in self._history_cache.values()]
            
            export_data = {
                'export_time': time.time(),
                'registry_stats': self.get_registry_stats(),
                'servers': servers_data,
                'history': history_data
            }
            
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.info(f"Registry exported to {filepath}")
            
        except Exception as e:
            self.logger.error(f"Failed to export registry: {e}")
    
    def import_registry(self, filepath: str) -> int:
        """Import registry from JSON file."""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            imported_count = 0
            
            # Import servers
            for server_data in data.get('servers', []):
                try:
                    server = VPNServer.from_dict(server_data)
                    if self.register_server(server):
                        imported_count += 1
                except Exception as e:
                    self.logger.error(f"Failed to import server: {e}")
            
            self.logger.info(f"Imported {imported_count} servers from {filepath}")
            return imported_count
            
        except Exception as e:
            self.logger.error(f"Failed to import registry: {e}")
            return 0
