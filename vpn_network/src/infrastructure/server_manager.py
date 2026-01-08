"""
Server Management System for VPN Global Infrastructure.
This module provides comprehensive server deployment, management, monitoring,
and orchestration capabilities for global VPN infrastructure.
"""
import os
import sys
import time
import json
import asyncio
import subprocess
import threading
import hashlib
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from collections import defaultdict, deque
from pathlib import Path
import ipaddress
import socket

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from discovery import VPNServer, ServerStatus
from utils.logger import LoggableMixin
from utils.config_loader import Config


class ServerRole(Enum):
    """Server roles in the infrastructure."""
    GATEWAY = auto()
    CORE = auto()
    EDGE = auto()
    BACKUP = auto()
    MONITORING = auto()
    LOAD_BALANCER = auto()
    DNS = auto()


class ServerStatus(Enum):
    """Enhanced server status for infrastructure management."""
    PROVISIONING = auto()
    DEPLOYING = auto()
    STARTING = auto()
    RUNNING = auto()
    STOPPING = auto()
    STOPPED = auto()
    MAINTENANCE = auto()
    ERROR = auto()
    DECOMMISSIONING = auto()
    DECOMMISSIONED = auto()


class DeploymentType(Enum):
    """Server deployment types."""
    MANUAL = auto()
    AUTOMATED = auto()
    TEMPLATE = auto()
    CLONE = auto()
    MIGRATION = auto()


class ServerTier(Enum):
    """Server performance tiers."""
    BASIC = auto()
    STANDARD = auto()
    PREMIUM = auto()
    ENTERPRISE = auto()
    DEDICATED = auto()


@dataclass
class ServerSpecs:
    """Server specifications."""
    cpu_cores: int
    cpu_speed: float  # GHz
    memory_gb: int
    storage_gb: int
    bandwidth_mbps: float
    network_type: str  # fiber, copper, wireless
    location: str
    provider: str
    cost_per_month: float
    tier: ServerTier
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class ServerDeployment:
    """Server deployment configuration."""
    deployment_id: str
    server_id: str
    deployment_type: DeploymentType
    template_id: Optional[str]
    target_region: str
    target_zone: Optional[str]
    specs: ServerSpecs
    config: Dict[str, Any]
    created_at: float
    deployed_at: Optional[float]
    status: ServerStatus
    progress: float  # 0.0 to 1.0
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class ServerMetrics:
    """Real-time server metrics."""
    server_id: str
    timestamp: float
    cpu_usage: float  # 0.0 to 1.0
    memory_usage: float  # 0.0 to 1.0
    disk_usage: float  # 0.0 to 1.0
    network_in_mbps: float
    network_out_mbps: float
    active_connections: int
    load_average: float  # 1-minute average
    uptime_seconds: float
    temperature: Optional[float] = None  # Celsius
    power_usage: Optional[float] = None  # Watts
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class ServerGroup:
    """Server group for management."""
    group_id: str
    name: str
    description: str
    server_ids: List[str]
    role: ServerRole
    region: str
    load_balancing_config: Dict[str, Any]
    health_check_config: Dict[str, Any]
    created_at: float
    updated_at: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class ServerManager(LoggableMixin):
    """Comprehensive server management system."""
    
    def __init__(self, config_path: str = "config/vpn_config.json"):
        self.config_path = config_path
        self.config = Config(config_path).to_dict()
        self.infrastructure_config = self.config.get('infrastructure', {})
        
        # Data storage
        self.servers: Dict[str, VPNServer] = {}
        self.deployments: Dict[str, ServerDeployment] = {}
        self.server_groups: Dict[str, ServerGroup] = {}
        self.server_metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # State management
        self.management_state = {}
        self.deployment_queue: deque = deque(maxlen=100)
        self.active_deployments: Set[str] = set()
        
        # Background tasks
        self.monitor_thread = None
        self.deployment_thread = None
        self.running = False
        
        # Statistics
        self.stats = {
            'total_servers': 0,
            'active_servers': 0,
            'total_deployments': 0,
            'successful_deployments': 0,
            'failed_deployments': 0,
            'total_groups': 0,
            'average_deployment_time': 0.0,
            'server_uptime': 0.0,
            'infrastructure_health': 0.0
        }
        
        # Initialize infrastructure
        self._initialize()
    
    def _initialize(self):
        """Initialize the server management system."""
        try:
            # Create infrastructure directories
            os.makedirs('data/infrastructure', exist_ok=True)
            os.makedirs('data/infrastructure/servers', exist_ok=True)
            os.makedirs('data/infrastructure/deployments', exist_ok=True)
            os.makedirs('data/infrastructure/groups', exist_ok=True)
            os.makedirs('data/infrastructure/metrics', exist_ok=True)
            
            # Load existing data
            self._load_servers()
            self._load_deployments()
            self._load_groups()
            
            # Start background monitoring
            self._start_background_tasks()
            
            self.logger.info("Server management system initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize server management: {e}")
            raise
    
    def _load_servers(self):
        """Load existing server configurations."""
        try:
            servers_file = 'data/infrastructure/servers/servers.json'
            if os.path.exists(servers_file):
                with open(servers_file, 'r') as f:
                    data = json.load(f)
                    for server_data in data.get('servers', []):
                        server = VPNServer(
                            server_id=server_data['server_id'],
                            hostname=server_data['hostname'],
                            ip_address=server_data['ip_address'],
                            port=server_data['port'],
                            protocol=server_data.get('protocol', 'both'),
                            region=server_data.get('region', 'Unknown'),
                            country=server_data.get('country', 'Unknown'),
                            city=server_data.get('city', 'Unknown'),
                            latitude=server_data.get('latitude', 0.0),
                            longitude=server_data.get('longitude', 0.0),
                            response_time=server_data.get('response_time', 0.0),
                            load=server_data.get('load', 0.0),
                            bandwidth_mbps=server_data.get('bandwidth_mbps', 0.0),
                            current_clients=server_data.get('current_clients', 0),
                            max_clients=server_data.get('max_clients', 100),
                            status=ServerStatus(server_data.get('status', 'OFFLINE')),
                            last_seen=server_data.get('last_seen', 0.0)
                        )
                        self.servers[server.server_id] = server
                
                self.logger.info(f"Loaded {len(self.servers)} servers from storage")
                
        except Exception as e:
            self.logger.error(f"Failed to load servers: {e}")
    
    def _load_deployments(self):
        """Load existing deployment configurations."""
        try:
            deployments_file = 'data/infrastructure/deployments/deployments.json'
            if os.path.exists(deployments_file):
                with open(deployments_file, 'r') as f:
                    data = json.load(f)
                    for deployment_data in data.get('deployments', []):
                        deployment = ServerDeployment(
                            deployment_id=deployment_data['deployment_id'],
                            server_id=deployment_data['server_id'],
                            deployment_type=DeploymentType(deployment_data['deployment_type']),
                            template_id=deployment_data.get('template_id'),
                            target_region=deployment_data['target_region'],
                            target_zone=deployment_data.get('target_zone'),
                            specs=ServerSpecs(**deployment_data['specs']),
                            config=deployment_data.get('config', {}),
                            created_at=deployment_data['created_at'],
                            deployed_at=deployment_data.get('deployed_at'),
                            status=ServerStatus(deployment_data['status']),
                            progress=deployment_data.get('progress', 0.0),
                            error_message=deployment_data.get('error_message')
                        )
                        self.deployments[deployment.deployment_id] = deployment
                        
                        if deployment.status in [ServerStatus.RUNNING, ServerStatus.STARTING]:
                            self.active_deployments.add(deployment.deployment_id)
                
                self.logger.info(f"Loaded {len(self.deployments)} deployments from storage")
                
        except Exception as e:
            self.logger.error(f"Failed to load deployments: {e}")
    
    def _load_groups(self):
        """Load existing server groups."""
        try:
            groups_file = 'data/infrastructure/groups/groups.json'
            if os.path.exists(groups_file):
                with open(groups_file, 'r') as f:
                    data = json.load(f)
                    for group_data in data.get('groups', []):
                        group = ServerGroup(
                            group_id=group_data['group_id'],
                            name=group_data['name'],
                            description=group_data['description'],
                            server_ids=group_data['server_ids'],
                            role=ServerRole(group_data['role']),
                            region=group_data['region'],
                            load_balancing_config=group_data.get('load_balancing_config', {}),
                            health_check_config=group_data.get('health_check_config', {}),
                            created_at=group_data['created_at'],
                            updated_at=group_data['updated_at']
                        )
                        self.server_groups[group.group_id] = group
                
                self.logger.info(f"Loaded {len(self.server_groups)} server groups from storage")
                
        except Exception as e:
            self.logger.error(f"Failed to load server groups: {e}")
    
    def deploy_server(self, deployment_config: Dict[str, Any]) -> str:
        """Deploy a new server."""
        try:
            # Generate deployment ID
            deployment_id = f"deploy_{int(time.time())}_{hashlib.md5(str(deployment_config).encode()).hexdigest()[:8]}"
            
            # Create deployment object
            deployment = ServerDeployment(
                deployment_id=deployment_id,
                server_id=deployment_config.get('server_id', f"server_{deployment_id[:8]}"),
                deployment_type=DeploymentType(deployment_config.get('type', 'AUTOMATED')),
                template_id=deployment_config.get('template_id'),
                target_region=deployment_config.get('region', 'us-east-1'),
                target_zone=deployment_config.get('zone'),
                specs=ServerSpecs(**deployment_config.get('specs', {})),
                config=deployment_config.get('config', {}),
                created_at=time.time(),
                deployed_at=None,
                status=ServerStatus.PROVISIONING,
                progress=0.0
            )
            
            # Add to deployments
            self.deployments[deployment_id] = deployment
            self.deployment_queue.append(deployment_id)
            
            # Update statistics
            self.stats['total_deployments'] += 1
            
            self.logger.info(f"Server deployment queued: {deployment_id}")
            
            # Start deployment process
            self._start_deployment(deployment_id)
            
            return deployment_id
            
        except Exception as e:
            self.logger.error(f"Failed to deploy server: {e}")
            raise
    
    def _start_deployment(self, deployment_id: str):
        """Start the deployment process."""
        try:
            deployment = self.deployments.get(deployment_id)
            if not deployment:
                self.logger.error(f"Deployment {deployment_id} not found")
                return
            
            deployment.status = ServerStatus.DEPLOYING
            deployment.progress = 0.1
            self.active_deployments.add(deployment_id)
            
            # Start deployment in background
            threading.Thread(
                target=self._execute_deployment,
                args=(deployment_id,),
                daemon=True
            ).start()
            
            self.logger.info(f"Started deployment: {deployment_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to start deployment: {e}")
    
    def _execute_deployment(self, deployment_id: str):
        """Execute the deployment process."""
        try:
            deployment = self.deployments[deployment_id]
            start_time = time.time()
            
            # Simulate deployment steps
            steps = [
                ("Validating configuration", 0.1),
                ("Provisioning resources", 0.3),
                ("Installing dependencies", 0.5),
                ("Configuring network", 0.7),
                ("Starting services", 0.9),
                ("Running health checks", 1.0)
            ]
            
            for step_name, progress in steps:
                deployment.progress = progress
                self._save_deployments()
                
                # Simulate step execution time
                time.sleep(2)
                
                self.logger.info(f"Deployment {deployment_id}: {step_name} ({progress*100:.0f}%)")
            
            # Create server record
            server = VPNServer(
                server_id=deployment.server_id,
                hostname=deployment.server_id,
                ip_address=self._allocate_ip_address(deployment.target_region),
                port=1194,
                protocol='both',
                region=deployment.target_region,
                country=self._get_country_from_region(deployment.target_region),
                city=self._get_city_from_region(deployment.target_region),
                latitude=self._get_latitude_from_region(deployment.target_region),
                longitude=self._get_longitude_from_region(deployment.target_region),
                response_time=0.0,
                load=0.0,
                bandwidth_mbps=deployment.specs.bandwidth_mbps,
                current_clients=0,
                max_clients=deployment.specs.memory_gb * 10,  # Estimate based on memory
                status=ServerStatus.RUNNING,
                last_seen=time.time()
            )
            
            self.servers[deployment.server_id] = server
            self._save_servers()
            
            # Update deployment status
            deployment.status = ServerStatus.RUNNING
            deployment.deployed_at = time.time()
            deployment.progress = 1.0
            self.active_deployments.add(deployment_id)
            
            # Update statistics
            self.stats['successful_deployments'] += 1
            deployment_time = time.time() - start_time
            self.stats['average_deployment_time'] = (
                (self.stats['average_deployment_time'] * (self.stats['successful_deployments'] - 1) + deployment_time) /
                self.stats['successful_deployments']
            )
            
            self._save_deployments()
            
            self.logger.info(f"Deployment completed: {deployment_id} in {deployment_time:.2f}s")
            
        except Exception as e:
            deployment = self.deployments[deployment_id]
            deployment.status = ServerStatus.ERROR
            deployment.error_message = str(e)
            self.stats['failed_deployments'] += 1
            self._save_deployments()
            
            self.logger.error(f"Deployment failed: {deployment_id} - {e}")
    
    def _allocate_ip_address(self, region: str) -> str:
        """Allocate IP address for a region."""
        # Simple IP allocation based on region
        region_ips = {
            'us-east-1': '192.168.1.100',
            'us-west-1': '192.168.1.101',
            'eu-west-1': '192.168.1.102',
            'eu-central-1': '192.168.1.103',
            'ap-southeast-1': '192.168.1.104',
            'ap-northeast-1': '192.168.1.105'
        }
        
        base_ip = region_ips.get(region, '192.168.1.200')
        
        # Add random suffix for uniqueness
        import random
        suffix = random.randint(10, 250)
        return f"{base_ip.rsplit('.', 1)[0]}.{suffix}"
    
    def _get_country_from_region(self, region: str) -> str:
        """Get country from region."""
        region_countries = {
            'us-east-1': 'United States',
            'us-west-1': 'United States',
            'eu-west-1': 'Ireland',
            'eu-central-1': 'Germany',
            'ap-southeast-1': 'Singapore',
            'ap-northeast-1': 'Japan'
        }
        return region_countries.get(region, 'Unknown')
    
    def _get_city_from_region(self, region: str) -> str:
        """Get city from region."""
        region_cities = {
            'us-east-1': 'Virginia',
            'us-west-1': 'California',
            'eu-west-1': 'Dublin',
            'eu-central-1': 'Frankfurt',
            'ap-southeast-1': 'Singapore',
            'ap-northeast-1': 'Tokyo'
        }
        return region_cities.get(region, 'Unknown')
    
    def _get_latitude_from_region(self, region: str) -> float:
        """Get latitude from region."""
        region_coords = {
            'us-east-1': 39.0458,  # Virginia
            'us-west-1': 37.7749,  # California
            'eu-west-1': 53.3498,   # Dublin
            'eu-central-1': 50.1109,  # Frankfurt
            'ap-southeast-1': 1.3521,  # Singapore
            'ap-northeast-1': 35.6762  # Tokyo
        }
        return region_coords.get(region, 0.0)
    
    def _get_longitude_from_region(self, region: str) -> float:
        """Get longitude from region."""
        region_coords = {
            'us-east-1': -77.4538,  # Virginia
            'us-west-1': -122.4194, # California
            'eu-west-1': -6.2603,   # Dublin
            'eu-central-1': 8.6821,   # Frankfurt
            'ap-southeast-1': 103.8198, # Singapore
            'ap-northeast-1': 139.6503  # Tokyo
        }
        return region_coords.get(region, 0.0)
    
    def decommission_server(self, server_id: str, force: bool = False) -> bool:
        """Decommission a server."""
        try:
            server = self.servers.get(server_id)
            if not server:
                self.logger.error(f"Server {server_id} not found")
                return False
            
            # Check if server can be decommissioned
            if not force and server.current_clients > 0:
                self.logger.warning(f"Server {server_id} has active clients, cannot decommission")
                return False
            
            # Find and update deployments
            for deployment_id, deployment in self.deployments.items():
                if deployment.server_id == server_id:
                    deployment.status = ServerStatus.DECOMMISSIONING
                    deployment.progress = 0.1
            
            # Start decommissioning process
            threading.Thread(
                target=self._execute_decommissioning,
                args=(server_id,),
                daemon=True
            ).start()
            
            self.logger.info(f"Server decommissioning started: {server_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to decommission server {server_id}: {e}")
            return False
    
    def _execute_decommissioning(self, server_id: str):
        """Execute the decommissioning process."""
        try:
            start_time = time.time()
            
            # Simulate decommissioning steps
            steps = [
                ("Draining connections", 0.2),
                ("Stopping services", 0.4),
                ("Backing up data", 0.6),
                ("Releasing resources", 0.8),
                ("Cleaning up", 1.0)
            ]
            
            for step_name, progress in steps:
                # Update deployment progress
                for deployment_id, deployment in self.deployments.items():
                    if deployment.server_id == server_id:
                        deployment.progress = progress
                
                self._save_deployments()
                time.sleep(1)
                
                self.logger.info(f"Decommissioning {server_id}: {step_name} ({progress*100:.0f}%)")
            
            # Remove server
            if server_id in self.servers:
                del self.servers[server_id]
            
            # Update deployments
            for deployment_id, deployment in list(self.deployments.items()):
                if deployment.server_id == server_id:
                    deployment.status = ServerStatus.DECOMMISSIONED
                    deployment.progress = 1.0
                    self.active_deployments.discard(deployment_id)
            
            # Save changes
            self._save_servers()
            self._save_deployments()
            
            decommission_time = time.time() - start_time
            self.logger.info(f"Server decommissioned: {server_id} in {decommission_time:.2f}s")
            
        except Exception as e:
            self.logger.error(f"Failed to decommission server {server_id}: {e}")
    
    def create_server_group(self, group_config: Dict[str, Any]) -> str:
        """Create a server group."""
        try:
            group_id = f"group_{int(time.time())}_{hashlib.md5(str(group_config).encode()).hexdigest()[:6]}"
            
            group = ServerGroup(
                group_id=group_id,
                name=group_config.get('name', f"Group {group_id[:8]}"),
                description=group_config.get('description', ''),
                server_ids=group_config.get('server_ids', []),
                role=ServerRole(group_config.get('role', 'EDGE')),
                region=group_config.get('region', 'global'),
                load_balancing_config=group_config.get('load_balancing_config', {}),
                health_check_config=group_config.get('health_check_config', {}),
                created_at=time.time(),
                updated_at=time.time()
            )
            
            self.server_groups[group_id] = group
            self._save_groups()
            
            self.logger.info(f"Server group created: {group_id}")
            return group_id
            
        except Exception as e:
            self.logger.error(f"Failed to create server group: {e}")
            raise
    
    def add_server_to_group(self, group_id: str, server_id: str) -> bool:
        """Add a server to a group."""
        try:
            group = self.server_groups.get(group_id)
            if not group:
                self.logger.error(f"Group {group_id} not found")
                return False
            
            if server_id not in group.server_ids:
                group.server_ids.append(server_id)
                group.updated_at = time.time()
                self._save_groups()
                
                self.logger.info(f"Added server {server_id} to group {group_id}")
                return True
            else:
                self.logger.warning(f"Server {server_id} already in group {group_id}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to add server to group: {e}")
            return False
    
    def remove_server_from_group(self, group_id: str, server_id: str) -> bool:
        """Remove a server from a group."""
        try:
            group = self.server_groups.get(group_id)
            if not group:
                self.logger.error(f"Group {group_id} not found")
                return False
            
            if server_id in group.server_ids:
                group.server_ids.remove(server_id)
                group.updated_at = time.time()
                self._save_groups()
                
                self.logger.info(f"Removed server {server_id} from group {group_id}")
                return True
            else:
                self.logger.warning(f"Server {server_id} not in group {group_id}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to remove server from group: {e}")
            return False
    
    def get_server_metrics(self, server_id: str, hours: int = 1) -> List[ServerMetrics]:
        """Get metrics for a specific server."""
        try:
            metrics = self.server_metrics.get(server_id, deque())
            
            if not metrics:
                return []
            
            cutoff_time = time.time() - (hours * 3600)
            recent_metrics = [m for m in metrics if m.timestamp >= cutoff_time]
            
            return recent_metrics
            
        except Exception as e:
            self.logger.error(f"Failed to get server metrics: {e}")
            return []
    
    def record_server_metrics(self, metrics: ServerMetrics):
        """Record metrics for a server."""
        try:
            self.server_metrics[metrics.server_id].append(metrics)
            
            # Update server record if available
            server = self.servers.get(metrics.server_id)
            if server:
                server.load = metrics.load_average
                server.last_seen = metrics.timestamp
                self._save_servers()
            
        except Exception as e:
            self.logger.error(f"Failed to record server metrics: {e}")
    
    def get_infrastructure_status(self) -> Dict[str, Any]:
        """Get comprehensive infrastructure status."""
        try:
            # Count servers by status
            status_counts = defaultdict(int)
            for server in self.servers.values():
                status_counts[server.status.name] += 1
            
            # Count deployments by status
            deployment_counts = defaultdict(int)
            for deployment in self.deployments.values():
                deployment_counts[deployment.status.name] += 1
            
            # Calculate infrastructure health
            total_servers = len(self.servers)
            healthy_servers = status_counts.get('RUNNING', 0) + status_counts.get('ONLINE', 0)
            infrastructure_health = healthy_servers / total_servers if total_servers > 0 else 0.0
            
            return {
                'servers': {
                    'total': total_servers,
                    'by_status': dict(status_counts),
                    'by_region': self._get_servers_by_region(),
                    'by_role': self._get_servers_by_role()
                },
                'deployments': {
                    'total': len(self.deployments),
                    'active': len(self.active_deployments),
                    'by_status': dict(deployment_counts),
                    'queue_size': len(self.deployment_queue)
                },
                'groups': {
                    'total': len(self.server_groups),
                    'by_role': self._get_groups_by_role()
                },
                'health': {
                    'infrastructure_health': infrastructure_health,
                    'average_uptime': self._calculate_average_uptime(),
                    'total_capacity': self._calculate_total_capacity()
                },
                'statistics': self.stats,
                'last_updated': time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get infrastructure status: {e}")
            return {}
    
    def _get_servers_by_region(self) -> Dict[str, int]:
        """Count servers by region."""
        region_counts = defaultdict(int)
        for server in self.servers.values():
            region_counts[server.region] += 1
        return dict(region_counts)
    
    def _get_servers_by_role(self) -> Dict[str, int]:
        """Count servers by role (derived from groups)."""
        role_counts = defaultdict(int)
        for group in self.server_groups.values():
            role_counts[group.role.name] += len(group.server_ids)
        return dict(role_counts)
    
    def _get_groups_by_role(self) -> Dict[str, int]:
        """Count groups by role."""
        role_counts = defaultdict(int)
        for group in self.server_groups.values():
            role_counts[group.role.name] += 1
        return dict(role_counts)
    
    def _calculate_average_uptime(self) -> float:
        """Calculate average uptime across all servers."""
        try:
            if not self.servers:
                return 0.0
            
            total_uptime = 0.0
            server_count = 0
            
            for server_id in self.servers.keys():
                metrics = self.get_server_metrics(server_id, 24)  # Last 24 hours
                if metrics:
                    uptime = sum(m.uptime_seconds for m in metrics) / len(metrics)
                    total_uptime += uptime
                    server_count += 1
            
            return total_uptime / server_count if server_count > 0 else 0.0
            
        except Exception as e:
            self.logger.error(f"Failed to calculate average uptime: {e}")
            return 0.0
    
    def _calculate_total_capacity(self) -> Dict[str, float]:
        """Calculate total infrastructure capacity."""
        try:
            total_bandwidth = 0.0
            total_connections = 0
            total_memory = 0
            
            for server in self.servers.values():
                total_bandwidth += server.bandwidth_mbps
                total_connections += server.max_clients
                # Estimate memory from specs if available
                total_memory += 1024  # Placeholder, would get from actual specs
            
            return {
                'total_bandwidth_mbps': total_bandwidth,
                'total_connections': total_connections,
                'total_memory_gb': total_memory,
                'utilization_percentage': (total_connections / max(1, total_connections * 10)) * 100
            }
            
        except Exception as e:
            self.logger.error(f"Failed to calculate total capacity: {e}")
            return {}
    
    def _save_servers(self):
        """Save servers to storage."""
        try:
            servers_data = {
                'servers': [server.to_dict() for server in self.servers.values()],
                'last_updated': time.time()
            }
            
            with open('data/infrastructure/servers/servers.json', 'w') as f:
                json.dump(servers_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save servers: {e}")
    
    def _save_deployments(self):
        """Save deployments to storage."""
        try:
            deployments_data = {
                'deployments': [deployment.to_dict() for deployment in self.deployments.values()],
                'last_updated': time.time()
            }
            
            with open('data/infrastructure/deployments/deployments.json', 'w') as f:
                json.dump(deployments_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save deployments: {e}")
    
    def _save_groups(self):
        """Save groups to storage."""
        try:
            groups_data = {
                'groups': [group.to_dict() for group in self.server_groups.values()],
                'last_updated': time.time()
            }
            
            with open('data/infrastructure/groups/groups.json', 'w') as f:
                json.dump(groups_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save groups: {e}")
    
    def _start_background_tasks(self):
        """Start background monitoring tasks."""
        if self.running:
            return
        
        self.running = True
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitoring_worker, daemon=True)
        self.monitor_thread.start()
        
        # Start deployment processing thread
        self.deployment_thread = threading.Thread(target=self._deployment_worker, daemon=True)
        self.deployment_thread.start()
        
        self.logger.info("Background tasks started")
    
    def _monitoring_worker(self):
        """Background worker for infrastructure monitoring."""
        while self.running:
            try:
                # Update statistics
                self.stats['total_servers'] = len(self.servers)
                self.stats['active_servers'] = len([s for s in self.servers.values() 
                                                if s.status in [ServerStatus.RUNNING, ServerStatus.ONLINE]])
                self.stats['total_groups'] = len(self.server_groups)
                
                # Calculate infrastructure health
                if self.stats['total_servers'] > 0:
                    self.stats['infrastructure_health'] = self.stats['active_servers'] / self.stats['total_servers']
                
                time.sleep(30)  # Update every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Monitoring worker error: {e}")
                time.sleep(10)
    
    def _deployment_worker(self):
        """Background worker for processing deployments."""
        while self.running:
            try:
                if self.deployment_queue:
                    deployment_id = self.deployment_queue.popleft()
                    self._start_deployment(deployment_id)
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Deployment worker error: {e}")
                time.sleep(10)
    
    def stop(self):
        """Stop the server management system."""
        try:
            self.running = False
            
            # Wait for threads to finish
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=10)
            
            if self.deployment_thread and self.deployment_thread.is_alive():
                self.deployment_thread.join(timeout=10)
            
            # Save final state
            self._save_servers()
            self._save_deployments()
            self._save_groups()
            
            self.logger.info("Server management system stopped")
            
        except Exception as e:
            self.logger.error(f"Failed to stop server management system: {e}")
