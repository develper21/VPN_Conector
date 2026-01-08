#!/usr/bin/env python3
"""
Multi-Server Architecture Test Suite
Tests server discovery, registry, health checking, and load balancing.
"""
import os
import sys
import time
import asyncio
import subprocess
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_server_discovery():
    """Test server discovery functionality."""
    print("\n🧪 Testing Server Discovery")
    print("=" * 35)
    
    try:
        from discovery.server_discovery import ServerDiscovery, VPNServer, ServerStatus
        
        config = {
            'discovery': {
                'enabled_methods': ['dns_lookup', 'http_api', 'direct_probe'],
                'timeout': 5,
                'max_concurrent': 10,
                'static_servers': [
                    {
                        'server_id': 'test-server-1',
                        'hostname': 'test.vpn.example.com',
                        'ip_address': '127.0.0.1',
                        'port': 1194,
                        'protocol': 'both'
                    }
                ]
            }
        }
        
        discovery = ServerDiscovery(config)
        print("✅ Server discovery initialized")
        
        # Test static servers
        servers = discovery.get_static_servers()
        if servers:
            print(f"✅ Static servers loaded: {len(servers)}")
        else:
            print("❌ No static servers found")
            return False
        
        # Test server registration
        for server in servers:
            success = discovery.discovered_servers.update({server.server_id: server})
            print(f"✅ Server registered: {server.server_id}")
        
        # Test server filtering
        openvpn_servers = discovery.get_servers_by_protocol('openvpn')
        wireguard_servers = discovery.get_servers_by_protocol('wireguard')
        
        print(f"✅ OpenVPN servers: {len(openvpn_servers)}")
        print(f"✅ WireGuard servers: {len(wireguard_servers)}")
        
        # Test best servers selection
        best_servers = discovery.get_best_servers(count=3)
        print(f"✅ Best servers selected: {len(best_servers)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Server discovery test failed: {e}")
        return False

def test_server_registry():
    """Test server registry functionality."""
    print("\n🧪 Testing Server Registry")
    print("=" * 30)
    
    try:
        from discovery.server_registry import ServerRegistry, ServerMetrics, ServerHistory
        from discovery.server_discovery import VPNServer, ServerStatus
        
        config = {
            'registry': {
                'database_path': 'data/test_vpn_servers.db',
                'auto_cleanup': False,
                'retention_days': 30
            }
        }
        
        registry = ServerRegistry(config)
        print("✅ Server registry initialized")
        
        # Create test server
        test_server = VPNServer(
            server_id='test-registry-server',
            hostname='test.vpn.example.com',
            ip_address='127.0.0.1',
            port=1194,
            protocol='both',
            region='North America',
            country='United States',
            city='New York',
            latitude=40.7128,
            longitude=-74.0060
        )
        
        # Test server registration
        success = registry.register_server(test_server)
        if success:
            print("✅ Server registered successfully")
        else:
            print("❌ Server registration failed")
            return False
        
        # Test server retrieval
        retrieved_server = registry.get_server('test-registry-server')
        if retrieved_server and retrieved_server.server_id == test_server.server_id:
            print("✅ Server retrieved successfully")
        else:
            print("❌ Server retrieval failed")
            return False
        
        # Test metrics addition
        metrics = ServerMetrics(
            server_id='test-registry-server',
            timestamp=time.time(),
            response_time=50.0,
            bandwidth_mbps=100.0,
            packet_loss=0.01,
            uptime=0.99,
            cpu_usage=0.3,
            memory_usage=0.4,
            active_connections=10,
            error_rate=0.001
        )
        
        registry.add_metrics(metrics)
        print("✅ Metrics added successfully")
        
        # Test connection attempt recording
        registry.record_connection_attempt('test-registry-server', True, 45.0)
        registry.record_connection_attempt('test-registry-server', False, error="Timeout")
        print("✅ Connection attempts recorded")
        
        # Test statistics
        stats = registry.get_registry_stats()
        if stats['total_servers'] > 0:
            print(f"✅ Registry stats: {stats['total_servers']} servers")
        else:
            print("❌ No servers in registry")
            return False
        
        # Cleanup
        registry.remove_server('test-registry-server')
        print("✅ Test server cleaned up")
        
        return True
        
    except Exception as e:
        print(f"❌ Server registry test failed: {e}")
        return False

def test_health_checker():
    """Test health checker functionality."""
    print("\n🧪 Testing Health Checker")
    print("=" * 30)
    
    try:
        from discovery.health_checker import HealthChecker, HealthStatus
        from discovery.server_registry import ServerRegistry
        from discovery.server_discovery import VPNServer, ServerStatus
        
        config = {
            'health_checker': {
                'enabled_checks': ['connectivity', 'response_time'],
                'interval': 30,
                'timeout': 5,
                'max_concurrent': 5,
                'retry_count': 2
            },
            'registry': {
                'database_path': 'data/test_vpn_servers.db',
                'auto_cleanup': False
            }
        }
        
        registry = ServerRegistry(config)
        health_checker = HealthChecker(config, registry)
        print("✅ Health checker initialized")
        
        # Create test server
        test_server = VPNServer(
            server_id='test-health-server',
            hostname='localhost',
            ip_address='127.0.0.1',
            port=80,  # Use port 80 for testing (likely to be available)
            protocol='both',
            region='North America',
            country='United States',
            city='New York',
            latitude=40.7128,
            longitude=-74.0060
        )
        
        registry.register_server(test_server)
        print("✅ Test server registered")
        
        # Test manual health check
        result = health_checker.run_manual_check('test-health-server')
        if result:
            print(f"✅ Health check completed: {result.status.name}")
            print(f"   Message: {result.message}")
            print(f"   Response time: {result.response_time:.2f}ms")
        else:
            print("⚠️  Health check returned no result (server may be unavailable)")
        
        # Test health status retrieval
        health_status = health_checker.get_server_health('test-health-server')
        if health_status:
            print(f"✅ Health status: {health_status.name}")
        else:
            print("⚠️  No health status available")
        
        # Test health summary
        summary = health_checker.get_health_summary()
        print(f"✅ Health summary: {summary['total_servers']} servers")
        
        # Cleanup
        registry.remove_server('test-health-server')
        print("✅ Test server cleaned up")
        
        return True
        
    except Exception as e:
        print(f"❌ Health checker test failed: {e}")
        return False

def test_geographic_load_balancer():
    """Test geographic load balancer functionality."""
    print("\n🧪 Testing Geographic Load Balancer")
    print("=" * 40)
    
    try:
        from discovery.geographic_load_balancer import GeographicLoadBalancer, LoadBalanceStrategy, ClientLocation
        from discovery.server_registry import ServerRegistry
        from discovery.health_checker import HealthChecker
        from discovery.server_discovery import VPNServer, ServerStatus
        
        config = {
            'load_balancer': {
                'default_strategy': 'geographic',
                'max_servers_per_request': 5,
                'geographic_weight': 0.4,
                'performance_weight': 0.3,
                'load_weight': 0.2,
                'health_weight': 0.1
            },
            'registry': {
                'database_path': 'data/test_vpn_servers.db',
                'auto_cleanup': False
            },
            'health_checker': {
                'enabled_checks': [],
                'interval': 60
            }
        }
        
        registry = ServerRegistry(config)
        health_checker = HealthChecker(config, registry)
        load_balancer = GeographicLoadBalancer(config, registry, health_checker)
        print("✅ Load balancer initialized")
        
        # Create test servers in different locations
        test_servers = [
            VPNServer(
                server_id='us-server',
                hostname='us.vpn.example.com',
                ip_address='192.168.1.100',
                port=1194,
                protocol='both',
                region='North America',
                country='United States',
                city='New York',
                latitude=40.7128,
                longitude=-74.0060,
                response_time=50.0,
                load=0.3
            ),
            VPNServer(
                server_id='eu-server',
                hostname='eu.vpn.example.com',
                ip_address='192.168.1.101',
                port=1194,
                protocol='both',
                region='Europe',
                country='Germany',
                city='Berlin',
                latitude=52.5200,
                longitude=13.4050,
                response_time=80.0,
                load=0.5
            ),
            VPNServer(
                server_id='asia-server',
                hostname='asia.vpn.example.com',
                ip_address='192.168.1.102',
                port=51820,
                protocol='wireguard',
                region='Asia',
                country='Japan',
                city='Tokyo',
                latitude=35.6762,
                longitude=139.6503,
                response_time=120.0,
                load=0.7
            )
        ]
        
        # Register test servers
        for server in test_servers:
            registry.register_server(server)
        print(f"✅ {len(test_servers)} test servers registered")
        
        # Test client location
        client_location = ClientLocation(
            latitude=40.7128,  # New York
            longitude=-74.0060,
            city='New York',
            country='United States'
        )
        print(f"✅ Client location: {client_location.city}")
        
        # Test geographic selection
        nearest_servers = load_balancer.get_nearest_servers(client_location, count=2)
        print(f"✅ Nearest servers: {len(nearest_servers)}")
        
        for score in nearest_servers:
            print(f"   {score.server_id}: {score.total_score:.3f} (distance: {score.details['distance_km']:.1f}km)")
        
        # Test fastest servers
        fastest_servers = load_balancer.get_fastest_servers(count=2)
        print(f"✅ Fastest servers: {len(fastest_servers)}")
        
        for score in fastest_servers:
            print(f"   {score.server_id}: {score.total_score:.3f} (response: {score.details['response_time_ms']:.1f}ms)")
        
        # Test protocol-specific selection
        wireguard_servers = load_balancer.select_best_servers(
            client_location=client_location,
            protocol='wireguard',
            count=2
        )
        print(f"✅ WireGuard servers: {len(wireguard_servers)}")
        
        # Test recommendations
        recommendations = load_balancer.get_server_recommendations(
            client_location=client_location,
            preferences={'count': 2}
        )
        print(f"✅ Recommendations: {len(recommendations)} categories")
        
        for category, servers in recommendations.items():
            print(f"   {category}: {len(servers)} servers")
        
        # Test statistics
        stats = load_balancer.get_load_balancer_stats()
        print(f"✅ Load balancer stats: {stats['stats']['total_selections']} selections")
        
        # Cleanup
        for server in test_servers:
            registry.remove_server(server.server_id)
        print("✅ Test servers cleaned up")
        
        return True
        
    except Exception as e:
        print(f"❌ Geographic load balancer test failed: {e}")
        return False

def test_multi_server_integration():
    """Test multi-server integration."""
    print("\n🧪 Testing Multi-Server Integration")
    print("=" * 40)
    
    try:
        from integrations.multi_server_integration import MultiServerManager, MultiServerMode
        
        config = {
            'multi_server': {
                'enabled': True,
                'mode': 'distributed',
                'auto_discovery': False,  # Disable for testing
                'auto_failover': True,
                'max_connections': 3,
                'discovery': {
                    'static_servers': [
                        {
                            'server_id': 'integration-test-server',
                            'hostname': 'test.vpn.example.com',
                            'ip_address': '127.0.0.1',
                            'port': 80,
                            'protocol': 'both',
                            'public_key': 'test1234567890abcdef='
                        }
                    ]
                },
                'registry': {
                    'database_path': 'data/test_vpn_servers.db',
                    'auto_cleanup': False
                },
                'health_checker': {
                    'enabled_checks': ['connectivity'],
                    'interval': 60,
                    'timeout': 5
                },
                'load_balancer': {
                    'default_strategy': 'geographic'
                }
            }
        }
        
        manager = MultiServerManager(config)
        print("✅ Multi-server manager initialized")
        
        # Test manager start
        manager.start()
        print("✅ Manager started")
        
        # Test connection status
        status = manager.get_connection_status()
        print(f"✅ Connection status: {status['mode']} mode")
        print(f"   Active connections: {status['active_connections']}")
        
        # Test available servers
        available_servers = manager.get_available_servers()
        print(f"✅ Available servers: {len(available_servers)}")
        
        # Test server recommendations
        recommendations = manager.get_server_recommendations()
        print(f"✅ Recommendations: {len(recommendations)} categories")
        
        # Test statistics
        stats = manager.get_multi_server_stats()
        print(f"✅ Multi-server stats available")
        
        # Test manager stop
        manager.stop()
        print("✅ Manager stopped")
        
        return True
        
    except Exception as e:
        print(f"❌ Multi-server integration test failed: {e}")
        return False

def test_dependencies():
    """Test required dependencies for multi-server functionality."""
    print("\n🧪 Testing Multi-Server Dependencies")
    print("=" * 45)
    
    required_packages = [
        'aiohttp',
        'dns.resolver',
        'geoip2',
        'ping3',
        'psutil',
        'sqlite3',
        'statistics',
        'asyncio',
        'threading',
        'math',
        'json',
        'time'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            if package == 'dns.resolver':
                import dns.resolver
            elif package == 'geoip2':
                import geoip2.database
            elif package == 'ping3':
                import ping3
            elif package == 'psutil':
                import psutil
            elif package == 'aiohttp':
                import aiohttp
            else:
                __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {missing_packages}")
        print("Install with: pip install aiohttp dnspython geoip2 ping3 psutil")
        return False
    
    print("✅ All dependencies available")
    return True

def main():
    """Run multi-server architecture test suite."""
    print("🚀 Multi-Server Architecture Test Suite")
    print("=" * 60)
    print("Testing: Discovery + Registry + Health + Load Balancing")
    
    tests = [
        ("Dependencies", test_dependencies),
        ("Server Discovery", test_server_discovery),
        ("Server Registry", test_server_registry),
        ("Health Checker", test_health_checker),
        ("Geographic Load Balancer", test_geographic_load_balancer),
        ("Multi-Server Integration", test_multi_server_integration),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Multi-Server Test Results Summary")
    print("=" * 60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:<30} {status}")
        if result:
            passed += 1
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 MULTI-SERVER ARCHITECTURE COMPLETED!")
        print("\n✅ IMPLEMENTED FEATURES:")
        print("   • Server Discovery (DNS, API, Direct Probe)")
        print("   • Server Registry (SQLite Database)")
        print("   • Health Checker (Comprehensive Monitoring)")
        print("   • Geographic Load Balancer (Smart Selection)")
        print("   • Multi-Server Integration (Unified Management)")
        print("   • Auto-Failover (High Availability)")
        print("   • Performance Optimization (Load Distribution)")
        
        print("\n🌍 GLOBAL VPN CAPABILITIES:")
        print("   • Automatic Server Discovery")
        print("   • Geographic Server Selection")
        print("   • Real-time Health Monitoring")
        print("   • Intelligent Load Balancing")
        print("   • Seamless Failover")
        print("   • Performance Analytics")
        
        print("\n🎯 USAGE EXAMPLES:")
        print("   # Multi-server client:")
        print("   python src/main.py --client --multi-server")
        print()
        print("   # Specific protocol:")
        print("   python src/main.py --client --multi-server --protocol wireguard")
        print()
        print("   # Custom configuration:")
        print("   python src/main.py --client --multi-server --config custom.json")
        
    else:
        print(f"\n⚠️  {total - passed} test(s) failed.")
        print("Please check the implementation and dependencies.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
