"""
Test cases for VPN server functionality.
"""
import os
import sys
import time
import socket
import unittest
import tempfile
import threading
import ipaddress
from unittest.mock import patch, MagicMock, ANY, call

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.vpn_server.server import VPNServer, ClientSession, VPNServerError
from src.vpn_server.tunnel_manager import TunnelManager, TunnelError
from src.vpn_server.access_control import AccessControl, AuthError
from src.network.interface import UDPSocket, NetworkError
from src.network.packet_handler import (
    Packet, PacketType, DataPacket, HandshakePacket, KeepalivePacket, ErrorPacket
)
from src.security.encryption import EncryptionManager, CipherAlgorithm
from src.security.key_exchange import ECDHKeyExchange

class MockUDPSocket:
    """Mock UDP socket for testing."""
    def __init__(self):
        self.recv_queue = []
        self.sent_data = []
        self.addr = None
        self.timeout = None
        self.blocking = True
    
    def bind(self, addr):
        self.addr = addr
    
    def sendto(self, data, addr):
        self.sent_data.append((data, addr))
        return len(data)
    
    def recvfrom(self, bufsize):
        if not self.recv_queue:
            if self.timeout == 0 or not self.blocking:
                raise socket.timeout("No data available")
            time.sleep(0.1)  # Simulate blocking
            raise socket.timeout("No data available")
        return self.recv_queue.pop(0)
    
    def settimeout(self, timeout):
        self.timeout = timeout
    
    def setblocking(self, flag):
        self.blocking = flag
    
    def close(self):
        pass
    
    def queue_receive(self, data, addr=('127.0.0.1', 12345)):
        """Queue data to be received by recvfrom."""
        self.recv_queue.append((data, addr))
        return addr


class TestVPNServer(unittest.TestCase):
    """Test cases for VPNServer class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for test files
        self.test_dir = tempfile.TemporaryDirectory()
        
        # Create a mock configuration
        self.config = {
            'server': {
                'host': '0.0.0.0',
                'port': 1194,
                'protocol': 'udp',
                'max_clients': 10,
                'timeout': 30,
                'keepalive_interval': 10
            },
            'security': {
                'cipher': 'AES-256-GCM',
                'auth': 'SHA256',
                'tls_version': 'TLSv1.3',
                'key_exchange': 'ECDH'
            },
            'tunnel': {
                'network': '10.8.0.0',
                'netmask': '255.255.255.0',
                'dns_servers': ['8.8.8.8', '8.8.4.4'],
                'mtu': 1500
            },
            'authentication': {
                'enabled': True,
                'method': 'password',
                'users': {
                    'testuser': {
                        'password': 'testpass',
                        'ip': '10.8.0.2'
                    }
                }
            }
        }
        
        # Create a mock UDPSocket
        self.mock_socket = MockUDPSocket()
        
        # Patch the UDPSocket class to return our mock
        self.socket_patcher = patch('src.network.interface.socket.socket', 
                                  return_value=self.mock_socket)
        self.mock_socket_class = self.socket_patcher.start()
        
        # Create a VPNServer instance
        self.server = VPNServer(self.config)
        
        # Mock the tunnel manager
        self.server.tunnel_manager = MagicMock(spec=TunnelManager)
        self.server.tunnel_manager.allocate_ip.return_value = '10.8.0.2'
        
        # Mock the access control
        self.server.access_control = MagicMock(spec=AccessControl)
        self.server.access_control.authenticate.return_value = {
            'username': 'testuser',
            'ip': '10.8.0.2'
        }
    
    def tearDown(self):
        """Clean up test fixtures."""
        self.socket_patcher.stop()
        self.test_dir.cleanup()
    
    def test_server_initialization(self):
        """Test VPNServer initialization."""
        self.assertEqual(self.server.host, '0.0.0.0')
        self.assertEqual(self.server.port, 1194)
        self.assertEqual(self.server.max_clients, 10)
        self.assertEqual(self.server.timeout, 30)
        self.assertIsInstance(self.server.encryption_manager, EncryptionManager)
        self.assertIsInstance(self.server.key_exchange, ECDHKeyExchange)
        self.assertEqual(len(self.server.clients), 0)
    
    def test_handle_handshake(self):
        """Test handling of handshake packets."""
        # Create a mock client address
        client_addr = ('192.168.1.100', 54321)
        
        # Queue a handshake packet
        handshake_packet = HandshakePacket(b'handshake_data')
        self.mock_socket.queue_receive(handshake_packet.serialize(), client_addr)
        
        # Process the packet
        self.server._process_packets()
        
        # Verify a handshake response was sent
        self.assertEqual(len(self.mock_socket.sent_data), 1)
        sent_data, sent_addr = self.mock_socket.sent_data[0]
        sent_packet = Packet.deserialize(sent_data)
        
        self.assertEqual(sent_addr, client_addr)
        self.assertEqual(sent_packet.type, PacketType.HANDSHAKE_RESPONSE)
        
        # Verify a client session was created
        self.assertIn(client_addr, self.server.clients)
        client_session = self.server.clients[client_addr]
        self.assertEqual(client_session.addr, client_addr)
        self.assertEqual(client_session.state, 'HANDSHAKE_COMPLETE')
    
    def test_handle_authentication(self):
        """Test handling of authentication packets."""
        # Create a mock client session in HANDSHAKE_COMPLETE state
        client_addr = ('192.168.1.100', 54321)
        self.server.clients[client_addr] = ClientSession(
            addr=client_addr,
            state='HANDSHAKE_COMPLETE',
            handshake_data=b'handshake_data'
        )
        
        # Queue an authentication packet
        auth_packet = Packet(
            PacketType.AUTH_REQUEST,
            b'username=testuser&password=testpass'
        )
        self.mock_socket.queue_receive(auth_packet.serialize(), client_addr)
        
        # Process the packet
        self.server._process_packets()
        
        # Verify an authentication response was sent
        self.assertEqual(len(self.mock_socket.sent_data), 1)
        sent_data, sent_addr = self.mock_socket.sent_data[0]
        sent_packet = Packet.deserialize(sent_data)
        
        self.assertEqual(sent_addr, client_addr)
        self.assertEqual(sent_packet.type, PacketType.AUTH_RESPONSE)
        
        # Verify the client session was updated
        client_session = self.server.clients[client_addr]
        self.assertEqual(client_session.state, 'AUTHENTICATED')
        self.assertEqual(client_session.username, 'testuser')
        self.assertEqual(client_session.virtual_ip, '10.8.0.2')
        
        # Verify the tunnel manager was called to set up the tunnel
        self.server.tunnel_manager.add_route.assert_called_once_with(
            '10.8.0.2', client_addr
        )
    
    def test_handle_data(self):
        """Test handling of data packets."""
        # Create a mock client session in AUTHENTICATED state
        client_addr = ('192.168.1.100', 54321)
        self.server.clients[client_addr] = ClientSession(
            addr=client_addr,
            state='AUTHENTICATED',
            username='testuser',
            virtual_ip='10.8.0.2',
            encryption_key=b'test_encryption_key',
            hmac_key=b'test_hmac_key'
        )
        
        # Create a test data packet
        test_data = b'test data'
        data_packet = DataPacket(test_data)
        
        # Encrypt the packet
        enc_manager = EncryptionManager(algorithm=CipherAlgorithm.AES_256_GCM)
        enc_manager.set_keys(b'test_encryption_key')
        iv = os.urandom(12)
        encrypted_data = enc_manager.encrypt(
            data_packet.serialize(),
            iv=iv
        )
        
        # Queue the encrypted data packet
        self.mock_socket.queue_receive(
            encrypted_data.ciphertext + encrypted_data.tag,
            client_addr
        )
        
        # Process the packet
        self.server._process_packets()
        
        # Verify the data was processed (in a real test, you'd check the tunnel)
        # For now, just verify no errors occurred
        self.assertTrue(True)
    
    def test_handle_keepalive(self):
        """Test handling of keepalive packets."""
        # Create a mock client session in AUTHENTICATED state
        client_addr = ('192.168.1.100', 54321)
        self.server.clients[client_addr] = ClientSession(
            addr=client_addr,
            state='AUTHENTICATED',
            username='testuser',
            virtual_ip='10.8.0.2',
            last_seen=time.time() - 20  # Simulate last seen 20 seconds ago
        )
        
        # Queue a keepalive packet
        keepalive_packet = KeepalivePacket()
        self.mock_socket.queue_receive(keepalive_packet.serialize(), client_addr)
        
        # Process the packet
        self.server._process_packets()
        
        # Verify a keepalive response was sent
        self.assertEqual(len(self.mock_socket.sent_data), 1)
        sent_data, sent_addr = self.mock_socket.sent_data[0]
        sent_packet = Packet.deserialize(sent_data)
        
        self.assertEqual(sent_addr, client_addr)
        self.assertEqual(sent_packet.type, PacketType.KEEPALIVE)
        
        # Verify the client's last_seen was updated
        client_session = self.server.clients[client_addr]
        self.assertGreater(client_session.last_seen, time.time() - 1)
    
    def test_cleanup_inactive_clients(self):
        """Test cleanup of inactive client sessions."""
        # Create a mock client session that's been inactive for too long
        client_addr = ('192.168.1.100', 54321)
        self.server.clients[client_addr] = ClientSession(
            addr=client_addr,
            state='AUTHENTICATED',
            username='testuser',
            virtual_ip='10.8.0.2',
            last_seen=time.time() - 3600  # 1 hour ago
        )
        
        # Run the cleanup
        self.server._cleanup_inactive_clients()
        
        # Verify the client was removed
        self.assertNotIn(client_addr, self.server.clients)
        
        # Verify the tunnel manager was called to remove the route
        self.server.tunnel_manager.remove_route.assert_called_once_with('10.8.0.2')


class TestTunnelManager(unittest.TestCase):
    """Test cases for TunnelManager class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'network': '10.8.0.0',
            'netmask': '255.255.255.0',
            'dns_servers': ['8.8.8.8', '8.8.4.4'],
            'mtu': 1500
        }
        self.manager = TunnelManager(self.config)
    
    @patch('subprocess.run')
    def test_add_route_linux(self, mock_run):
        """Test adding a route on Linux."""
        with patch('sys.platform', 'linux'):
            self.manager.add_route('10.8.0.2', ('192.168.1.100', 54321))
            
            # Verify the correct commands were executed
            expected_calls = [
                call(['ip', 'route', 'add', '10.8.0.2/32', 'via', '192.168.1.100'], 
                     check=True, capture_output=True, text=True),
                call(['iptables', '-A', 'FORWARD', '-s', '10.8.0.2/32', '-j', 'ACCEPT'], 
                     check=True, capture_output=True, text=True),
                call(['iptables', '-A', 'FORWARD', '-d', '10.8.0.2/32', '-j', 'ACCEPT'], 
                     check=True, capture_output=True, text=True)
            ]
            mock_run.assert_has_calls(expected_calls, any_order=True)
    
    @patch('subprocess.run')
    def test_remove_route_linux(self, mock_run):
        """Test removing a route on Linux."""
        with patch('sys.platform', 'linux'):
            self.manager.remove_route('10.8.0.2')
            
            # Verify the correct commands were executed
            expected_calls = [
                call(['ip', 'route', 'del', '10.8.0.2/32'], 
                     check=True, capture_output=True, text=True),
                call(['iptables', '-D', 'FORWARD', '-s', '10.8.0.2/32', '-j', 'ACCEPT'], 
                     check=True, capture_output=True, text=True),
                call(['iptables', '-D', 'FORWARD', '-d', '10.8.0.2/32', '-j', 'ACCEPT'], 
                     check=True, capture_output=True, text=True)
            ]
            mock_run.assert_has_calls(expected_calls, any_order=True)
    
    def test_allocate_ip(self):
        """Test IP address allocation."""
        # Allocate an IP address
        ip = self.manager.allocate_ip()
        
        # Verify the IP is in the correct range
        self.assertTrue(ip.startswith('10.8.0.'))
        self.assertNotEqual(ip, '10.8.0.0')  # Network address
        self.assertNotEqual(ip, '10.8.0.255')  # Broadcast address
        
        # Allocate another IP
        ip2 = self.manager.allocate_ip()
        self.assertNotEqual(ip, ip2)  # Should be different IPs
        
        # Free an IP and allocate it again
        self.manager.free_ip(ip)
        ip3 = self.manager.allocate_ip()
        self.assertEqual(ip, ip3)  # Should reuse the freed IP


class TestAccessControl(unittest.TestCase):
    """Test cases for AccessControl class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'enabled': True,
            'method': 'password',
            'users': {
                'testuser': {
                    'password': 'testpass',
                    'ip': '10.8.0.2'
                }
            }
        }
        self.access_control = AccessControl(self.config)
    
    def test_authenticate_success(self):
        """Test successful authentication."""
        # Mock the handshake data
        handshake_data = b'handshake_data'
        
        # Test authentication with correct credentials
        result = self.access_control.authenticate(
            'testuser',
            'testpass',
            handshake_data
        )
        
        # Verify the result
        self.assertEqual(result['username'], 'testuser')
        self.assertEqual(result['ip'], '10.8.0.2')
    
    def test_authenticate_invalid_username(self):
        """Test authentication with invalid username."""
        # Mock the handshake data
        handshake_data = b'handshake_data'
        
        # Test authentication with invalid username
        with self.assertRaises(AuthError):
            self.access_control.authenticate(
                'nonexistent_user',
                'testpass',
                handshake_data
            )
    
    def test_authenticate_invalid_password(self):
        """Test authentication with invalid password."""
        # Mock the handshake data
        handshake_data = b'handshake_data'
        
        # Test authentication with invalid password
        with self.assertRaises(AuthError):
            self.access_control.authenticate(
                'testuser',
                'wrongpassword',
                handshake_data
            )
    
    def test_authenticate_disabled(self):
        """Test authentication when disabled."""
        # Disable authentication
        self.access_control.enabled = False
        
        # Mock the handshake data
        handshake_data = b'handshake_data'
        
        # Test authentication (should always succeed when disabled)
        result = self.access_control.authenticate(
            'anyuser',
            'anypassword',
            handshake_data
        )
        
        # Verify the result (should use a default IP)
        self.assertEqual(result['username'], 'anonymous')
        self.assertTrue(result['ip'].startswith('10.8.0.'))


if __name__ == '__main__':
    unittest.main()
