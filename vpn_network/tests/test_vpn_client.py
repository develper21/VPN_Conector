"""
Test cases for VPN client functionality.
"""
import os
import sys
import time
import socket
import unittest
import tempfile
import threading
from unittest.mock import patch, MagicMock, ANY

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.vpn_client.client import VPNClient, VPNClientError
from src.vpn_client.connection_manager import ConnectionManager, ConnectionState
from src.vpn_client.authentication import ClientAuthenticator, AuthMethod
from src.network.interface import UDPSocket, NetworkError
from src.network.packet_handler import Packet, PacketType, DataPacket, HandshakePacket
from src.security.encryption import EncryptionManager, CipherAlgorithm
from src.security.key_exchange import ECDHKeyExchange

class MockUDPSocket:
    """Mock UDP socket for testing."""
    def __init__(self):
        self.recv_queue = []
        self.sent_data = []
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
    
    def queue_receive(self, data, addr=('127.0.0.1', 1194)):
        """Queue data to be received by recvfrom."""
        self.recv_queue.append((data, addr))


class TestVPNClient(unittest.TestCase):
    """Test cases for VPNClient class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for test files
        self.test_dir = tempfile.TemporaryDirectory()
        
        # Create a mock configuration
        self.config = {
            'server': {
                'host': '127.0.0.1',
                'port': 1194,
                'protocol': 'udp',
                'timeout': 5.0,
                'keepalive': 30
            },
            'security': {
                'cipher': 'AES-256-GCM',
                'auth': 'SHA256',
                'tls_version': 'TLSv1.3',
                'key_exchange': 'ECDH'
            },
            'tunnel': {
                'ip': '10.8.0.2',
                'netmask': '255.255.255.0',
                'dns_servers': ['8.8.8.8', '8.8.4.4'],
                'mtu': 1500
            },
            'authentication': {
                'method': 'password',
                'username': 'testuser',
                'password': 'testpass',
                'ca_cert': None,
                'client_cert': None,
                'client_key': None
            }
        }
        
        # Create a mock UDPSocket
        self.mock_socket = MockUDPSocket()
        
        # Patch the UDPSocket class to return our mock
        self.socket_patcher = patch('src.network.interface.socket.socket', 
                                  return_value=self.mock_socket)
        self.mock_socket_class = self.socket_patcher.start()
        
        # Create a VPN client instance
        self.client = VPNClient(self.config)
        
        # Mock the tun interface
        self.client.tun = MagicMock()
        self.client.tun.read.return_value = b'test data'
        self.client.tun.write = MagicMock()
    
    def tearDown(self):
        """Clean up test fixtures."""
        self.socket_patcher.stop()
        self.test_dir.cleanup()
    
    def test_client_initialization(self):
        """Test VPNClient initialization."""
        self.assertEqual(self.client.config, self.config)
        self.assertEqual(self.client.host, '127.0.0.1')
        self.assertEqual(self.client.port, 1194)
        self.assertIsInstance(self.client.encryption_manager, EncryptionManager)
        self.assertIsInstance(self.client.key_exchange, ECDHKeyExchange)
    
    def test_connect_success(self):
        """Test successful connection to the VPN server."""
        # Mock the handshake process
        handshake_response = HandshakePacket(b'handshake_data')
        self.mock_socket.queue_receive(handshake_response.serialize())
        
        # Mock the authentication response
        auth_response = Packet(PacketType.AUTH_RESPONSE, b'authentication_success')
        self.mock_socket.queue_receive(auth_response.serialize())
        
        # Mock the configuration response
        config_response = Packet(PacketType.CONFIG_RESPONSE, b'config_data')
        self.mock_socket.queue_receive(config_response.serialize())
        
        # Start the client in a separate thread
        client_thread = threading.Thread(target=self.client.connect)
        client_thread.daemon = True
        client_thread.start()
        
        # Wait for the client to process the handshake
        time.sleep(0.1)
        
        # Verify the connection was established
        self.assertTrue(self.client.is_connected())
        
        # Stop the client
        self.client.disconnect()
        client_thread.join(timeout=1.0)
    
    def test_send_data(self):
        """Test sending data through the VPN tunnel."""
        # Connect the client
        self.client._connected = True
        
        # Send test data
        test_data = b'test data'
        self.client.send(test_data)
        
        # Verify the data was sent
        self.assertEqual(len(self.mock_socket.sent_data), 1)
        sent_packet = Packet.deserialize(self.mock_socket.sent_data[0][0])
        self.assertEqual(sent_packet.type, PacketType.DATA)
        self.assertEqual(sent_packet.payload, test_data)
    
    def test_receive_data(self):
        """Test receiving data from the VPN tunnel."""
        # Connect the client
        self.client._connected = True
        
        # Queue a data packet to be received
        test_data = b'test data'
        data_packet = DataPacket(test_data)
        self.mock_socket.queue_receive(data_packet.serialize())
        
        # Receive the data
        received_data = self.client.receive()
        
        # Verify the data was received correctly
        self.assertEqual(received_data, test_data)
    
    def test_handle_keepalive(self):
        """Test handling of keepalive packets."""
        # Connect the client
        self.client._connected = True
        
        # Queue a keepalive packet
        keepalive_packet = Packet(PacketType.KEEPALIVE, b'')
        self.mock_socket.queue_receive(keepalive_packet.serialize())
        
        # Process the packet
        self.client._process_packets()
        
        # Verify a keepalive response was sent
        self.assertEqual(len(self.mock_socket.sent_data), 1)
        sent_packet = Packet.deserialize(self.mock_socket.sent_data[0][0])
        self.assertEqual(sent_packet.type, PacketType.KEEPALIVE)
    
    def test_handle_error(self):
        """Test handling of error packets."""
        # Connect the client
        self.client._connected = True
        
        # Queue an error packet
        error_packet = Packet(PacketType.ERROR, b'test error')
        self.mock_socket.queue_receive(error_packet.serialize())
        
        # Process the packet (should raise an exception)
        with self.assertRaises(VPNClientError):
            self.client._process_packets()
        
        # Verify the client disconnected
        self.assertFalse(self.client.is_connected())


class TestConnectionManager(unittest.TestCase):
    """Test cases for ConnectionManager class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.manager = ConnectionManager()
        self.config = {
            'host': '127.0.0.1',
            'port': 1194,
            'timeout': 5.0,
            'retry_interval': 1.0,
            'max_retries': 3
        }
    
    def test_add_connection(self):
        """Test adding a new connection."""
        conn_id = self.manager.add_connection('test_conn', self.config)
        self.assertIn(conn_id, self.manager.connections)
        self.assertEqual(self.manager.connections[conn_id].name, 'test_conn')
        self.assertEqual(self.manager.connections[conn_id].state, ConnectionState.DISCONNECTED)
    
    def test_remove_connection(self):
        """Test removing a connection."""
        conn_id = self.manager.add_connection('test_conn', self.config)
        self.manager.remove_connection(conn_id)
        self.assertNotIn(conn_id, self.manager.connections)
    
    def test_get_connection(self):
        """Test getting a connection by ID."""
        conn_id = self.manager.add_connection('test_conn', self.config)
        conn = self.manager.get_connection(conn_id)
        self.assertEqual(conn.name, 'test_conn')
    
    def test_connect_disconnect(self):
        """Test connecting and disconnecting a connection."""
        # Mock the VPN client
        mock_client = MagicMock()
        with patch('src.vpn_client.connection_manager.VPNClient', return_value=mock_client):
            conn_id = self.manager.add_connection('test_conn', self.config)
            
            # Test connecting
            self.manager.connect(conn_id)
            mock_client.connect.assert_called_once()
            self.assertEqual(self.manager.connections[conn_id].state, ConnectionState.CONNECTED)
            
            # Test disconnecting
            self.manager.disconnect(conn_id)
            mock_client.disconnect.assert_called_once()
            self.assertEqual(self.manager.connections[conn_id].state, ConnectionState.DISCONNECTED)


class TestClientAuthenticator(unittest.TestCase):
    """Test cases for ClientAuthenticator class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'method': 'password',
            'username': 'testuser',
            'password': 'testpass',
            'ca_cert': None,
            'client_cert': None,
            'client_key': None
        }
        self.authenticator = ClientAuthenticator(self.config)
    
    def test_password_authentication(self):
        """Test password-based authentication."""
        # Mock the server response
        mock_socket = MagicMock()
        mock_socket.recv.return_value = Packet(
            PacketType.AUTH_RESPONSE,
            b'authentication_success'
        ).serialize()
        
        # Test authentication
        result = self.authenticator.authenticate(mock_socket)
        self.assertTrue(result)
        
        # Verify the authentication request was sent
        mock_socket.send.assert_called_once()
        sent_packet = Packet.deserialize(mock_socket.send.call_args[0][0])
        self.assertEqual(sent_packet.type, PacketType.AUTH_REQUEST)
        self.assertIn(b'testuser', sent_packet.payload)
        self.assertIn(b'testpass', sent_packet.payload)
    
    def test_certificate_authentication(self):
        """Test certificate-based authentication."""
        # Update config to use certificate authentication
        self.config.update({
            'method': 'certificate',
            'client_cert': 'test_cert.pem',
            'client_key': 'test_key.pem'
        })
        
        # Mock the server response
        mock_socket = MagicMock()
        mock_socket.recv.return_value = Packet(
            PacketType.AUTH_RESPONSE,
            b'authentication_success'
        ).serialize()
        
        # Mock the certificate and key loading
        with patch('builtins.open', unittest.mock.mock_open(read_data='test_cert')), \
             patch('os.path.exists', return_value=True):
            # Test authentication
            result = self.authenticator.authenticate(mock_socket)
            self.assertTrue(result)
            
            # Verify the authentication request was sent
            mock_socket.send.assert_called_once()
            sent_packet = Packet.deserialize(mock_socket.send.call_args[0][0])
            self.assertEqual(sent_packet.type, PacketType.AUTH_REQUEST)
            self.assertIn(b'certificate', sent_packet.payload.lower())


if __name__ == '__main__':
    unittest.main()
