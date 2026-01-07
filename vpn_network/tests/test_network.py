"""Test cases for network module."""
import os
import socket
import unittest
import tempfile
import ipaddress
from unittest.mock import patch, MagicMock, ANY

# Add the project root to the Python path
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.network.interface import TunInterface, UDPSocket, NetworkInterface, NetworkError
from src.network.packet_handler import Packet, PacketType, PacketProcessor, DataPacket, HandshakePacket

class TestTunInterface(unittest.TestCase):
    """Test cases for TunInterface class."""
    
    @patch('os.system')
    @patch('os.open')
    @patch('fcntl.ioctl')
    @patch('os.fdopen')
    def test_tun_interface_creation(self, mock_fdopen, mock_ioctl, mock_open, mock_system):
        """Test creation of a TUN interface."""
        # Mock the file descriptor
        mock_fd = 123
        mock_open.return_value = mock_fd
        
        # Mock the ioctl call
        mock_ioctl.return_value = 0
        
        # Create a TUN interface
        tun = TunInterface('tun0', '10.0.0.1', '255.255.255.0', mtu=1500)
        
        # Assert that the interface was created with the correct parameters
        self.assertEqual(tun.name, 'tun0')
        self.assertEqual(tun.ip, '10.0.0.1')
        self.assertEqual(tun.netmask, '255.255.255.0')
        self.assertEqual(tun.mtu, 1500)
        
        # Verify that the necessary system calls were made
        mock_system.assert_called()
        mock_ioctl.assert_called()
        mock_open.assert_called_with('/dev/net/tun', os.O_RDWR)
    
    @patch('os.system')
    @patch('os.open')
    @patch('fcntl.ioctl')
    def test_tun_interface_read_write(self, mock_ioctl, mock_open, mock_system):
        """Test reading from and writing to a TUN interface."""
        # Mock the file descriptor and file object
        mock_fd = 123
        mock_file = MagicMock()
        mock_file.fileno.return_value = mock_fd
        mock_open.return_value = mock_fd
        
        # Mock the ioctl call
        mock_ioctl.return_value = 0
        
        # Create a TUN interface
        with patch('os.fdopen', return_value=mock_file):
            tun = TunInterface('tun0', '10.0.0.1', '255.255.255.0')
            
            # Test writing to the interface
            data = b'test data'
            tun.write(data)
            mock_file.write.assert_called_with(data)
            
            # Test reading from the interface
            mock_file.read.return_value = data
            result = tun.read(1024)
            self.assertEqual(result, data)
            mock_file.read.assert_called_with(1024)
    
    @patch('os.system')
    def test_tun_interface_cleanup(self, mock_system):
        """Test cleanup of a TUN interface."""
        # Create a TUN interface with a mock file descriptor
        tun = TunInterface('tun0', '10.0.0.1', '255.255.255.0')
        tun._fd = 123  # Set a mock file descriptor
        
        # Test cleanup
        tun.close()
        
        # Verify that the interface was brought down
        mock_system.assert_called_with('ip link set tun0 down')


class TestUDPSocket(unittest.TestCase):
    """Test cases for UDPSocket class."""
    
    @patch('socket.socket')
    def test_udp_socket_creation(self, mock_socket):
        """Test creation of a UDP socket."""
        # Mock the socket
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        
        # Create a UDP socket
        udp = UDPSocket('127.0.0.1', 1194)
        
        # Assert that the socket was created with the correct parameters
        self.assertEqual(udp.host, '127.0.0.1')
        self.assertEqual(udp.port, 1194)
        mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_DGRAM)
        mock_sock.setsockopt.assert_called_with(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        mock_sock.bind.assert_called_with(('127.0.0.1', 1194))
    
    @patch('socket.socket')
    def test_udp_socket_send_receive(self, mock_socket):
        """Test sending and receiving data with a UDP socket."""
        # Mock the socket
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        
        # Create a UDP socket
        udp = UDPSocket('127.0.0.1', 1194)
        
        # Test sending data
        data = b'test data'
        udp.sendto(data, ('127.0.0.1', 1195))
        mock_sock.sendto.assert_called_with(data, ('127.0.0.1', 1195))
        
        # Test receiving data
        mock_sock.recvfrom.return_value = (data, ('127.0.0.1', 1195))
        result, addr = udp.recvfrom(1024)
        self.assertEqual(result, data)
        self.assertEqual(addr, ('127.0.0.1', 1195))
        mock_sock.recvfrom.assert_called_with(1024)
    
    @patch('socket.socket')
    def test_udp_socket_timeout(self, mock_socket):
        """Test setting socket timeout."""
        # Mock the socket
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        
        # Create a UDP socket with a timeout
        udp = UDPSocket('127.0.0.1', 1194, timeout=5.0)
        
        # Verify that the timeout was set correctly
        mock_sock.settimeout.assert_called_with(5.0)
        
        # Test changing the timeout
        udp.settimeout(10.0)
        mock_sock.settimeout.assert_called_with(10.0)


class TestPacketHandler(unittest.TestCase):
    """Test cases for packet handling functionality."""
    
    def test_packet_creation(self):
        """Test creation of different packet types."""
        # Test DataPacket
        data = b'test data'
        packet = DataPacket(data)
        self.assertEqual(packet.type, PacketType.DATA)
        self.assertEqual(packet.payload, data)
        
        # Test HandshakePacket
        handshake = HandshakePacket(b'handshake data')
        self.assertEqual(handshake.type, PacketType.HANDSHAKE)
        self.assertEqual(handshake.payload, b'handshake_data')
    
    def test_packet_serialization(self):
        """Test packet serialization and deserialization."""
        # Create a packet
        data = b'test data'
        packet = DataPacket(data)
        
        # Serialize the packet
        serialized = packet.serialize()
        
        # Deserialize the packet
        deserialized = Packet.deserialize(serialized)
        
        # Verify that the deserialized packet matches the original
        self.assertEqual(deserialized.type, PacketType.DATA)
        self.assertEqual(deserialized.payload, data)
    
    def test_packet_processor(self):
        """Test packet processing with encryption and decryption."""
        # Create a packet processor with a test key
        key = b'0123456789abcdef0123456789abcdef'  # 256-bit key
        iv = b'0123456789ab'  # 96-bit IV for AES-GCM
        processor = PacketProcessor(key)
        
        # Create a test packet
        data = b'test data'
        packet = DataPacket(data)
        
        # Encrypt the packet
        encrypted = processor.encrypt_packet(packet, iv)
        
        # Decrypt the packet
        decrypted = processor.decrypt_packet(encrypted)
        
        # Verify that the decrypted packet matches the original
        self.assertEqual(decrypted.type, PacketType.DATA)
        self.assertEqual(decrypted.payload, data)


if __name__ == '__main__':
    unittest.main()
