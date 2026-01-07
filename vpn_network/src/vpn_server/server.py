"""
VPN Server Implementation

This module implements the main VPN server that handles client connections,
manages encryption, and routes traffic between clients and the network.
"""
import os
import sys
import time
import select
import logging
import threading
import ipaddress
from typing import Dict, List, Tuple, Optional, Set, Callable, Any
from dataclasses import dataclass, field
from enum import Enum, auto

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from network.interface import UDPSocket, NetworkError, create_udp_socket
from network.packet_handler import (
    Packet, PacketHeader, PacketType, PacketProcessor, 
    EncryptionMethod, DecryptionError, PacketError
)
from .tunnel_manager import TunnelManager
from .access_control import AccessControl
from utils.logger import LoggableMixin
from utils.validator import (
    validate_ip_address, validate_port, validate_boolean,
    validate_integer, validate_string, validate_dict
)

class ClientState(Enum):
    """Client connection states."""
    DISCONNECTED = auto()
    HANDSHAKE_INIT = auto()
    HANDSHAKE_RESP = auto()
    CONNECTED = auto()
    ERROR = auto()

@dataclass
class ClientSession(LoggableMixin):
    """Represents a connected VPN client session."""
    client_id: str
    address: Tuple[str, int]
    state: ClientState = ClientState.DISCONNECTED
    last_seen: float = field(default_factory=time.time)
    public_key: Optional[bytes] = None
    shared_secret: Optional[bytes] = None
    cipher: Optional[AESGCM] = None
    hmac_key: Optional[bytes] = None
    virtual_ip: Optional[str] = None
    
    def __post_init__(self):
        """Initialize the logger for this session."""
        self.logger = logging.getLogger(f"{__name__}.ClientSession-{self.client_id[:8]}")
    
    def update_last_seen(self):
        """Update the last seen timestamp."""
        self.last_seen = time.time()
    
    def is_expired(self, timeout: float) -> bool:
        """Check if the session has expired."""
        return (time.time() - self.last_seen) > timeout
    
    def setup_encryption(self, server_private_key: ec.EllipticCurvePrivateKey):
        """Set up encryption for this session."""
        if not self.public_key:
            raise ValueError("No public key provided for encryption setup")
        
        try:
            # Load the client's public key
            client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(),
                self.public_key
            )
            
            # Perform key exchange
            self.shared_secret = server_private_key.exchange(
                ec.ECDH(),
                client_public_key
            )
            
            # Derive encryption and HMAC keys
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=64,  # 32 bytes for AES-256 key + 32 bytes for HMAC key
                salt=None,
                info=b'vpn-key-derivation',
            )
            
            # Split the derived key material
            key_material = hkdf.derive(self.shared_secret)
            encryption_key = key_material[:32]
            self.hmac_key = key_material[32:]
            
            # Initialize the cipher
            self.cipher = AESGCM(encryption_key)
            
            self.logger.debug("Encryption setup complete")
            
        except Exception as e:
            self.logger.error(f"Failed to set up encryption: {e}")
            raise

class VPNServer(LoggableMixin):
    """
    Main VPN server class that handles client connections and traffic routing.
    """
    
    def __init__(
        self,
        config: dict,
        private_key: Optional[ec.EllipticCurvePrivateKey] = None,
        **kwargs
    ):
        """
        Initialize the VPN server.
        
        Args:
            config: Server configuration dictionary.
            private_key: Optional private key for the server. If not provided,
                        a new one will be generated.
            **kwargs: Additional keyword arguments for LoggableMixin.
        """
        super().__init__(**kwargs)
        
        # Configuration
        self.config = self._validate_config(config)
        self.host = self.config['server']['host']
        self.port = self.config['server']['port']
        self.protocol = self.config['server']['protocol'].lower()
        self.max_clients = self.config['server']['max_clients']
        
        # Server state
        self._running = False
        self._shutdown_event = threading.Event()
        self._clients_lock = threading.RLock()
        self._sessions: Dict[Tuple[str, int], ClientSession] = {}
        self._virtual_ips: Set[str] = set()
        
        # Network components
        self._socket: Optional[UDPSocket] = None
        self._packet_processor = PacketProcessor()
        
        # Generate or use provided private key
        self.private_key = private_key or ec.generate_private_key(
            ec.SECP256R1()
        )
        
        # Derive public key
        self.public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        # Initialize tunnel manager and access control
        self.tunnel_manager = TunnelManager(
            tunnel_network=self.config['network']['tunnel_ip'],
            netmask=self.config['network']['tunnel_netmask'],
            dns_servers=self.config['network']['dns_servers']
        )
        
        self.access_control = AccessControl()
        
        # Setup logging
        self._setup_logging()
        
        self.logger.info("VPN Server initialized")
    
    def _validate_config(self, config: dict) -> dict:
        """Validate and normalize the server configuration."""
        schema = {
            'server': {
                'host': (str, True),
                'port': (int, True),
                'protocol': (str, True),
                'max_clients': (int, True),
                'keepalive': (str, False)
            },
            'security': {
                'cipher': (str, True),
                'auth': (str, True),
                'tls_version': (str, False),
                'key_exchange': (str, False),
                'certificate_authority': (str, False),
                'certificate': (str, False),
                'private_key': (str, False)
            },
            'network': {
                'tunnel_ip': (str, True),
                'tunnel_netmask': (str, True),
                'dns_servers': (list, False)
            },
            'logging': {
                'level': (str, False),
                'file': (str, False),
                'max_size_mb': (int, False),
                'backup_count': (int, False)
            }
        }
        
        return validate_dict(config, schema, allow_extra=True)
    
    def _setup_logging(self):
        """Configure logging for the server."""
        log_config = self.config.get('logging', {})
        log_level = getattr(logging, log_config.get('level', 'INFO'), logging.INFO)
        
        # Configure root logger
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler()]
        )
        
        # Add file handler if configured
        log_file = log_config.get('file')
        if log_file:
            from logging.handlers import RotatingFileHandler
            
            max_bytes = log_config.get('max_size_mb', 10) * 1024 * 1024
            backup_count = log_config.get('backup_count', 5)
            
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setFormatter(
                logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            )
            
            root_logger = logging.getLogger()
            root_logger.addHandler(file_handler)
            
            self.logger.info(f"Logging to file: {log_file}")
    
    def start(self) -> None:
        """Start the VPN server."""
        if self._running:
            self.logger.warning("Server is already running")
            return
        
        try:
            self.logger.info(f"Starting VPN server on {self.host}:{self.port} ({self.protocol.upper()})")
            
            # Create and bind the socket
            self._socket = create_udp_socket(
                local_addr=(self.host, self.port)
            )

            # Ensure the underlying socket is open before configuring options
            if not self._socket.is_open:
                self._socket.open()
            
            # Start the server threads
            self._running = True
            self._shutdown_event.clear()
            
            # Start the main server loop in a separate thread
            self._server_thread = threading.Thread(
                target=self._run_server,
                name="VPNServer-Main",
                daemon=True
            )
            self._server_thread.start()
            
            # Start the keepalive thread
            self._keepalive_thread = threading.Thread(
                target=self._keepalive_loop,
                name="VPNServer-Keepalive",
                daemon=True
            )
            self._keepalive_thread.start()
            
            self.logger.info("VPN server started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}", exc_info=True)
            self.stop()
            raise
    
    def stop(self) -> None:
        """Stop the VPN server and clean up resources."""
        if not self._running:
            return
        
        self.logger.info("Stopping VPN server...")
        
        # Signal threads to stop
        self._running = False
        self._shutdown_event.set()
        
        # Close all client sessions
        with self._clients_lock:
            for session in list(self._sessions.values()):
                self._disconnect_client(session)
            self._sessions.clear()
        
        # Close the socket
        if self._socket:
            try:
                self._socket.close()
            except Exception as e:
                self.logger.error(f"Error closing socket: {e}")
            finally:
                self._socket = None
        
        # Wait for threads to finish
        if hasattr(self, '_server_thread'):
            self._server_thread.join(timeout=5.0)
        
        if hasattr(self, '_keepalive_thread'):
            self._keepalive_thread.join(timeout=2.0)
        
        self.logger.info("VPN server stopped")
    
    def _run_server(self) -> None:
        """Main server loop that handles incoming connections and data."""
        self.logger.debug("Starting server main loop")
        
        try:
            while self._running:
                try:
                    # Process incoming data
                    self._socket.process(timeout=1.0)
                    
                    # Process any pending packets
                    self._process_incoming()
                    
                    # Check for inactive clients
                    self._check_inactive_clients()
                    
                except (OSError, select.error) as e:
                    if self._running:
                        self.logger.error(f"Network error in server loop: {e}")
                        time.sleep(1)  # Prevent tight loop on error
                except Exception as e:
                    self.logger.error(f"Unexpected error in server loop: {e}", exc_info=True)
                    time.sleep(1)  # Prevent tight loop on error
                    
        except KeyboardInterrupt:
            self.logger.info("Server shutdown requested")
        except Exception as e:
            self.logger.critical(f"Fatal error in server loop: {e}", exc_info=True)
        finally:
            self.stop()
    
    def _process_incoming(self) -> None:
        """Process incoming data from clients."""
        try:
            while True:
                # Receive data from the socket
                try:
                    data, addr = self._socket.recv(65535)
                    if not data:
                        break
                        
                    # Process the packet
                    self._handle_packet(data, addr)
                    
                except BlockingIOError:
                    # No more data to read
                    break
                except ConnectionResetError:
                    # Client reset the connection
                    self.logger.warning(f"Connection reset by client {addr}")
                    self._remove_client(addr)
                    break
                except Exception as e:
                    self.logger.error(f"Error processing incoming data: {e}", exc_info=True)
                    break
                    
        except Exception as e:
            self.logger.error(f"Error in process_incoming: {e}", exc_info=True)
    
    def _handle_packet(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle an incoming packet from a client."""
        try:
            # Get or create a session for this client
            session = self._get_or_create_session(addr)
            
            # Update last seen time
            session.update_last_seen()
            
            # Process the packet
            try:
                # For handshake packets, don't use encryption
                if len(data) > 1 and data[4] in (PacketType.HANDSHAKE_INIT, 
                                               PacketType.HANDSHAKE_RESP,
                                               PacketType.HANDSHAKE_FIN):
                    packet = self._packet_processor.process_packet(data)
                else:
                    # For encrypted packets, use the session's packet processor
                    if not hasattr(session, 'packet_processor'):
                        raise PacketError("No encryption set up for session")
                    
                    packet = session.packet_processor.process_packet(data)
            
            except (DecryptionError, PacketError) as e:
                self.logger.warning(f"Invalid packet from {addr}: {e}")
                self._disconnect_client(session)
                return
            
            # Handle the packet based on its type
            if packet.header.packet_type == PacketType.HANDSHAKE_INIT:
                self._handle_handshake_init(packet, session)
            elif packet.header.packet_type == PacketType.HANDSHAKE_RESP:
                self._handle_handshake_response(packet, session)
            elif packet.header.packet_type == PacketType.HANDSHAKE_FIN:
                self._handle_handshake_finish(packet, session)
            elif packet.header.packet_type == PacketType.DATA:
                self._handle_data(packet, session)
            elif packet.header.packet_type == PacketType.KEEPALIVE:
                self._handle_keepalive(packet, session)
            else:
                self.logger.warning(f"Unhandled packet type: {packet.header.packet_type}")
                
        except Exception as e:
            self.logger.error(f"Error handling packet from {addr}: {e}", exc_info=True)
    
    def _handle_handshake_init(self, packet: Packet, session: ClientSession) -> None:
        """Handle handshake initiation from a client."""
        if session.state != ClientState.DISCONNECTED:
            self.logger.warning(f"Unexpected handshake init from {session.client_id} in state {session.state}")
            return
        
        try:
            # Extract client's public key
            session.public_key = packet.payload
            
            # Perform key exchange
            session.setup_encryption(self.private_key)
            
            # Generate a unique client ID if not set
            if not session.client_id:
                session.client_id = f"client-{os.urandom(4).hex()}"
            
            # Allocate a virtual IP for this client
            session.virtual_ip = self.tunnel_manager.allocate_ip()
            if not session.virtual_ip:
                raise RuntimeError("No available IP addresses in the tunnel network")
            
            # Initialize packet processor for this session
            session.packet_processor = PacketProcessor(
                encryption_key=session.cipher._key,
                hmac_key=session.hmac_key
            )
            
            # Create handshake response
            response = session.packet_processor.create_handshake_response(
                self.public_key,
                session.virtual_ip.encode()
            )
            
            # Send the response
            self._send_data(response, session.address)
            
            # Update session state
            session.state = ClientState.HANDSHAKE_RESP
            
            self.logger.info(f"Handshake initiated with {session.client_id} ({session.virtual_ip})")
            
        except Exception as e:
            self.logger.error(f"Handshake init failed for {session.client_id}: {e}", exc_info=True)
            self._disconnect_client(session)
    
    def _handle_handshake_response(self, packet: Packet, session: ClientSession) -> None:
        """Handle handshake response (server-side, should not be called)."""
        self.logger.warning(f"Unexpected handshake response from {session.client_id}")
        self._disconnect_client(session)
    
    def _handle_handshake_finish(self, packet: Packet, session: ClientSession) -> None:
        """Handle handshake finalization from a client."""
        if session.state != ClientState.HANDSHAKE_RESP:
            self.logger.warning(f"Unexpected handshake finish from {session.client_id} in state {session.state}")
            return
        
        try:
            # Verify the handshake
            if not session.packet_processor:
                raise ValueError("No packet processor for session")
            
            # Update session state
            session.state = ClientState.CONNECTED
            
            # Add routes for this client
            self.tunnel_manager.add_route(session.virtual_ip, session.address)
            
            self.logger.info(f"Client {session.client_id} connected with IP {session.virtual_ip}")
            
            # Send a keepalive to complete the connection
            self._send_keepalive(session)
            
        except Exception as e:
            self.logger.error(f"Handshake finish failed for {session.client_id}: {e}", exc_info=True)
            self._disconnect_client(session)
    
    def _handle_data(self, packet: Packet, session: ClientSession) -> None:
        """Handle a data packet from a client."""
        if session.state != ClientState.CONNECTED:
            self.logger.warning(f"Data packet from {session.client_id} in non-connected state: {session.state}")
            return
        
        try:
            # Process the packet (decryption already done in _handle_packet)
            # Here you would typically route the packet to the appropriate destination
            # For now, just log it
            self.logger.debug(f"Received {len(packet.payload)} bytes from {session.client_id}")
            
            # Example: Echo the data back to the client
            # In a real VPN, you would route this to the appropriate destination
            # self._send_data(packet.payload, session.address)
            
        except Exception as e:
            self.logger.error(f"Error handling data from {session.client_id}: {e}", exc_info=True)
    
    def _handle_keepalive(self, packet: Packet, session: ClientSession) -> None:
        """Handle a keepalive packet."""
        self.logger.debug(f"Keepalive from {session.client_id}")
        # Just update the last seen time, which is already done in _handle_packet
    
    def _send_data(self, data: bytes, address: Tuple[str, int]) -> None:
        """Send data to a client."""
        try:
            self._socket.send(data, address)
        except Exception as e:
            self.logger.error(f"Error sending data to {address}: {e}")
    
    def _send_keepalive(self, session: ClientSession) -> None:
        """Send a keepalive packet to a client."""
        if not session.packet_processor:
            return
            
        keepalive = session.packet_processor.create_keepalive()
        self._send_data(keepalive, session.address)
    
    def _get_or_create_session(self, address: Tuple[str, int]) -> ClientSession:
        """Get or create a session for the given address."""
        with self._clients_lock:
            if address in self._sessions:
                return self._sessions[address]
            
            # Create a new session
            session = ClientSession(
                client_id=f"client-{os.urandom(4).hex()}",
                address=address
            )
            
            self._sessions[address] = session
            self.logger.info(f"New client connected: {address} ({session.client_id})")
            
            return session
    
    def _remove_client(self, address: Tuple[str, int]) -> None:
        """Remove a client session."""
        with self._clients_lock:
            if address not in self._sessions:
                return
            
            session = self._sessions[address]
            self._disconnect_client(session)
            
    def _disconnect_client(self, session: ClientSession) -> None:
        """Disconnect a client and clean up resources."""
        with self._clients_lock:
            if session.address in self._sessions:
                del self._sessions[session.address]
            
            # Release the virtual IP
            if session.virtual_ip:
                self.tunnel_manager.release_ip(session.virtual_ip)
            
            self.logger.info(f"Client disconnected: {session.client_id} ({session.virtual_ip or 'no IP'})")
    
    def _check_inactive_clients(self) -> None:
        """Check for and disconnect inactive clients."""
        timeout = 300  # 5 minutes
        now = time.time()
        
        with self._clients_lock:
            to_remove = [
                addr for addr, session in self._sessions.items()
                if now - session.last_seen > timeout
            ]
            
            for addr in to_remove:
                self.logger.info(f"Disconnecting inactive client: {addr}")
                self._disconnect_client(self._sessions[addr])
    
    def _keepalive_loop(self) -> None:
        """Send keepalive packets to connected clients."""
        keepalive_interval = 30  # seconds
        
        while self._running:
            try:
                # Send keepalive to all connected clients
                with self._clients_lock:
                    for session in list(self._sessions.values()):
                        if session.state == ClientState.CONNECTED:
                            self._send_keepalive(session)
                
                # Sleep for the keepalive interval
                self._shutdown_event.wait(keepalive_interval)
                
            except Exception as e:
                self.logger.error(f"Error in keepalive loop: {e}", exc_info=True)
                time.sleep(1)  # Prevent tight loop on error
    
    def get_connected_clients(self) -> List[Dict[str, Any]]:
        """Get information about connected clients."""
        with self._clients_lock:
            return [
                {
                    'client_id': session.client_id,
                    'address': f"{session.address[0]}:{session.address[1]}",
                    'virtual_ip': session.virtual_ip,
                    'state': session.state.name,
                    'last_seen': time.strftime(
                        '%Y-%m-%d %H:%M:%S',
                        time.localtime(session.last_seen)
                    ),
                    'bytes_sent': 0,  # TODO: Track bytes sent/received
                    'bytes_received': 0
                }
                for session in self._sessions.values()
            ]

# Example usage
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="VPN Server")
    parser.add_argument("--config", "-c", default="config/vpn_config.json",
                       help="Path to configuration file")
    parser.add_argument("--host", default="0.0.0.0",
                       help="Host to bind to (overrides config)")
    parser.add_argument("--port", type=int, default=1194,
                       help="Port to listen on (overrides config)")
    parser.add_argument("--debug", action="store_true",
                       help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Load configuration
    import json
    with open(args.config, 'r') as f:
        config = json.load(f)
    
    # Override config with command line arguments
    if args.host:
        config['server']['host'] = args.host
    if args.port:
        config['server']['port'] = args.port
    
    # Set up logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and start the server
    server = VPNServer(config)
    
    try:
        server.start()
        
        # Keep the main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.stop()
