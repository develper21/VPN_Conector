#!/usr/bin/env python3
"""
Main entry point for the VPN Security Project.
Handles both client and server modes of operation with OpenVPN and WireGuard support.
"""
import argparse
import logging
import signal
import sys
from typing import Optional, TYPE_CHECKING

from utils.logger import setup_logger
from utils.config_loader import Config
from vpn_server.server import VPNServer

if TYPE_CHECKING:
    from vpn_client.client import VPNClient

# Import new protocol integrations
try:
    from integrations.openvpn_integration import OpenVPNClient, OpenVPNServer
    from integrations.wireguard_integration import WireGuardClient, WireGuardServer, WireGuardManager
    PROTOCOLS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Protocol integrations not available: {e}")
    PROTOCOLS_AVAILABLE = False

# Import advanced features
try:
    from advanced_features.advanced_features_manager import AdvancedFeaturesManager
    ADVANCED_FEATURES_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Advanced features not available: {e}")
    ADVANCED_FEATURES_AVAILABLE = False

# Global variables for cleanup
vpn_server: Optional[VPNServer] = None
vpn_client: Optional["VPNClient"] = None
openvpn_server: Optional[OpenVPNServer] = None
openvpn_client: Optional[OpenVPNClient] = None
wireguard_server: Optional[WireGuardServer] = None
wireguard_client: Optional[WireGuardClient] = None
wireguard_manager: Optional[WireGuardManager] = None
advanced_features_manager: Optional[AdvancedFeaturesManager] = None

def signal_handler(sig, frame):
    """Handle shutdown signals gracefully."""
    print("\nShutting down VPN...")
    if vpn_server:
        vpn_server.stop()
    if vpn_client:
        vpn_client.stop()
    if openvpn_server:
        openvpn_server.stop()
    if openvpn_client:
        openvpn_client.disconnect()
    if wireguard_server:
        wireguard_server.stop()
    if wireguard_client:
        wireguard_client.disconnect()
    if wireguard_manager:
        wireguard_manager.stop()
    if advanced_features_manager:
        advanced_features_manager.shutdown()
    sys.exit(0)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Educational VPN Implementation")
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--server", action="store_true", help="Run in server mode")
    mode_group.add_argument("--client", action="store_true", help="Run in client mode")
    mode_group.add_argument("--ui", action="store_true", help="Launch desktop management UI")
    
    # Protocol selection
    protocol_group = parser.add_mutually_exclusive_group()
    protocol_group.add_argument("--protocol", choices=["legacy", "openvpn", "wireguard"], 
                               default="legacy", help="VPN protocol to use")
    protocol_group.add_argument("--openvpn", action="store_true", help="Use OpenVPN protocol")
    protocol_group.add_argument("--wireguard", action="store_true", help="Use WireGuard protocol")
    
    # Common arguments
    parser.add_argument("--config", default="config/vpn_config.json", 
                       help="Path to configuration file")
    parser.add_argument("--log-level", default="INFO", 
                       choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                       help="Set the logging level")
    
    # Server-specific arguments
    server_group = parser.add_argument_group('server', 'Server specific arguments')
    server_group.add_argument("--host", help="Server host address")
    server_group.add_argument("--port", type=int, help="Server port")
    
    # Client-specific arguments
    client_group = parser.add_argument_group('client', 'Client specific arguments')
    client_group.add_argument("--server-address", help="Server address to connect to")
    client_group.add_argument("--server-port", type=int, 
                            help="Server port to connect to")
    
    return parser.parse_args()

def main():
    """Main entry point for the VPN application."""
    global vpn_server, vpn_client, openvpn_server, openvpn_client, wireguard_server, wireguard_client, wireguard_manager, advanced_features_manager
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Determine protocol
    protocol = "legacy"
    if args.openvpn:
        protocol = "openvpn"
    elif args.wireguard:
        protocol = "wireguard"
    elif args.protocol != "legacy":
        protocol = args.protocol
    
    if args.ui:
        try:
            from ui.app import run_ui
        except ImportError as exc:
            print(f"Failed to import UI components: {exc}")
            sys.exit(1)

        return run_ui(config_path=args.config, log_level=args.log_level)

    # Set up logging
    logger = setup_logger("vpn_main", args.log_level)
    logger.info(f"Starting VPN Security Project with protocol: {protocol}")
    
    # Load configuration
    try:
        config = Config(args.config)
        config_data = config.to_dict()
        logger.info(f"Configuration loaded from {args.config}")
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)
    
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Initialize advanced features manager
    if ADVANCED_FEATURES_AVAILABLE:
        try:
            advanced_features_manager = AdvancedFeaturesManager()
            logger.info("Advanced features manager initialized")
        except Exception as e:
            logger.error(f"Failed to initialize advanced features: {e}")
            advanced_features_manager = None
    
    try:
        if args.server:
            # Server mode
            logger.info(f"Starting SERVER mode with {protocol} protocol")
            
            if protocol == "openvpn":
                if not PROTOCOLS_AVAILABLE:
                    logger.error("OpenVPN protocol not available")
                    sys.exit(1)
                
                openvpn_server = OpenVPNServer(config_data)
                openvpn_server.start()
                
            elif protocol == "wireguard":
                if not PROTOCOLS_AVAILABLE:
                    logger.error("WireGuard protocol not available")
                    sys.exit(1)
                
                wireguard_server = WireGuardServer(config_data)
                wireguard_server.start()
                
            else:
                # Legacy VPN server
                vpn_server = VPNServer(config_data)
                vpn_server.start()
                
        elif args.client:
            # Client mode
            logger.info(f"Starting CLIENT mode with {protocol} protocol")
            
            if protocol == "openvpn":
                if not PROTOCOLS_AVAILABLE:
                    logger.error("OpenVPN protocol not available")
                    sys.exit(1)
                
                openvpn_client = OpenVPNClient(config_data)
                server_host = args.server_address or config_data.get('client', {}).get('server_host', '127.0.0.1')
                server_port = args.server_port or config_data.get('client', {}).get('server_port', 1194)
                
                if openvpn_client.connect(server_host, server_port):
                    logger.info("OpenVPN client connected successfully")
                    
                    # Activate advanced features
                    if advanced_features_manager:
                        advanced_features_manager.on_vpn_connected("tun0")
                    
                    # Keep the client running
                    while True:
                        try:
                            command = input("Enter command (or 'exit' to quit): ")
                            if command.lower() == 'exit':
                                break
                        except KeyboardInterrupt:
                            break
                        except Exception as e:
                            logger.error(f"Error in client: {e}")
                            break
                else:
                    logger.error("Failed to connect OpenVPN client")
                    sys.exit(1)
                    
            elif protocol == "wireguard":
                if not PROTOCOLS_AVAILABLE:
                    logger.error("WireGuard protocol not available")
                    sys.exit(1)
                
                wireguard_client = WireGuardClient(config_data)
                server_host = args.server_address or config_data.get('client', {}).get('server_host', '127.0.0.1')
                server_port = args.server_port or config_data.get('wireguard', {}).get('port', 51820)
                
                # For WireGuard, we need the server's public key
                server_public_key_hex = input("Enter server public key (hex): ").strip()
                try:
                    server_public_key = bytes.fromhex(server_public_key_hex)
                except ValueError:
                    logger.error("Invalid server public key format")
                    sys.exit(1)
                
                if wireguard_client.connect(server_host, server_port, server_public_key):
                    logger.info("WireGuard client connected successfully")
                    
                    # Activate advanced features
                    if advanced_features_manager:
                        advanced_features_manager.on_vpn_connected("wg0")
                    
                    # Keep the client running
                    while True:
                        try:
                            command = input("Enter command (or 'exit' to quit): ")
                            if command.lower() == 'exit':
                                break
                        except KeyboardInterrupt:
                            break
                        except Exception as e:
                            logger.error(f"Error in client: {e}")
                            break
                else:
                    logger.error("Failed to connect WireGuard client")
                    sys.exit(1)
                    
            else:
                # Legacy VPN client
                from vpn_client.client import VPNClient  # Local import to avoid unnecessary dependency loading
                vpn_client = VPNClient(config_data)
                vpn_client.connect()
                
                # Activate advanced features
                if advanced_features_manager:
                    advanced_features_manager.on_vpn_connected("tun0")
                
                # Keep the client running
                while True:
                    try:
                        command = input("Enter command (or 'exit' to quit): ")
                        if command.lower() == 'exit':
                            break
                    except KeyboardInterrupt:
                        break
                    except Exception as e:
                        logger.error(f"Error in client: {e}")
                        break
                
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user")
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        # Cleanup
        if advanced_features_manager:
            advanced_features_manager.on_vpn_disconnected()
            advanced_features_manager.shutdown()
        if vpn_server:
            vpn_server.stop()
        if vpn_client:
            vpn_client.disconnect()
        if openvpn_server:
            openvpn_server.stop()
        if openvpn_client:
            openvpn_client.disconnect()
        if wireguard_server:
            wireguard_server.stop()
        if wireguard_client:
            wireguard_client.disconnect()
        if wireguard_manager:
            wireguard_manager.stop()
        if getattr(args, "ui", False):
            logger.debug("UI mode terminated")
        logger.info("VPN application stopped")

if __name__ == "__main__":
    main()
