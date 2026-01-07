#!/usr/bin/env python3
"""
Main entry point for the VPN Security Project.
Handles both client and server modes of operation.
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

# Global variables for cleanup
vpn_server: Optional[VPNServer] = None
vpn_client: Optional["VPNClient"] = None

def signal_handler(sig, frame):
    """Handle shutdown signals gracefully."""
    print("\nShutting down VPN...")
    if vpn_server:
        vpn_server.stop()
    if vpn_client:
        vpn_client.stop()
    sys.exit(0)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Educational VPN Implementation")
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--server", action="store_true", help="Run in server mode")
    mode_group.add_argument("--client", action="store_true", help="Run in client mode")
    mode_group.add_argument("--ui", action="store_true", help="Launch desktop management UI")
    
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
    global vpn_server, vpn_client
    
    # Parse command line arguments
    args = parse_arguments()
    
    if args.ui:
        try:
            from ui.app import run_ui
        except ImportError as exc:
            print(f"Failed to import UI components: {exc}")
            sys.exit(1)

        return run_ui(config_path=args.config, log_level=args.log_level)

    # Set up logging
    logger = setup_logger("vpn_main", args.log_level)
    logger.info("Starting VPN Security Project")
    
    # Load configuration
    try:
        config = Config(args.config)
        logger.info(f"Configuration loaded from {args.config}")
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)
    
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        config_data = config.to_dict()
        if args.server:
            # Server mode
            logger.info("Starting in SERVER mode")
            vpn_server = VPNServer(config_data)
            vpn_server.start()
        elif args.client:
            # Client mode
            logger.info("Starting in CLIENT mode")
            from vpn_client.client import VPNClient  # Local import to avoid unnecessary dependency loading
            vpn_client = VPNClient(config_data)
            vpn_client.connect()
            
            # Keep the client running
            while True:
                try:
                    # Main client loop - could be used for command input
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
        if vpn_server:
            vpn_server.stop()
        if vpn_client:
            vpn_client.disconnect()
        if getattr(args, "ui", False):
            logger.debug("UI mode terminated")
        logger.info("VPN application stopped")

if __name__ == "__main__":
    main()
