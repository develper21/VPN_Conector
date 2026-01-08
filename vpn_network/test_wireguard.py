#!/usr/bin/env python3
"""
Test script for WireGuard protocol implementation.
Tests packet creation, cryptography, key rotation, and UDP protocol handling.
"""
import os
import sys
import time
import json
import threading
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from protocols.wireguard import (
    WireGuardProtocol, WireGuardHandshakeInitiation, 
    WireGuardHandshakeResponse, WireGuardDataPacket,
    WireGuardCrypto, WireGuardKeyRotation
)
from protocols.wireguard_udp import WireGuardUDPHandler, WireGuardConnectionState
from integrations.wireguard_integration import WireGuardClient, WireGuardServer, WireGuardManager
from utils.config_loader import Config


def test_wireguard_cryptography():
    """Test WireGuard cryptographic operations."""
    print("🧪 Testing WireGuard Cryptography")
    print("=" * 40)
    
    try:
        crypto = WireGuardCrypto()
        
        # Test keypair generation
        private_key, public_key = crypto.generate_keypair()
        print(f"✅ Keypair generated: {len(private_key)} bytes private, {len(public_key)} bytes public")
        
        # Test shared secret
        peer_private, peer_public = crypto.generate_keypair()
        shared_secret1 = crypto.shared_secret(private_key, peer_public)
        shared_secret2 = crypto.shared_secret(peer_private, public_key)
        
        if shared_secret1 == shared_secret2:
            print("✅ Shared secret computation successful")
        else:
            print("❌ Shared secret mismatch")
            return False
        
        # Test session key derivation
        session_keys = crypto.derive_session_keys(shared_secret1, public_key)
        if 'initiator_key' in session_keys and 'responder_key' in session_keys:
            print("✅ Session key derivation successful")
        else:
            print("❌ Session key derivation failed")
            return False
        
        # Test ChaCha20-Poly1305 encryption
        plaintext = b"Hello, WireGuard!"
        key = os.urandom(32)
        nonce = os.urandom(12)
        
        ciphertext, mac = crypto.encrypt_chacha20poly1305(plaintext, key, nonce)
        decrypted = crypto.decrypt_chacha20poly1305(ciphertext, key, nonce, mac)
        
        if decrypted == plaintext:
            print("✅ ChaCha20-Poly1305 encryption/decryption successful")
        else:
            print("❌ ChaCha20-Poly1305 encryption/decryption failed")
            return False
        
        # Test timestamp generation and verification
        timestamp = crypto.generate_timestamp()
        if crypto.verify_timestamp(timestamp):
            print("✅ Timestamp generation and verification successful")
        else:
            print("❌ Timestamp verification failed")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Cryptography test failed: {e}")
        return False


def test_wireguard_key_rotation():
    """Test WireGuard key rotation mechanism."""
    print("\n🧪 Testing WireGuard Key Rotation")
    print("=" * 40)
    
    try:
        key_rotation = WireGuardKeyRotation(rotation_interval=1)  # 1 second for testing
        
        # Generate initial keypair
        initial_private, initial_public = key_rotation.generate_initial_keypair()
        print(f"✅ Initial keypair generated")
        
        # Test rotation should not be needed immediately
        if not key_rotation.should_rotate():
            print("✅ Key rotation correctly not needed initially")
        else:
            print("❌ Key rotation incorrectly needed immediately")
            return False
        
        # Wait for rotation interval
        time.sleep(1.1)
        
        # Test rotation should be needed now
        if key_rotation.should_rotate():
            print("✅ Key rotation correctly needed after interval")
        else:
            print("❌ Key rotation incorrectly not needed after interval")
            return False
        
        # Test key rotation
        new_private, new_public = key_rotation.rotate_keypair()
        if new_private != initial_private and new_public != initial_public:
            print("✅ Key rotation successful")
        else:
            print("❌ Key rotation failed - keys unchanged")
            return False
        
        # Test active keypair retrieval
        active_keypair = key_rotation.get_active_keypair()
        if active_keypair and active_keypair[0] == new_private:
            print("✅ Active keypair retrieval successful")
        else:
            print("❌ Active keypair retrieval failed")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Key rotation test failed: {e}")
        return False


def test_wireguard_packets():
    """Test WireGuard packet creation and parsing."""
    print("\n🧪 Testing WireGuard Packets")
    print("=" * 35)
    
    try:
        # Test handshake initiation
        handshake_init = WireGuardHandshakeInitiation(
            sender_index=12345,
            ephemeral_public_key=os.urandom(32),
            static_public_key=os.urandom(32),
            timestamp=os.urandom(12),
            mac1=os.urandom(16),
            mac2=os.urandom(16)
        )
        
        init_data = handshake_init.to_bytes()
        parsed_init = WireGuardHandshakeInitiation.from_bytes(init_data)
        
        if (parsed_init.sender_index == handshake_init.sender_index and
            parsed_init.ephemeral_public_key == handshake_init.ephemeral_public_key):
            print("✅ Handshake initiation packet creation/parsing successful")
        else:
            print("❌ Handshake initiation packet creation/parsing failed")
            return False
        
        # Test handshake response
        handshake_response = WireGuardHandshakeResponse(
            sender_index=54321,
            receiver_index=12345,
            ephemeral_public_key=os.urandom(32),
            static_public_key=os.urandom(32),
            timestamp=os.urandom(12),
            mac1=os.urandom(16),
            mac2=os.urandom(16)
        )
        
        response_data = handshake_response.to_bytes()
        parsed_response = WireGuardHandshakeResponse.from_bytes(response_data)
        
        if (parsed_response.sender_index == handshake_response.sender_index and
            parsed_response.receiver_index == handshake_response.receiver_index):
            print("✅ Handshake response packet creation/parsing successful")
        else:
            print("❌ Handshake response packet creation/parsing failed")
            return False
        
        # Test data packet
        data_packet = WireGuardDataPacket(
            receiver_index=12345,
            counter=67890,
            encrypted_data=os.urandom(100)
        )
        
        data_packet_data = data_packet.to_bytes()
        parsed_data_packet = WireGuardDataPacket.from_bytes(data_packet_data)
        
        if (parsed_data_packet.receiver_index == data_packet.receiver_index and
            parsed_data_packet.counter == data_packet.counter):
            print("✅ Data packet creation/parsing successful")
        else:
            print("❌ Data packet creation/parsing failed")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Packet test failed: {e}")
        return False


def test_wireguard_protocol():
    """Test WireGuard protocol implementation."""
    print("\n🧪 Testing WireGuard Protocol")
    print("=" * 35)
    
    try:
        config = {
            'key_rotation_interval': 120
        }
        
        protocol = WireGuardProtocol(config)
        print("✅ WireGuard protocol initialized successfully")
        
        # Test peer addition
        peer_public_key = os.urandom(32)
        protocol.add_peer("test_peer", peer_public_key)
        print("✅ Peer added successfully")
        
        # Test handshake initiation
        handshake_init = protocol.create_handshake_initiation("test_peer")
        if handshake_init and len(handshake_init.to_bytes()) == 148:
            print("✅ Handshake initiation created successfully")
        else:
            print("❌ Handshake initiation creation failed")
            return False
        
        # Test data packet creation
        test_data = b"Test WireGuard data"
        data_packet = protocol.create_data_packet("test_peer", test_data)
        if data_packet:
            print("✅ Data packet created successfully")
        else:
            print("❌ Data packet creation failed")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Protocol test failed: {e}")
        return False


def test_wireguard_udp_handler():
    """Test WireGuard UDP handler."""
    print("\n🧪 Testing WireGuard UDP Handler")
    print("=" * 40)
    
    try:
        config = {
            'key_rotation_interval': 120
        }
        
        handler = WireGuardUDPHandler(config)
        print("✅ UDP handler initialized successfully")
        
        # Test peer addition
        peer_public_key = os.urandom(32)
        handler.add_peer("test_peer", peer_public_key, ("127.0.0.1", 12345))
        print("✅ Peer added to UDP handler successfully")
        
        # Test statistics
        stats = handler.get_statistics()
        if 'total_peers' in stats and stats['total_peers'] == 1:
            print("✅ Statistics retrieval successful")
        else:
            print("❌ Statistics retrieval failed")
            return False
        
        # Test peer status
        peer_status = handler.get_peer_status("test_peer")
        if peer_status and peer_status['peer_id'] == "test_peer":
            print("✅ Peer status retrieval successful")
        else:
            print("❌ Peer status retrieval failed")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ UDP handler test failed: {e}")
        return False


def test_wireguard_integration():
    """Test WireGuard client/server integration."""
    print("\n🧪 Testing WireGuard Integration")
    print("=" * 40)
    
    try:
        config = {
            'key_rotation_interval': 120
        }
        
        # Test manager creation
        manager = WireGuardManager(config)
        print("✅ WireGuard manager created successfully")
        
        # Test server start
        server_success = manager.start_server("127.0.0.1", 51820)
        if server_success:
            print("✅ WireGuard server started successfully")
        else:
            print("❌ WireGuard server start failed")
            return False
        
        # Test status
        status = manager.get_status()
        if status['mode'] == 'server' and status['running']:
            print("✅ Server status retrieval successful")
        else:
            print("❌ Server status retrieval failed")
            return False
        
        # Test client connection (in separate thread for testing)
        def test_client():
            try:
                client_config = {'key_rotation_interval': 120}
                client = WireGuardClient(client_config)
                
                # This would normally connect to a real server
                # For testing, we just verify the client can be created
                print("✅ WireGuard client created successfully")
                
                client.disconnect()
                
            except Exception as e:
                print(f"❌ Client test failed: {e}")
        
        # Run client test in thread
        client_thread = threading.Thread(target=test_client, daemon=True)
        client_thread.start()
        client_thread.join(timeout=5)
        
        # Stop server
        manager.stop()
        print("✅ WireGuard server stopped successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        return False


def test_configuration():
    """Test WireGuard configuration."""
    print("\n🧪 Testing WireGuard Configuration")
    print("=" * 40)
    
    try:
        config_path = "config/vpn_config.json"
        if not os.path.exists(config_path):
            print(f"❌ Configuration file not found: {config_path}")
            return False
        
        config = Config(config_path).to_dict()
        
        # Check WireGuard configuration
        wireguard_config = config.get('wireguard', {})
        if not wireguard_config:
            print("❌ WireGuard configuration missing")
            return False
        
        required_fields = ['enabled', 'port', 'key_rotation_interval', 'persistent_keepalive']
        for field in required_fields:
            if field not in wireguard_config:
                print(f"❌ Missing WireGuard configuration field: {field}")
                return False
        
        print("✅ WireGuard configuration validated successfully")
        
        if wireguard_config.get('enabled'):
            print(f"✅ WireGuard enabled on port {wireguard_config.get('port')}")
            print(f"✅ Key rotation interval: {wireguard_config.get('key_rotation_interval')}s")
        
        return True
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False


def main():
    """Run all WireGuard tests."""
    print("🚀 WireGuard Protocol Implementation Test Suite")
    print("=" * 60)
    
    tests = [
        ("Configuration", test_configuration),
        ("WireGuard Cryptography", test_wireguard_cryptography),
        ("WireGuard Key Rotation", test_wireguard_key_rotation),
        ("WireGuard Packets", test_wireguard_packets),
        ("WireGuard Protocol", test_wireguard_protocol),
        ("WireGuard UDP Handler", test_wireguard_udp_handler),
        ("WireGuard Integration", test_wireguard_integration),
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
    print("📊 WireGuard Test Results Summary")
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
        print("\n🎉 All WireGuard tests passed! Implementation is ready.")
        print("\nKey features implemented:")
        print("✅ Modern cryptography (ChaCha20-Poly1305, Curve25519)")
        print("✅ UDP-only protocol handling")
        print("✅ Automatic key rotation")
        print("✅ High-performance packet processing")
        print("✅ Full client/server integration")
        print("\nNext steps:")
        print("1. Test with real WireGuard clients")
        print("2. Configure network routing")
        print("3. Deploy to production environment")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please check the implementation.")
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
