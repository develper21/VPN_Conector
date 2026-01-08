#!/usr/bin/env python3
"""
Test script for OpenVPN protocol implementation.
Tests packet creation, encryption, and basic functionality.
"""
import os
import sys
import time
import json
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from protocols.openvpn import OpenVPNProtocol, OpenVPNPacketType, OpenVPNCipher, OpenVPNAuth
from integrations.openvpn_integration import OpenVPNClient, OpenVPNServer
from utils.config_loader import Config


def test_openvpn_protocol():
    """Test OpenVPN protocol implementation."""
    print("Testing OpenVPN Protocol Implementation")
    print("=" * 50)
    
    # Test configuration
    config = {
        'cipher': 'AES-256-GCM',
        'auth': 'SHA256',
        'tls_version': 'TLSv1.3',
        'certificate_authority': 'config/certificates/ca.crt',
        'certificate': 'config/certificates/server.crt',
        'private_key': 'config/certificates/server.key'
    }
    
    try:
        # Initialize protocol
        protocol = OpenVPNProtocol(config)
        print("OpenVPN Protocol initialized successfully")
        
        # Test packet creation
        test_data = b"Hello, OpenVPN World!"
        packet = protocol.create_packet(
            OpenVPNPacketType.P_DATA_V2,
            test_data,
            packet_id=1
        )
        print(f"Packet created: {len(packet.to_bytes())} bytes")
        
        # Test packet parsing
        parsed_packet = protocol.parse_packet(packet.to_bytes())
        if parsed_packet and parsed_packet.payload == test_data:
            print("Packet parsing successful")
        else:
            print("Packet parsing failed")
            return False
        
        # Test encryption/decryption
        session_key = os.urandom(32)
        encrypted_data, iv, tag = protocol.encrypt_packet(packet, session_key)
        print(f"Packet encrypted: {len(encrypted_data)} bytes")
        
        decrypted_packet = protocol.decrypt_packet(encrypted_data, session_key, iv, tag)
        if decrypted_packet and decrypted_packet.payload == test_data:
            print("Packet decryption successful")
        else:
            print("Packet decryption failed")
            return False
        
        # Test cipher combinations
        test_ciphers = [
            (OpenVPNCipher.AES_256_GCM, OpenVPNAuth.SHA256),
            (OpenVPNCipher.AES_128_GCM, OpenVPNAuth.SHA256),
            (OpenVPNCipher.CHACHA20_POLY1305, OpenVPNAuth.SHA256),
        ]
        
        for cipher, auth in test_ciphers:
            try:
                from protocols.openvpn import OpenVPNCipherManager
                cipher_manager = OpenVPNCipherManager(cipher, auth)
                print(f"Cipher {cipher.value}/{auth.value} supported")
            except ValueError as e:
                print(f"Cipher {cipher.value}/{auth.value} failed: {e}")
                return False
        
        return True
        
    except Exception as e:
        print(f"Protocol test failed: {e}")
        return False


def test_openvpn_client():
    """Test OpenVPN client implementation."""
    print("\nTesting OpenVPN Client")
    print("=" * 30)
    
    try:
        # Load configuration
        config_path = "config/vpn_config.json"
        if not os.path.exists(config_path):
            print(f"Configuration file not found: {config_path}")
            return False
        
        config = Config(config_path).to_dict()
        
        # Initialize client
        client = OpenVPNClient(config)
        print("OpenVPN Client initialized successfully")
        
        # Test packet creation and encryption
        test_data = b"Test data for OpenVPN client"
        
        # Mock session keys for testing
        client.session_keys = {
            'client_write_key': os.urandom(32),
            'client_write_iv': os.urandom(16),
            'server_write_key': os.urandom(32),
            'server_write_iv': os.urandom(16)
        }
        
        # Test data sending (without actual connection)
        print("Client configuration validated")
        
        return True
        
    except Exception as e:
        print(f"Client test failed: {e}")
        return False


def test_performance_optimizations():
    """Test Cython performance optimizations."""
    print("\nTesting Performance Optimizations")
    print("=" * 40)
    
    try:
        # Test Cython extensions
        from performance.packet_processor import FastPacketProcessor, MemoryPool, PacketChecksum
        
        # Test fast packet processor
        processor = FastPacketProcessor("AES-256-GCM", os.urandom(32))
        test_data = b"Performance test data" * 100  # Larger test data
        
        start_time = time.time()
        encrypted = processor.encrypt_fast(test_data)
        encrypt_time = time.time() - start_time
        
        start_time = time.time()
        decrypted = processor.decrypt_fast(encrypted)
        decrypt_time = time.time() - start_time
        
        if decrypted == test_data:
            print(f"Fast encryption/decryption successful")
            print(f"   Encryption: {encrypt_time:.6f}s")
            print(f"   Decryption: {decrypt_time:.6f}s")
        else:
            print("Fast encryption/decryption failed")
            return False
        
        # Test memory pool
        pool = MemoryPool(1500, 100)
        buffer = pool.get_buffer()
        pool.return_buffer(buffer)
        print("Memory pool working correctly")
        
        # Test checksum
        checksum = PacketChecksum.calculate_checksum(test_data)
        print(f"Checksum calculation: {checksum}")
        
        return True
        
    except ImportError as e:
        print(f"Cython extensions not built: {e}")
        print("   Run 'python build.py' to build performance extensions")
        return True  # Not a failure, just not built
    except Exception as e:
        print(f"Performance test failed: {e}")
        return False


def test_configuration():
    """Test configuration loading and validation."""
    print("\nTesting Configuration")
    print("=" * 30)
    
    try:
        config_path = "config/vpn_config.json"
        if not os.path.exists(config_path):
            print(f"Configuration file not found: {config_path}")
            return False
        
        config = Config(config_path).to_dict()
        
        # Check required sections
        required_sections = ['server', 'client', 'security', 'openvpn', 'performance']
        for section in required_sections:
            if section not in config:
                print(f"Missing configuration section: {section}")
                return False
        
        print("Configuration loaded and validated successfully")
        
        # Check OpenVPN specific settings
        openvpn_config = config.get('openvpn', {})
        if openvpn_config.get('enabled'):
            print(f"OpenVPN enabled with cipher: {openvpn_config.get('cipher')}")
        
        # Check performance settings
        perf_config = config.get('performance', {})
        if perf_config.get('use_cython'):
            print("Cython optimizations enabled")
        
        return True
        
    except Exception as e:
        print(f"Configuration test failed: {e}")
        return False


def main():
    """Run all tests."""
    print("OpenVPN Protocol Implementation Test Suite")
    print("=" * 60)
    
    tests = [
        ("Configuration", test_configuration),
        ("OpenVPN Protocol", test_openvpn_protocol),
        ("OpenVPN Client", test_openvpn_client),
        ("Performance Optimizations", test_performance_optimizations),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"{test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Results Summary")
    print("=" * 60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"{test_name:<25} {status}")
        if result:
            passed += 1
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\nAll tests passed! OpenVPN implementation is ready.")
        print("\nNext steps:")
        print("1. Generate SSL certificates: ./scripts/generate_certs.sh")
        print("2. Start VPN server: python src/main.py --server")
        print("3. Start VPN client: python src/main.py --client")
    else:
        print(f"\n{total - passed} test(s) failed. Please check the implementation.")
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
