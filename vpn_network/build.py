#!/usr/bin/env python3
"""
Build script for Cython extensions.
Run this script to compile performance optimizations.
"""
import os
import sys
import subprocess
from pathlib import Path

def build_cython_extensions():
    """Build Cython extensions for performance optimization."""
    print("Building Cython extensions for VPN performance optimization...")
    
    # Change to performance directory
    perf_dir = Path(__file__).parent / "src" / "performance"
    os.chdir(perf_dir)
    
    try:
        # Build the extensions
        result = subprocess.run([
            sys.executable, "setup.py", "build_ext", "--inplace"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("Cython extensions built successfully!")
            print(result.stdout)
        else:
            print("Failed to build Cython extensions:")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"Error building extensions: {e}")
        return False
    
    return True

def install_dependencies():
    """Install required dependencies."""
    print("Installing dependencies...")
    
    try:
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("Dependencies installed successfully!")
        else:
            print("Failed to install dependencies:")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"Error installing dependencies: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("Building VPN Security Project with OpenVPN Protocol Support")
    print("=" * 60)
    
    # Install dependencies
    if not install_dependencies():
        sys.exit(1)
    
    # Build Cython extensions
    if not build_cython_extensions():
        print("Warning: Cython extensions failed to build")
        print("The project will still work but with reduced performance")
    
    print("\nBuild process completed!")
    print("\nNext steps:")
    print("1. Test the OpenVPN protocol implementation")
    print("2. Configure your VPN settings in config/vpn_config.json")
    print("3. Run: python src/main.py --server  (for server mode)")
    print("4. Run: python src/main.py --client  (for client mode)")
