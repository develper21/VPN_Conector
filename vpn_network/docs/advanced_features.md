# Advanced VPN Features

This document describes the advanced features implemented in the VPN project.

## Overview

The VPN project includes four major advanced features that enhance security, privacy, and usability:

1. **Split Tunneling** - Selective routing of traffic through VPN or direct internet
2. **Kill Switch** - Automatic internet blocking when VPN disconnects
3. **DNS Leak Protection** - Prevents DNS queries from leaking outside VPN tunnel
4. **Protocol Obfuscation** - Bypasses deep packet inspection and firewalls

## Feature Details

### 1. Split Tunneling

**Location**: `src/advanced_features/split_tunneling.py`

Split tunneling allows you to selectively route traffic through the VPN tunnel or directly to the internet.

#### Features:
- **IP-based routing**: Route specific IP ranges or subnets
- **Domain-based routing**: Route traffic to specific domains
- **Application-based routing**: Route traffic from specific applications
- **Priority-based rules**: Higher priority rules override lower ones
- **Dynamic rule management**: Add/remove rules without restarting VPN

#### Configuration:
```json
{
  "rules": [
    {
      "name": "Local Network",
      "target": "192.168.0.0/16,10.0.0.0/8",
      "route_via_vpn": false,
      "rule_type": "ip",
      "priority": 10
    },
    {
      "name": "Streaming Services",
      "target": "netflix.com,amazon.com",
      "route_via_vpn": true,
      "rule_type": "domain",
      "priority": 50
    }
  ]
}
```

#### Usage:
```python
from advanced_features import SplitTunnelingManager, RoutingRule

# Create manager
split_manager = SplitTunnelingManager()

# Add custom rule
rule = RoutingRule(
    name="Work Applications",
    target="slack.com,teams.microsoft.com",
    route_via_vpn=True,
    rule_type="domain"
)
split_manager.add_rule(rule)

# Activate with VPN interface
split_manager.activate("tun0")
```

### 2. Kill Switch

**Location**: `src/advanced_features/kill_switch.py`

The kill switch automatically blocks internet access when the VPN connection is lost, preventing IP leaks.

#### Features:
- **Automatic VPN monitoring**: Continuously monitors VPN connection status
- **iptables-based blocking**: Uses firewall rules to block traffic
- **Configurable blocking**: Block all internet or specific traffic types
- **Allowed networks**: Configure networks that can bypass the block
- **Auto-recovery**: Attempts to reconnect VPN when disconnected
- **Strict mode**: Enhanced security with additional restrictions

#### Configuration:
```json
{
  "enabled": true,
  "block_all_internet": true,
  "allowed_networks": ["192.168.0.0/16", "10.0.0.0/8"],
  "allowed_applications": ["/usr/bin/chrome"],
  "vpn_interface": "tun0",
  "monitoring_interval": 5,
  "auto_recovery": true,
  "strict_mode": false
}
```

#### Usage:
```python
from advanced_features import KillSwitch

# Create kill switch
kill_switch = KillSwitch()

# Activate with VPN interface
kill_switch.activate("tun0")

# Test functionality
if kill_switch.test_kill_switch():
    print("Kill switch working correctly")
```

### 3. DNS Leak Protection

**Location**: `src/advanced_features/dns_leak_protection.py`

DNS leak protection ensures that all DNS queries go through the VPN tunnel, preventing DNS leaks.

#### Features:
- **DNS traffic monitoring**: Monitors all DNS queries using packet capture
- **iptables filtering**: Blocks external DNS servers
- **VPN DNS enforcement**: Forces all queries through VPN DNS servers
- **DNS over HTTPS blocking**: Prevents DoH bypass attempts
- **Query logging**: Logs all DNS queries for analysis
- **Custom DNS server**: Local DNS filter server

#### Configuration:
```json
{
  "enabled": true,
  "vpn_dns_servers": ["1.1.1.1", "8.8.8.8"],
  "block_external_dns": true,
  "force_vpn_dns": true,
  "monitor_interface": "any",
  "dns_port": 53,
  "allowed_dns_servers": [],
  "log_dns_queries": true,
  "block_dns_over_https": true
}
```

#### Usage:
```python
from advanced_features import DNSLeakProtection

# Create DNS protection
dns_protection = DNSLeakProtection()

# Activate with VPN interface
dns_protection.activate("tun0")

# Get DNS query log
queries = dns_protection.get_dns_query_log(limit=50)
```

### 4. Protocol Obfuscation

**Location**: `src/advanced_features/protocol_obfuscation.py`

Protocol obfuscation disguises VPN traffic to bypass deep packet inspection (DPI) and firewalls.

#### Features:
- **Multiple techniques**: TLS camouflage, Shadowsocks, custom protocols, obfs4
- **Packet encryption**: AES-256-GCM encryption for obfuscated packets
- **Traffic shaping**: Random padding, packet chopping, timing obfuscation
- **Fake traffic generation**: Generates realistic cover traffic
- **HTTP header camouflage**: Makes traffic look like HTTPS

#### Configuration:
```json
{
  "enabled": true,
  "technique": "tls_camouflage",
  "encryption_method": "aes-256-gcm",
  "compression": true,
  "random_padding": true,
  "packet_chopping": true,
  "timing_obfuscation": true,
  "fake_traffic": true
}
```

#### Usage:
```python
from advanced_features import ProtocolObfuscator

# Create obfuscator
obfuscator = ProtocolObfuscator()

# Activate
obfuscator.activate()

# Obfuscate packet
data = b"Hello VPN"
obfuscated = obfuscator.obfuscate_packet(data)
original = obfuscator.deobfuscate_packet(obfuscated)
```

## Advanced Features Manager

**Location**: `src/advanced_features/advanced_features_manager.py`

The Advanced Features Manager coordinates all advanced features and provides a unified interface.

### Features:
- **Unified control**: Single interface for all features
- **Automatic activation**: Activates features when VPN connects
- **Priority management**: Configurable activation order
- **Health monitoring**: Monitors feature health and auto-recovers
- **Configuration management**: Centralized configuration handling

### Usage:
```python
from advanced_features.advanced_features_manager import AdvancedFeaturesManager

# Create manager
manager = AdvancedFeaturesManager()

# Handle VPN connection
manager.on_vpn_connected("tun0")

# Get comprehensive status
status = manager.get_comprehensive_status()

# Handle VPN disconnection
manager.on_vpn_disconnected()
```

## Integration with Main Application

The advanced features are integrated into the main VPN application in `src/main.py`:

1. **Initialization**: Features are initialized when the application starts
2. **Automatic activation**: Features activate when VPN client connects
3. **Graceful shutdown**: Features are properly deactivated on shutdown

### Command Line Usage:

```bash
# Start VPN client with advanced features
python src/main.py --client --protocol openvpn --server-address vpn.example.com

# Advanced features will automatically activate when VPN connects
```

## Configuration Files

All features use JSON configuration files stored in the `config/` directory:

- `config/split_tunneling.json` - Split tunneling configuration
- `config/kill_switch.json` - Kill switch configuration  
- `config/dns_leak_protection.json` - DNS leak protection configuration
- `config/protocol_obfuscation.json` - Protocol obfuscation configuration
- `config/advanced_features.json` - Global advanced features configuration

## Security Considerations

### Root Privileges
Most features require root privileges for:
- iptables rule management (Kill Switch, DNS Protection)
- Network interface manipulation (Split Tunneling)
- Packet capture (DNS Protection)

### Network Impact
- **Kill Switch**: Blocks all internet when VPN disconnects
- **DNS Protection**: May break applications that hardcode DNS servers
- **Split Tunneling**: Complex routing may affect performance
- **Protocol Obfuscation**: Adds overhead to VPN traffic

### Recommendations
1. Test features in a safe environment before production use
2. Monitor system logs for feature-related errors
3. Keep configuration backups
4. Understand the security implications of each feature

## Troubleshooting

### Common Issues

1. **Features not activating**: Check root privileges and configuration files
2. **Kill Switch blocking legitimate traffic**: Review allowed networks configuration
3. **DNS leaks still occurring**: Verify DNS servers and iptables rules
4. **Performance degradation**: Consider disabling resource-intensive features

### Debug Logging

Enable debug logging for detailed troubleshooting:

```python
from utils.logger import setup_logger
logger = setup_logger("advanced_features", "DEBUG")
```

### Testing

Each feature includes built-in testing functionality:

```python
# Test all features
results = manager.test_all_features()
print(results)
```

## Future Enhancements

Planned improvements include:
- GUI configuration interface
- More obfuscation techniques
- Advanced routing rules for split tunneling
- Integration with more VPN protocols
- Performance optimizations
- Additional security features
