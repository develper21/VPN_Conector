"""
Data validation utilities for the VPN Security Project.

This module provides functions to validate various types of data,
including network addresses, configuration values, and user input.
"""
import ipaddress
import re
import socket
from typing import Any, Dict, List, Optional, Tuple, Union, Callable, TypeVar, Type, cast
from functools import wraps

T = TypeVar('T')

class ValidationError(ValueError):
    """Raised when a validation check fails."""
    pass

def validate_ipv4_address(address: str) -> str:
    """
    Validate an IPv4 address.
    
    Args:
        address: The IP address to validate.
        
    Returns:
        The validated IP address.
        
    Raises:
        ValidationError: If the address is not a valid IPv4 address.
    """
    try:
        ipaddress.IPv4Address(address)
        return address
    except ipaddress.AddressValueError as e:
        raise ValidationError(f"Invalid IPv4 address: {address}") from e

def validate_ipv6_address(address: str) -> str:
    """
    Validate an IPv6 address.
    
    Args:
        address: The IP address to validate.
        
    Returns:
        The validated IP address.
        
    Raises:
        ValidationError: If the address is not a valid IPv6 address.
    """
    try:
        ipaddress.IPv6Address(address)
        return address
    except ipaddress.AddressValueError as e:
        raise ValidationError(f"Invalid IPv6 address: {address}") from e

def validate_ip_address(address: str) -> str:
    """
    Validate an IP address (IPv4 or IPv6).
    
    Args:
        address: The IP address to validate.
        
    Returns:
        The validated IP address.
        
    Raises:
        ValidationError: If the address is not a valid IP address.
    """
    try:
        return validate_ipv4_address(address)
    except ValidationError:
        try:
            return validate_ipv6_address(address)
        except ValidationError as e:
            raise ValidationError(f"Invalid IP address: {address}") from e

def validate_netmask(netmask: str) -> str:
    """
    Validate an IPv4 netmask.

    Args:
        netmask: The dotted-quad netmask string (e.g., "255.255.255.0").

    Returns:
        The normalized netmask string.

    Raises:
        ValidationError: If the netmask is invalid.
    """
    if not isinstance(netmask, str):
        raise ValidationError(f"Netmask must be a string, got {type(netmask).__name__}")

    try:
        network = ipaddress.IPv4Network(f"0.0.0.0/{netmask}", strict=False)
        return str(network.netmask)
    except (ipaddress.NetmaskValueError, ValueError) as e:
        raise ValidationError(f"Invalid IPv4 netmask: {netmask}") from e

def validate_port(port: int, allow_privileged: bool = False) -> int:
    """
    Validate a port number.
    
    Args:
        port: The port number to validate.
        allow_privileged: If False, ports below 1024 will be rejected.
        
    Returns:
        The validated port number.
        
    Raises:
        ValidationError: If the port number is invalid.
    """
    if not isinstance(port, int):
        raise ValidationError(f"Port must be an integer, got {type(port).__name__}")
    
    if port < 0 or port > 65535:
        raise ValidationError(f"Port must be between 0 and 65535, got {port}")
    
    if not allow_privileged and 0 < port < 1024:
        raise ValidationError(f"Privileged port {port} requires root privileges")
    
    return port

def validate_mac_address(address: str) -> str:
    """
    Validate a MAC address.
    
    Args:
        address: The MAC address to validate.
        
    Returns:
        The validated MAC address in lowercase with colons.
        
    Raises:
        ValidationError: If the MAC address is invalid.
    """
    # Remove any separators and convert to lowercase
    clean_addr = re.sub(r'[^0-9A-Fa-f]', '', address.lower())
    
    # Check length (must be 12 hex digits)
    if len(clean_addr) != 12:
        raise ValidationError(f"MAC address must be 12 hex digits, got {len(clean_addr)}")
    
    # Check that all characters are valid hex digits
    if not re.match(r'^[0-9a-f]{12}$', clean_addr):
        raise ValidationError("MAC address contains invalid characters")
    
    # Format with colons for consistency
    return ':'.join(clean_addr[i:i+2] for i in range(0, 12, 2))

def validate_hostname(hostname: str) -> str:
    """
    Validate a hostname.
    
    Args:
        hostname: The hostname to validate.
        
    Returns:
        The validated hostname in lowercase.
        
    Raises:
        ValidationError: If the hostname is invalid.
    """
    if not hostname:
        raise ValidationError("Hostname cannot be empty")
    
    if len(hostname) > 253:
        raise ValidationError(f"Hostname too long: {len(hostname)} > 253 characters")
    
    # Check each label
    labels = hostname.split('.')
    for label in labels:
        if not label:
            raise ValidationError("Hostname contains empty label")
        
        if len(label) > 63:
            raise ValidationError(f"Label too long: '{label}' is {len(label)} characters")
        
        # Must start and end with alphanumeric character
        if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$', label, re.IGNORECASE):
            raise ValidationError(f"Invalid label: '{label}'")
    
    return hostname.lower()

def validate_protocol(protocol: str) -> str:
    """
    Validate a network protocol (e.g., 'tcp', 'udp').
    
    Args:
        protocol: The protocol to validate.
        
    Returns:
        The validated protocol in lowercase.
        
    Raises:
        ValidationError: If the protocol is not supported.
    """
    protocol = protocol.lower()
    if protocol not in ('tcp', 'udp', 'icmp', 'icmpv6'):
        raise ValidationError(f"Unsupported protocol: {protocol}")
    return protocol

def validate_string(value: Any, min_length: int = 1, max_length: Optional[int] = None) -> str:
    """
    Validate a string value.
    
    Args:
        value: The value to validate.
        min_length: Minimum allowed length.
        max_length: Maximum allowed length (None for no limit).
        
    Returns:
        The validated string.
        
    Raises:
        ValidationError: If the value is not a valid string.
    """
    if not isinstance(value, str):
        raise ValidationError(f"Expected string, got {type(value).__name__}")
    
    if len(value) < min_length:
        raise ValidationError(f"String too short: {len(value)} < {min_length} characters")
    
    if max_length is not None and len(value) > max_length:
        raise ValidationError(f"String too long: {len(value)} > {max_length} characters")
    
    return value

def validate_integer(
    value: Any, 
    min_value: Optional[int] = None, 
    max_value: Optional[int] = None
) -> int:
    """
    Validate an integer value.
    
    Args:
        value: The value to validate.
        min_value: Minimum allowed value (inclusive).
        max_value: Maximum allowed value (inclusive).
        
    Returns:
        The validated integer.
        
    Raises:
        ValidationError: If the value is not a valid integer or out of range.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        try:
            value = int(value)
        except (ValueError, TypeError) as e:
            raise ValidationError(f"Expected integer, got {type(value).__name__}") from e
    
    if min_value is not None and value < min_value:
        raise ValidationError(f"Value too small: {value} < {min_value}")
    
    if max_value is not None and value > max_value:
        raise ValidationError(f"Value too large: {value} > {max_value}")
    
    return value

def validate_bytes(
    value: Any,
    *,
    allow_memoryview: bool = True,
    allow_bytearray: bool = True,
    min_length: int = 0,
    max_length: Optional[int] = None
) -> bytes:
    """
    Validate a bytes-like value.

    Args:
        value: The value to validate.
        allow_memoryview: Whether to accept memoryview instances.
        allow_bytearray: Whether to accept bytearray instances.
        min_length: Minimum allowed length.
        max_length: Maximum allowed length (None for no limit).

    Returns:
        The validated value as immutable bytes.

    Raises:
        ValidationError: If the value is not bytes-like or length constraints fail.
    """

    allowed_types = (bytes,)
    candidates = []

    if allow_memoryview:
        candidates.append(memoryview)
    if allow_bytearray:
        candidates.append(bytearray)

    allowed_types += tuple(candidates)

    if not isinstance(value, allowed_types):
        raise ValidationError(f"Expected bytes-like value, got {type(value).__name__}")

    # Convert to immutable bytes if needed
    if isinstance(value, (bytearray, memoryview)):
        value = bytes(value)

    length = len(value)
    if length < min_length:
        raise ValidationError(f"Bytes value too short: {length} < {min_length}")
    if max_length is not None and length > max_length:
        raise ValidationError(f"Bytes value too long: {length} > {max_length}")

    return value

def validate_boolean(value: Any) -> bool:
    """
    Validate a boolean value.
    
    Args:
        value: The value to validate.
        
    Returns:
        The validated boolean.
        
    Raises:
        ValidationError: If the value cannot be converted to a boolean.
    """
    if isinstance(value, bool):
        return value
    
    if isinstance(value, str):
        value = value.lower()
        if value in ('true', 'yes', '1', 'on'):
            return True
        if value in ('false', 'no', '0', 'off'):
            return False
    
    raise ValidationError(f"Cannot convert to boolean: {value}")

def validate_enum(value: T, valid_values: List[T]) -> T:
    """
    Validate that a value is one of the allowed values.
    
    Args:
        value: The value to validate.
        valid_values: List of allowed values.
        
    Returns:
        The validated value.
        
    Raises:
        ValidationError: If the value is not in the list of allowed values.
    """
    if value not in valid_values:
        raise ValidationError(
            f"Invalid value: {value}. Must be one of: {', '.join(map(str, valid_values))}"
        )
    return value

def validate_dict(
    data: Dict[str, Any],
    schema: Dict[str, Union[Tuple[Type, bool], Dict[str, Any]]],
    allow_extra: bool = False
) -> Dict[str, Any]:
    """
    Validate a dictionary against a schema.
    
    Args:
        data: The dictionary to validate.
        schema: A dictionary mapping keys to (type, required) tuples.
        allow_extra: If True, extra keys in data are allowed.
        
    Returns:
        The validated dictionary with type-converted values.
        
    Raises:
        ValidationError: If validation fails.
    """
    if not isinstance(data, dict):
        raise ValidationError(f"Expected dictionary, got {type(data).__name__}")
    
    result = {}
    
    # Check for missing required fields
    for key, rule in schema.items():
        if isinstance(rule, dict):
            # Nested schema: only enforce presence, detailed validation later
            required = any(isinstance(v, tuple) and len(v) > 1 and v[1] for v in rule.values())
        else:
            _, required = rule
        if required and key not in data:
            raise ValidationError(f"Missing required field: {key}")
    
    # Validate each field
    for key, value in data.items():
        if key not in schema:
            if not allow_extra:
                raise ValidationError(f"Unexpected field: {key}")
            result[key] = value
            continue

        rule = schema[key]

        # Nested schema validation
        if isinstance(rule, dict):
            if not isinstance(value, dict):
                raise ValidationError(f"Field {key} must be a dictionary")
            result[key] = validate_dict(value, rule, allow_extra=False)
            continue

        expected_type, _ = rule
        
        try:
            if value is None and not isinstance(None, expected_type):
                raise ValidationError(f"Field {key} cannot be None")
            
            # Special handling for boolean values to avoid bool being a subclass of int
            if expected_type is bool and isinstance(value, int):
                raise ValidationError(f"Field {key} must be a boolean, got integer")
            
            # Convert the value to the expected type
            if value is not None and not isinstance(value, expected_type):
                if expected_type is bool and isinstance(value, str):
                    value = validate_boolean(value)
                elif expected_type in (int, float):
                    try:
                        value = expected_type(value)
                    except (ValueError, TypeError) as e:
                        raise ValidationError(
                            f"Field {key} must be of type {expected_type.__name__}, "
                            f"got {type(value).__name__}"
                        ) from e
                elif expected_type is str:
                    value = str(value)
                else:
                    raise ValidationError(
                        f"Field {key} must be of type {expected_type.__name__}, "
                        f"got {type(value).__name__}"
                    )
            
            result[key] = value
            
        except ValidationError as e:
            raise ValidationError(f"Validation error in field '{key}': {str(e)}") from e
    
    return result

def validate_list(
    items: List[Any],
    validator: Callable[[Any], T],
    min_length: int = 0,
    max_length: Optional[int] = None
) -> List[T]:
    """
    Validate a list of items.
    
    Args:
        items: The list to validate.
        validator: A function that validates each item.
        min_length: Minimum allowed list length.
        max_length: Maximum allowed list length (None for no limit).
        
    Returns:
        A new list with validated items.
        
    Raises:
        ValidationError: If validation fails.
    """
    if not isinstance(items, (list, tuple)):
        raise ValidationError(f"Expected list, got {type(items).__name__}")
    
    if len(items) < min_length:
        raise ValidationError(f"List too short: {len(items)} < {min_length} items")
    
    if max_length is not None and len(items) > max_length:
        raise ValidationError(f"List too long: {len(items)} > {max_length} items")
    
    result = []
    for i, item in enumerate(items):
        try:
            result.append(validator(item))
        except ValidationError as e:
            raise ValidationError(f"Item {i}: {str(e)}") from e
    
    return result

def validate_cidr(cidr: str) -> str:
    """
    Validate a CIDR notation network address.
    
    Args:
        cidr: The CIDR notation to validate (e.g., '192.168.1.0/24').
        
    Returns:
        The validated CIDR string.
        
    Raises:
        ValidationError: If the CIDR is invalid.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return str(network)
    except ValueError as e:
        raise ValidationError(f"Invalid CIDR notation: {cidr}") from e

def validate_json(json_str: str) -> Any:
    """
    Validate and parse a JSON string.
    
    Args:
        json_str: The JSON string to validate.
        
    Returns:
        The parsed JSON data.
        
    Raises:
        ValidationError: If the string is not valid JSON.
    """
    import json
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValidationError(f"Invalid JSON: {str(e)}") from e

def validate_regex(
    value: str, 
    pattern: str, 
    flags: int = 0,
    error_message: Optional[str] = None
) -> str:
    """
    Validate a string against a regular expression.
    
    Args:
        value: The string to validate.
        pattern: The regular expression pattern.
        flags: Regular expression flags.
        error_message: Custom error message.
        
    Returns:
        The validated string.
        
    Raises:
        ValidationError: If the string doesn't match the pattern.
    """
    if not re.match(pattern, value, flags):
        if error_message is None:
            error_message = f"Value does not match pattern: {pattern}"
        raise ValidationError(error_message)
    return value

def validate_datetime(
    date_string: str, 
    format_str: str = "%Y-%m-%d %H:%M:%S",
    timezone_aware: bool = False
) -> str:
    """
    Validate a datetime string against a format.
    
    Args:
        date_string: The datetime string to validate.
        format_str: The strptime format string.
        timezone_aware: If True, requires timezone information.
        
    Returns:
        The validated datetime string.
        
    Raises:
        ValidationError: If the datetime string is invalid.
    """
    from datetime import datetime
    
    try:
        dt = datetime.strptime(date_string, format_str)
        if timezone_aware and dt.tzinfo is None:
            raise ValidationError("Timezone information is required")
        return date_string
    except ValueError as e:
        raise ValidationError(f"Invalid datetime format. Expected: {format_str}") from e

def validate_email(email: str) -> str:
    """
    Validate an email address.
    
    Args:
        email: The email address to validate.
        
    Returns:
        The validated email address in lowercase.
        
    Raises:
        ValidationError: If the email address is invalid.
    """
    # Simple email validation regex (not RFC 5322 compliant but good enough for most cases)
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    
    if not re.match(email_regex, email):
        raise ValidationError(f"Invalid email address: {email}")
    
    return email.lower()

def validate_url(url: str, allowed_schemes: List[str] = None) -> str:
    """
    Validate a URL.
    
    Args:
        url: The URL to validate.
        allowed_schemes: List of allowed URL schemes (e.g., ['http', 'https']).
        
    Returns:
        The validated URL.
        
    Raises:
        ValidationError: If the URL is invalid or uses a disallowed scheme.
    """
    if allowed_schemes is None:
        allowed_schemes = ['http', 'https']
    
    try:
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        if not parsed.scheme:
            raise ValidationError("URL must include a scheme (e.g., http://)")
        
        if parsed.scheme not in allowed_schemes:
            raise ValidationError(
                f"URL scheme must be one of: {', '.join(allowed_schemes)}"
            )
        
        if not parsed.netloc:
            raise ValidationError("URL must include a network location (e.g., example.com)")
        
        return url
    except Exception as e:
        raise ValidationError(f"Invalid URL: {str(e)}") from e

def validate_file_exists(file_path: str) -> str:
    """
    Validate that a file exists.
    
    Args:
        file_path: Path to the file.
        
    Returns:
        The absolute path to the file.
        
    Raises:
        ValidationError: If the file doesn't exist or is not a file.
    """
    import os
    
    abs_path = os.path.abspath(file_path)
    if not os.path.exists(abs_path):
        raise ValidationError(f"File does not exist: {abs_path}")
    
    if not os.path.isfile(abs_path):
        raise ValidationError(f"Path is not a file: {abs_path}")
    
    return abs_path

def validate_directory_exists(directory: str, create: bool = False) -> str:
    """
    Validate that a directory exists.
    
    Args:
        directory: Path to the directory.
        create: If True, create the directory if it doesn't exist.
        
    Returns:
        The absolute path to the directory.
        
    Raises:
        ValidationError: If the directory doesn't exist and create is False.
    """
    import os
    
    abs_path = os.path.abspath(directory)
    
    if os.path.exists(abs_path):
        if not os.path.isdir(abs_path):
            raise ValidationError(f"Path exists but is not a directory: {abs_path}")
    elif create:
        try:
            os.makedirs(abs_path, exist_ok=True)
        except OSError as e:
            raise ValidationError(f"Failed to create directory {abs_path}: {str(e)}") from e
    else:
        raise ValidationError(f"Directory does not exist: {abs_path}")
    
    return abs_path

def validate_positive_number(value: Any, zero_allowed: bool = False) -> float:
    """
    Validate that a value is a positive number.
    
    Args:
        value: The value to validate.
        zero_allowed: If True, zero is considered valid.
        
    Returns:
        The validated number as a float.
        
    Raises:
        ValidationError: If the value is not a positive number.
    """
    try:
        num = float(value)
    except (ValueError, TypeError) as e:
        raise ValidationError(f"Expected a number, got {type(value).__name__}") from e
    
    if num < 0 or (not zero_allowed and num == 0):
        raise ValidationError(
            f"Value must be {'non-negative' if zero_allowed else 'positive'}, got {num}"
        )
    
    return num

def validate_uuid(uuid_str: str, version: int = 4) -> str:
    """
    Validate a UUID string.
    
    Args:
        uuid_str: The UUID string to validate.
        version: The expected UUID version (1-5).
        
    Returns:
        The validated UUID string in lowercase.
        
    Raises:
        ValidationError: If the UUID is invalid.
    """
    import uuid
    
    try:
        uuid_obj = uuid.UUID(uuid_str, version=version)
        return str(uuid_obj).lower()
    except (ValueError, AttributeError, TypeError) as e:
        raise ValidationError(f"Invalid UUID{version}: {uuid_str}") from e
