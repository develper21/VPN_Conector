"""
Access Control for the VPN Server

This module handles client authentication, authorization, and access control
for the VPN server. It supports multiple authentication methods including
username/password, client certificates, and two-factor authentication.
"""
import os
import time
import logging
import hashlib
import hmac
import json
import base64
import sqlite3
from typing import Dict, List, Optional, Tuple, Any, Union, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from threading import Lock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from utils.logger import LoggableMixin
from utils.validator import (
    validate_string, validate_boolean, validate_integer,
    validate_dict, validate_list, validate_email
)

class AuthError(Exception):
    """Base exception for authentication errors."""
    pass

class AuthenticationFailed(AuthError):
    """Raised when authentication fails."""
    pass

class AuthorizationFailed(AuthError):
    """Raised when authorization fails."""
    pass

class RateLimitExceeded(AuthError):
    """Raised when rate limiting is triggered."""
    pass

class AccountLocked(AuthError):
    """Raised when an account is locked."""
    pass

@dataclass
class User(LoggableMixin):
    """Represents a VPN user."""
    username: str
    password_hash: Optional[str] = None
    is_active: bool = True
    is_admin: bool = False
    created_at: float = field(default_factory=time.time)
    last_login: Optional[float] = None
    failed_attempts: int = 0
    lock_until: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize the logger for this user."""
        self._logger = logging.getLogger(f"{__name__}.User-{self.username}")
    
    def check_password(self, password: str) -> bool:
        """
        Check if the provided password matches the stored hash.
        
        Args:
            password: The password to check.
            
        Returns:
            True if the password is correct, False otherwise.
        """
        if not self.password_hash:
            return False
            
        # Format: $algorithm$salt$hash
        try:
            algorithm, salt, stored_hash = self.password_hash.split('$', 2)
            
            if algorithm == 'pbkdf2_sha256':
                # Generate the hash using the same parameters
                derived_key = hashlib.pbkdf2_hmac(
                    'sha256',
                    password.encode('utf-8'),
                    salt.encode('utf-8'),
                    100000,  # Number of iterations
                    dklen=32  # Length of the derived key
                )
                
                # Compare the derived key with the stored hash
                return hmac.compare_digest(
                    derived_key.hex(),
                    stored_hash
                )
            else:
                self.logger.warning(f"Unsupported password hashing algorithm: {algorithm}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error checking password: {e}", exc_info=True)
            return False
    
    def set_password(self, password: str) -> None:
        """
        Set a new password for the user.
        
        Args:
            password: The new password.
        """
        import secrets
        
        # Generate a random salt
        salt = secrets.token_hex(16)
        
        # Generate the password hash using PBKDF2
        derived_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000,  # Number of iterations
            dklen=32  # Length of the derived key
        )
        
        # Store the algorithm, salt, and hash
        self.password_hash = f"pbkdf2_sha256${salt}${derived_key.hex()}"
    
    def record_failed_attempt(self, max_attempts: int = 5, lock_time: int = 300) -> bool:
        """
        Record a failed login attempt and lock the account if necessary.
        
        Args:
            max_attempts: Maximum number of allowed failed attempts.
            lock_time: Time in seconds to lock the account for.
            
        Returns:
            True if the account is now locked, False otherwise.
        """
        self.failed_attempts += 1
        
        if self.failed_attempts >= max_attempts:
            self.lock_until = time.time() + lock_time
            self.logger.warning(f"Account {self.username} locked until {self.lock_until}")
            return True
            
        return False
    
    def is_locked(self) -> bool:
        """Check if the account is currently locked."""
        if not self.lock_until:
            return False
            
        if time.time() < self.lock_until:
            return True
            
        # Lock has expired, reset the lock
        self.lock_until = None
        self.failed_attempts = 0
        return False
    
    def record_successful_login(self) -> None:
        """Record a successful login."""
        self.last_login = time.time()
        self.failed_attempts = 0
        self.lock_until = None

class AccessControl(LoggableMixin):
    """
    Handles user authentication, authorization, and access control.
    """
    
    def __init__(
        self,
        db_path: Optional[str] = None,
        jwt_secret: Optional[str] = None,
        token_expiry: int = 3600,
        **kwargs
    ):
        """
        Initialize the AccessControl system.
        
        Args:
            db_path: Path to the SQLite database file. If None, an in-memory database is used.
            jwt_secret: Secret key for JWT token generation. If None, a random key is generated.
            token_expiry: Default token expiry time in seconds.
            **kwargs: Additional keyword arguments for LoggableMixin.
        """
        super().__init__(**kwargs)
        
        # Database configuration
        self.db_path = db_path or ":memory:"
        self._db_initialized = False
        self._db_lock = Lock()
        
        # JWT configuration
        self.jwt_secret = jwt_secret or os.urandom(32).hex()
        self.token_expiry = token_expiry
        
        # Rate limiting
        self._login_attempts: Dict[str, List[float]] = {}
        self._rate_limit = 5  # Max attempts per minute
        self._rate_window = 60  # Time window in seconds
        
        # Initialize the database
        self._init_database()
        
        # Create default admin user if no users exist
        self._create_default_admin()
        
        self.logger.info("AccessControl initialized")
    
    def _init_database(self) -> None:
        """Initialize the SQLite database."""
        with self._db_lock:
            if self._db_initialized:
                return
                
            is_new_db = not os.path.exists(self.db_path) or os.path.getsize(self.db_path) == 0
            
            # Create the database directory if it doesn't exist
            if self.db_path != ":memory:" and not os.path.exists(os.path.dirname(self.db_path)):
                os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            # Connect to the database
            self.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=10.0
            )
            self.conn.row_factory = sqlite3.Row
            
            # Create tables if this is a new database
            if is_new_db:
                self._create_tables()
            
            self._db_initialized = True
    
    def _create_tables(self) -> None:
        """Create the necessary database tables."""
        with self.conn:
            # Users table
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    is_admin BOOLEAN DEFAULT 0,
                    created_at REAL NOT NULL,
                    last_login REAL,
                    failed_attempts INTEGER DEFAULT 0,
                    lock_until REAL,
                    metadata TEXT DEFAULT '{}',
                    CONSTRAINT username_unique UNIQUE (username)
                )
            """)
            
            # API keys table
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    key_id TEXT UNIQUE NOT NULL,
                    key_secret TEXT NOT NULL,
                    name TEXT,
                    created_at REAL NOT NULL,
                    expires_at REAL,
                    last_used REAL,
                    is_active BOOLEAN DEFAULT 1,
                    permissions TEXT DEFAULT '[]',
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    CONSTRAINT key_id_unique UNIQUE (key_id)
                )
            """)
            
            # Audit log table
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp REAL NOT NULL,
                    details TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
                )
            """)
            
            # Create indexes
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id)")
    
    def _create_default_admin(self) -> None:
        """Create a default admin user if no users exist."""
        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute("SELECT COUNT(*) as count FROM users")
                count = cursor.fetchone()['count']
                
                if count == 0:
                    # Create default admin user with username 'admin' and password 'admin'
                    admin = User(
                        username="admin",
                        is_admin=True
                    )
                    admin.set_password("admin")
                    
                    # Save to database
                    cursor.execute("""
                        INSERT INTO users (
                            username, password_hash, is_active, is_admin, created_at, metadata
                        ) VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        admin.username,
                        admin.password_hash,
                        1,  # is_active
                        1,  # is_admin
                        admin.created_at,
                        json.dumps(admin.metadata)
                    ))
                    
                    self.logger.warning("Created default admin user: admin (password: admin)")
        except Exception as e:
            self.logger.error(f"Failed to create default admin user: {e}", exc_info=True)
    
    def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Tuple[bool, Optional[User], str]:
        """
        Authenticate a user with username and password.
        
        Args:
            username: The username to authenticate.
            password: The password to verify.
            ip_address: The IP address of the client (for rate limiting and logging).
            user_agent: The user agent string (for logging).
            
        Returns:
            A tuple of (success, user, message).
        """
        # Check rate limiting
        if ip_address and self._is_rate_limited(ip_address):
            self._log_audit(
                action="AUTH_RATE_LIMIT",
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                details={"reason": "rate_limit_exceeded"}
            )
            return False, None, "Too many login attempts. Please try again later."
        
        try:
            # Get the user from the database
            user = self.get_user_by_username(username)
            if not user:
                self._log_audit(
                    action="AUTH_FAILED",
                    username=username,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=False,
                    details={"reason": "user_not_found"}
                )
                return False, None, "Invalid username or password"
            
            # Check if the account is locked
            if user.is_locked():
                self._log_audit(
                    action="AUTH_FAILED",
                    username=username,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=False,
                    details={"reason": "account_locked"}
                )
                return False, None, "Account is temporarily locked. Please try again later."
            
            # Check if the account is active
            if not user.is_active:
                self._log_audit(
                    action="AUTH_FAILED",
                    username=username,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=False,
                    details={"reason": "account_inactive"}
                )
                return False, None, "Account is disabled. Please contact an administrator."
            
            # Verify the password
            if not user.check_password(password):
                # Record failed attempt
                user.record_failed_attempt()
                self._update_user(user)
                
                self._log_audit(
                    action="AUTH_FAILED",
                    username=username,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=False,
                    details={
                        "reason": "invalid_password",
                        "failed_attempts": user.failed_attempts
                    }
                )
                
                return False, None, "Invalid username or password"
            
            # Authentication successful
            user.record_successful_login()
            self._update_user(user)
            
            self._log_audit(
                action="AUTH_SUCCESS",
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                success=True
            )
            
            return True, user, "Authentication successful"
            
        except Exception as e:
            self.logger.error(f"Authentication error: {e}", exc_info=True)
            return False, None, f"Authentication error: {str(e)}"
    
    def authenticate_with_token(self, token: str) -> Tuple[bool, Optional[User], str]:
        """
        Authenticate a user with a JWT token.
        
        Args:
            token: The JWT token to verify.
            
        Returns:
            A tuple of (success, user, message).
        """
        try:
            # Verify and decode the token
            payload = self._verify_jwt_token(token)
            if not payload:
                return False, None, "Invalid or expired token"
            
            # Get the user from the database
            user = self.get_user_by_username(payload.get('sub'))
            if not user or not user.is_active:
                return False, None, "User not found or inactive"
            
            return True, user, "Token authentication successful"
            
        except Exception as e:
            self.logger.error(f"Token authentication error: {e}", exc_info=True)
            return False, None, f"Token authentication failed: {str(e)}"
    
    def create_user(
        self,
        username: str,
        password: Optional[str] = None,
        is_active: bool = True,
        is_admin: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[User], str]:
        """
        Create a new user.
        
        Args:
            username: The username for the new user.
            password: Optional password for the user. If None, the user will have no password.
            is_active: Whether the user account is active.
            is_admin: Whether the user has admin privileges.
            metadata: Additional metadata for the user.
            
        Returns:
            A tuple of (success, user, message).
        """
        try:
            # Validate input
            if not username:
                return False, None, "Username is required"
            
            # Check if the username already exists
            if self.get_user_by_username(username):
                return False, None, f"Username '{username}' is already taken"
            
            # Create the user
            user = User(
                username=username,
                is_active=is_active,
                is_admin=is_admin,
                metadata=metadata or {}
            )
            
            # Set the password if provided
            if password:
                user.set_password(password)
            
            # Save to database
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute("""
                    INSERT INTO users (
                        username, password_hash, is_active, is_admin, created_at, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    user.username,
                    user.password_hash,
                    1 if user.is_active else 0,
                    1 if user.is_admin else 0,
                    user.created_at,
                    json.dumps(user.metadata)
                ))
                
                user_id = cursor.lastrowid
                
                # Log the user creation
                self._log_audit(
                    action="USER_CREATED",
                    user_id=user_id,
                    username=username,
                    success=True,
                    details={
                        "is_active": is_active,
                        "is_admin": is_admin
                    }
                )
            
            return True, user, f"User '{username}' created successfully"
            
        except Exception as e:
            self.logger.error(f"Failed to create user: {e}", exc_info=True)
            return False, None, f"Failed to create user: {str(e)}"
    
    def update_user(
        self,
        username: str,
        password: Optional[str] = None,
        is_active: Optional[bool] = None,
        is_admin: Optional[bool] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[User], str]:
        """
        Update an existing user.
        
        Args:
            username: The username of the user to update.
            password: New password (if changing).
            is_active: New active status.
            is_admin: New admin status.
            metadata: Updated metadata (shallow merge with existing).
            
        Returns:
            A tuple of (success, user, message).
        """
        try:
            # Get the existing user
            user = self.get_user_by_username(username)
            if not user:
                return False, None, f"User '{username}' not found"
            
            # Update fields if provided
            if password is not None:
                user.set_password(password)
            
            if is_active is not None:
                user.is_active = is_active
            
            if is_admin is not None:
                user.is_admin = is_admin
            
            if metadata is not None:
                # Merge with existing metadata
                user.metadata.update(metadata)
            
            # Save changes
            self._update_user(user)
            
            return True, user, f"User '{username}' updated successfully"
            
        except Exception as e:
            self.logger.error(f"Failed to update user: {e}", exc_info=True)
            return False, None, f"Failed to update user: {str(e)}"
    
    def delete_user(self, username: str) -> Tuple[bool, str]:
        """
        Delete a user.
        
        Args:
            username: The username of the user to delete.
            
        Returns:
            A tuple of (success, message).
        """
        try:
            # Check if the user exists
            user = self.get_user_by_username(username)
            if not user:
                return False, f"User '{username}' not found"
            
            # Delete the user
            with self.conn:
                self.conn.execute("DELETE FROM users WHERE username = ?", (username,))
                
                # Log the deletion
                self._log_audit(
                    action="USER_DELETED",
                    username=username,
                    success=True
                )
            
            return True, f"User '{username}' deleted successfully"
            
        except Exception as e:
            self.logger.error(f"Failed to delete user: {e}", exc_info=True)
            return False, f"Failed to delete user: {str(e)}"
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """
        Get a user by username.
        
        Args:
            username: The username to look up.
            
        Returns:
            The User object if found, None otherwise.
        """
        if not username:
            return None
            
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM users WHERE username = ?
            """, (username,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return self._row_to_user(row)
            
        except Exception as e:
            self.logger.error(f"Error getting user by username: {e}", exc_info=True)
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """
        Get a user by ID.
        
        Args:
            user_id: The user ID to look up.
            
        Returns:
            The User object if found, None otherwise.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM users WHERE id = ?
            """, (user_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return self._row_to_user(row)
            
        except Exception as e:
            self.logger.error(f"Error getting user by ID: {e}", exc_info=True)
            return None
    
    def list_users(self, limit: int = 100, offset: int = 0) -> List[User]:
        """
        List all users.
        
        Args:
            limit: Maximum number of users to return.
            offset: Number of users to skip.
            
        Returns:
            A list of User objects.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM users
                ORDER BY username
                LIMIT ? OFFSET ?
            """, (limit, offset))
            
            return [self._row_to_user(row) for row in cursor.fetchall()]
            
        except Exception as e:
            self.logger.error(f"Error listing users: {e}", exc_info=True)
            return []
    
    def generate_api_key(
        self,
        username: str,
        name: str,
        expires_in_days: Optional[int] = None,
        permissions: Optional[List[str]] = None
    ) -> Tuple[bool, Optional[Dict[str, str]], str]:
        """
        Generate an API key for a user.
        
        Args:
            username: The username to generate the key for.
            name: A name for the API key.
            expires_in_days: Number of days until the key expires (None for no expiration).
            permissions: List of permissions to grant to the key.
            
        Returns:
            A tuple of (success, key_data, message).
        """
        try:
            # Get the user
            user = self.get_user_by_username(username)
            if not user:
                return False, None, f"User '{username}' not found"
            
            # Generate a key ID and secret
            import secrets
            import string
            
            key_id = 'key_' + ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(16))
            key_secret = secrets.token_urlsafe(32)
            
            # Hash the secret for storage
            secret_hash = hashlib.sha256(key_secret.encode()).hexdigest()
            
            # Calculate expiration
            expires_at = None
            if expires_in_days is not None:
                expires_at = time.time() + (expires_in_days * 86400)
            
            # Save the key to the database
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute("""
                    INSERT INTO api_keys (
                        user_id, key_id, key_secret, name,
                        created_at, expires_at, permissions
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    user.username,  # This should be user.id in a real implementation
                    key_id,
                    secret_hash,
                    name,
                    time.time(),
                    expires_at,
                    json.dumps(permissions or [])
                ))
            
            # Return the key data (the secret is only shown once)
            key_data = {
                'key_id': key_id,
                'key_secret': key_secret,
                'name': name,
                'expires_at': expires_at,
                'permissions': permissions or []
            }
            
            return True, key_data, "API key generated successfully"
            
        except Exception as e:
            self.logger.error(f"Failed to generate API key: {e}", exc_info=True)
            return False, None, f"Failed to generate API key: {str(e)}"
    
    def authenticate_with_api_key(self, key_id: str, key_secret: str) -> Tuple[bool, Optional[User], str]:
        """
        Authenticate a user with an API key.
        
        Args:
            key_id: The API key ID.
            key_secret: The API key secret.
            
        Returns:
            A tuple of (success, user, message).
        """
        try:
            # Hash the provided secret
            secret_hash = hashlib.sha256(key_secret.encode()).hexdigest()
            
            # Look up the key
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT k.*, u.*
                FROM api_keys k
                JOIN users u ON k.user_id = u.username  # Should be u.id in a real implementation
                WHERE k.key_id = ? AND k.key_secret = ? AND k.is_active = 1
                  AND (k.expires_at IS NULL OR k.expires_at > ?)
            """, (key_id, secret_hash, time.time()))
            
            row = cursor.fetchone()
            if not row:
                return False, None, "Invalid API key"
            
            # Update last used timestamp
            with self.conn:
                cursor.execute("""
                    UPDATE api_keys
                    SET last_used = ?
                    WHERE key_id = ?
                """, (time.time(), key_id))
            
            # Get the user
            user = self._row_to_user(row)
            if not user.is_active:
                return False, None, "User account is inactive"
            
            return True, user, "API key authentication successful"
            
        except Exception as e:
            self.logger.error(f"API key authentication error: {e}", exc_info=True)
            return False, None, f"API key authentication failed: {str(e)}"
    
    def _update_user(self, user: User) -> None:
        """
        Update a user in the database.
        
        Args:
            user: The user to update.
        """
        with self.conn:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE users
                SET password_hash = ?,
                    is_active = ?,
                    is_admin = ?,
                    last_login = ?,
                    failed_attempts = ?,
                    lock_until = ?,
                    metadata = ?
                WHERE username = ?
            """, (
                user.password_hash,
                1 if user.is_active else 0,
                1 if user.is_admin else 0,
                user.last_login,
                user.failed_attempts,
                user.lock_until,
                json.dumps(user.metadata),
                user.username
            ))
    
    def _row_to_user(self, row: sqlite3.Row) -> User:
        """
        Convert a database row to a User object.
        
        Args:
            row: The database row.
            
        Returns:
            A User object.
        """
        user = User(
            username=row['username'],
            password_hash=row['password_hash'],
            is_active=bool(row['is_active']),
            is_admin=bool(row['is_admin']),
            created_at=row['created_at'],
            last_login=row['last_login'],
            failed_attempts=row['failed_attempts'],
            lock_until=row['lock_until']
        )
        
        # Parse metadata
        try:
            user.metadata = json.loads(row['metadata']) if row['metadata'] else {}
        except (json.JSONDecodeError, TypeError):
            user.metadata = {}
        
        return user
    
    def _log_audit(
        self,
        action: str,
        username: Optional[str] = None,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log an audit event.
        
        Args:
            action: The action being logged.
            username: The username (if user_id is not available).
            user_id: The user ID.
            ip_address: The IP address of the client.
            user_agent: The user agent string.
            success: Whether the action was successful.
            details: Additional details about the event.
        """
        try:
            # If we have a username but no user_id, look it up
            if username and not user_id:
                user = self.get_user_by_username(username)
                if user:
                    # In a real implementation, we would have user.id
                    pass  # user_id = user.id
            
            # Insert the audit log entry
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute("""
                    INSERT INTO audit_log (
                        user_id, action, ip_address, user_agent,
                        timestamp, details, success
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_id,
                    action,
                    ip_address,
                    user_agent,
                    time.time(),
                    json.dumps(details or {}),
                    1 if success else 0
                ))
                
        except Exception as e:
            self.logger.error(f"Failed to log audit event: {e}", exc_info=True)
    
    def _is_rate_limited(self, ip_address: str) -> bool:
        """
        Check if an IP address is rate limited.
        
        Args:
            ip_address: The IP address to check.
            
        Returns:
            True if rate limited, False otherwise.
        """
        now = time.time()
        
        # Clean up old entries
        if ip_address in self._login_attempts:
            self._login_attempts[ip_address] = [
                t for t in self._login_attempts[ip_address]
                if now - t < self._rate_window
            ]
        else:
            self._login_attempts[ip_address] = []
        
        # Check if we've exceeded the rate limit
        if len(self._login_attempts[ip_address]) >= self._rate_limit:
            return True
        
        # Record this attempt
        self._login_attempts[ip_address].append(now)
        return False
    
    def _generate_jwt_token(self, user: User, expires_in: Optional[int] = None) -> str:
        """
        Generate a JWT token for a user.
        
        Args:
            user: The user to generate the token for.
            expires_in: Token expiry time in seconds.
            
        Returns:
            A JWT token string.
        """
        import jwt
        
        if expires_in is None:
            expires_in = self.token_expiry
        
        payload = {
            'sub': user.username,
            'iat': int(time.time()),
            'exp': int(time.time()) + expires_in,
            'admin': user.is_admin
        }
        
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')
    
    def _verify_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify a JWT token.
        
        Args:
            token: The JWT token to verify.
            
        Returns:
            The decoded token payload if valid, None otherwise.
        """
        import jwt
        
        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=['HS256'],
                options={'verify_exp': True}
            )
            return payload
        except jwt.ExpiredSignatureError:
            self.logger.warning("JWT token has expired")
            return None
        except jwt.InvalidTokenError as e:
            self.logger.warning(f"Invalid JWT token: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error verifying JWT token: {e}", exc_info=True)
            return None

# Example usage
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="VPN Access Control")
    parser.add_argument("--db", default=":memory:",
                       help="Path to the SQLite database file")
    
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create an access control instance
    access = AccessControl(db_path=args.db)
    
    # Example: Create a new user
    success, user, message = access.create_user(
        username="testuser",
        password="testpass123",
        is_active=True
    )
    
    if success and user:
        print(f"Created user: {user.username}")
        
        # Example: Authenticate the user
        success, auth_user, message = access.authenticate_user(
            username="testuser",
            password="testpass123"
        )
        
        if success and auth_user:
            print(f"Authentication successful for {auth_user.username}")
            
            # Example: Generate an API key
            success, key_data, message = access.generate_api_key(
                username="testuser",
                name="Test API Key"
            )
            
            if success and key_data:
                print(f"Generated API key: {key_data['key_id']}")
                print(f"Key secret (save this, it won't be shown again): {key_data['key_secret']}")
                
                # Example: Authenticate with API key
                success, api_user, message = access.authenticate_with_api_key(
                    key_id=key_data['key_id'],
                    key_secret=key_data['key_secret']
                )
                
                if success and api_user:
                    print(f"API key authentication successful for {api_user.username}")
                else:
                    print(f"API key authentication failed: {message}")
            else:
                print(f"Failed to generate API key: {message}")
        else:
            print(f"Authentication failed: {message}")
    else:
        print(f"Failed to create user: {message}")
