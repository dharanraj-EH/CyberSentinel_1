"""
Database operations for user authentication.
"""

import sqlite3
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from .models import User

logger = logging.getLogger(__name__)


class UserDatabase:
    """SQLite database for user management."""
    
    def __init__(self, db_path: Optional[Path] = None):
        """Initialize the user database.
        
        Args:
            db_path: Path to the SQLite database file. If None, uses default location.
        """
        if db_path is None:
            # Default location in user's home directory
            db_path = Path.home() / ".cybersentinel" / "users.db"
        
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize the database schema."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        full_name TEXT NOT NULL,
                        password_hash TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        is_active BOOLEAN DEFAULT 1,
                        role TEXT DEFAULT 'user'
                    )
                """)
                
                # Create indexes for better performance
                conn.execute("CREATE INDEX IF NOT EXISTS idx_username ON users(username)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_email ON users(email)")
                
                conn.commit()
                logger.info(f"Database initialized at {self.db_path}")
                
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    def create_user(self, user: User) -> Optional[User]:
        """Create a new user in the database.
        
        Args:
            user: User object to create.
            
        Returns:
            Created user with ID, or None if creation failed.
        """
        try:
            user.created_at = datetime.now()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    INSERT INTO users (username, email, full_name, password_hash, salt, 
                                     created_at, last_login, is_active, role)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user.username, user.email, user.full_name, user.password_hash,
                    user.salt, user.created_at, user.last_login, user.is_active, user.role
                ))
                
                user.id = cursor.lastrowid
                conn.commit()
                
                logger.info(f"User created: {user.username} (ID: {user.id})")
                return user
                
        except sqlite3.IntegrityError as e:
            if "username" in str(e):
                logger.warning(f"Username already exists: {user.username}")
            elif "email" in str(e):
                logger.warning(f"Email already exists: {user.email}")
            else:
                logger.error(f"Integrity error creating user: {e}")
            return None
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return None
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username.
        
        Args:
            username: Username to search for.
            
        Returns:
            User object or None if not found.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    "SELECT * FROM users WHERE username = ? AND is_active = 1",
                    (username,)
                )
                row = cursor.fetchone()
                
                if row:
                    return self._row_to_user(row)
                return None
                
        except Exception as e:
            logger.error(f"Error getting user by username: {e}")
            return None
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email.
        
        Args:
            email: Email to search for.
            
        Returns:
            User object or None if not found.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    "SELECT * FROM users WHERE email = ? AND is_active = 1",
                    (email,)
                )
                row = cursor.fetchone()
                
                if row:
                    return self._row_to_user(row)
                return None
                
        except Exception as e:
            logger.error(f"Error getting user by email: {e}")
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID.
        
        Args:
            user_id: User ID to search for.
            
        Returns:
            User object or None if not found.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    "SELECT * FROM users WHERE id = ? AND is_active = 1",
                    (user_id,)
                )
                row = cursor.fetchone()
                
                if row:
                    return self._row_to_user(row)
                return None
                
        except Exception as e:
            logger.error(f"Error getting user by ID: {e}")
            return None
    
    def update_last_login(self, user_id: int) -> bool:
        """Update user's last login timestamp.
        
        Args:
            user_id: User ID to update.
            
        Returns:
            True if successful, False otherwise.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "UPDATE users SET last_login = ? WHERE id = ?",
                    (datetime.now(), user_id)
                )
                conn.commit()
                return True
                
        except Exception as e:
            logger.error(f"Error updating last login: {e}")
            return False
    
    def get_all_users(self) -> List[User]:
        """Get all active users.
        
        Returns:
            List of User objects.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    "SELECT * FROM users WHERE is_active = 1 ORDER BY created_at DESC"
                )
                rows = cursor.fetchall()
                
                return [self._row_to_user(row) for row in rows]
                
        except Exception as e:
            logger.error(f"Error getting all users: {e}")
            return []
    
    def username_exists(self, username: str) -> bool:
        """Check if username already exists.
        
        Args:
            username: Username to check.
            
        Returns:
            True if username exists, False otherwise.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT 1 FROM users WHERE username = ?",
                    (username,)
                )
                return cursor.fetchone() is not None
                
        except Exception as e:
            logger.error(f"Error checking username existence: {e}")
            return False
    
    def email_exists(self, email: str) -> bool:
        """Check if email already exists.
        
        Args:
            email: Email to check.
            
        Returns:
            True if email exists, False otherwise.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT 1 FROM users WHERE email = ?",
                    (email,)
                )
                return cursor.fetchone() is not None
                
        except Exception as e:
            logger.error(f"Error checking email existence: {e}")
            return False
    
    def _row_to_user(self, row: sqlite3.Row) -> User:
        """Convert database row to User object.
        
        Args:
            row: SQLite row object.
            
        Returns:
            User object.
        """
        created_at = None
        last_login = None
        
        if row['created_at']:
            created_at = datetime.fromisoformat(row['created_at'])
        if row['last_login']:
            last_login = datetime.fromisoformat(row['last_login'])
        
        return User(
            id=row['id'],
            username=row['username'],
            email=row['email'],
            full_name=row['full_name'],
            password_hash=row['password_hash'],
            salt=row['salt'],
            created_at=created_at,
            last_login=last_login,
            is_active=bool(row['is_active']),
            role=row['role']
        )
