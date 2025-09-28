"""
Authentication manager for CyberSentinel.
"""

import logging
from typing import Optional, Tuple
from .database import UserDatabase
from .models import User

logger = logging.getLogger(__name__)


class AuthManager:
    """Manages user authentication and sessions."""
    
    def __init__(self):
        """Initialize the authentication manager."""
        self.db = UserDatabase()
        self.current_user: Optional[User] = None
    
    def register_user(self, username: str, email: str, full_name: str, 
                     password: str) -> Tuple[bool, str]:
        """Register a new user.
        
        Args:
            username: Unique username.
            email: User's email address.
            full_name: User's full name.
            password: User's password.
            
        Returns:
            Tuple of (success, message).
        """
        try:
            # Validate input
            if not username or len(username) < 3:
                return False, "Username must be at least 3 characters long"
            
            if not email or "@" not in email:
                return False, "Please enter a valid email address"
            
            if not full_name or len(full_name) < 2:
                return False, "Please enter your full name"
            
            if not password or len(password) < 6:
                return False, "Password must be at least 6 characters long"
            
            # Check if username already exists
            if self.db.username_exists(username):
                return False, "Username already exists"
            
            # Check if email already exists
            if self.db.email_exists(email):
                return False, "Email already registered"
            
            # Create new user
            user = User(
                username=username,
                email=email,
                full_name=full_name
            )
            user.set_password(password)
            
            # Save to database
            created_user = self.db.create_user(user)
            if created_user:
                logger.info(f"User registered successfully: {username}")
                return True, "Registration successful! You can now log in."
            else:
                return False, "Failed to create user account"
                
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False, f"Registration failed: {str(e)}"
    
    def login(self, username_or_email: str, password: str) -> Tuple[bool, str]:
        """Authenticate user login.
        
        Args:
            username_or_email: Username or email address.
            password: User's password.
            
        Returns:
            Tuple of (success, message).
        """
        try:
            if not username_or_email or not password:
                return False, "Please enter both username/email and password"
            
            # Try to find user by username or email
            user = None
            if "@" in username_or_email:
                user = self.db.get_user_by_email(username_or_email)
            else:
                user = self.db.get_user_by_username(username_or_email)
            
            if not user:
                return False, "Invalid username/email or password"
            
            # Verify password
            if not user.verify_password(password):
                return False, "Invalid username/email or password"
            
            # Update last login
            self.db.update_last_login(user.id)
            
            # Set current user
            self.current_user = user
            
            logger.info(f"User logged in: {user.username}")
            return True, f"Welcome back, {user.full_name}!"
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return False, f"Login failed: {str(e)}"
    
    def logout(self) -> None:
        """Log out the current user."""
        if self.current_user:
            logger.info(f"User logged out: {self.current_user.username}")
            self.current_user = None
    
    def is_logged_in(self) -> bool:
        """Check if a user is currently logged in.
        
        Returns:
            True if user is logged in, False otherwise.
        """
        return self.current_user is not None
    
    def get_current_user(self) -> Optional[User]:
        """Get the currently logged in user.
        
        Returns:
            Current user or None if not logged in.
        """
        return self.current_user
    
    def require_login(self) -> bool:
        """Check if login is required.
        
        Returns:
            True if login is required, False if user is already logged in.
        """
        return not self.is_logged_in()
    
    def validate_session(self) -> bool:
        """Validate the current session.
        
        Returns:
            True if session is valid, False otherwise.
        """
        if not self.current_user:
            return False
        
        # Refresh user data from database
        user = self.db.get_user_by_id(self.current_user.id)
        if not user:
            self.current_user = None
            return False
        
        self.current_user = user
        return True
