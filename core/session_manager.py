"""
Session manager for maintaining authentication state.
Handles cookies and authorization tokens across requests.
"""
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class SessionManager:
    """Manages authentication session state for 2FA testing."""
    
    def __init__(self, 
                 cookies: Optional[Dict[str, str]] = None,
                 auth_token: Optional[str] = None,
                 auth_type: str = "Bearer"):
        """
        Initialize session manager.
        
        Args:
            cookies: Dict of cookie name-value pairs
            auth_token: Authentication token (without prefix)
            auth_type: Type of auth (Bearer, Token, etc.)
        """
        self.cookies = cookies or {}
        self.auth_token = auth_token
        self.auth_type = auth_type
        
        logger.info(f"SessionManager initialized with {len(self.cookies)} cookies")
        if auth_token:
            logger.info(f"Authorization: {auth_type} {auth_token[:10]}...")
    
    def get_cookies(self) -> Dict[str, str]:
        """Return current cookies."""
        return self.cookies
    
    def get_auth_header(self) -> Optional[str]:
        """Return formatted Authorization header value."""
        if self.auth_token:
            return f"{self.auth_type} {self.auth_token}"
        return None
    
    def update_cookies(self, new_cookies: Dict[str, str]):
        """Update session cookies."""
        self.cookies.update(new_cookies)
        logger.debug(f"Cookies updated. Total: {len(self.cookies)}")
    
    def set_auth_token(self, token: str, auth_type: str = "Bearer"):
        """Update authentication token."""
        self.auth_token = token
        self.auth_type = auth_type
        logger.info(f"Auth token updated: {auth_type} {token[:10]}...")
    
    @classmethod
    def from_cookie_string(cls, cookie_string: str) -> 'SessionManager':
        """
        Create session manager from cookie string.
        
        Args:
            cookie_string: Cookie string format "name1=value1; name2=value2"
            
        Returns:
            SessionManager instance
        """
        cookies = {}
        for cookie in cookie_string.split(';'):
            cookie = cookie.strip()
            if '=' in cookie:
                name, value = cookie.split('=', 1)
                cookies[name.strip()] = value.strip()
        
        return cls(cookies=cookies)
    
    def to_cookie_string(self) -> str:
        """Convert cookies dict to string format."""
        return '; '.join([f"{k}={v}" for k, v in self.cookies.items()])
