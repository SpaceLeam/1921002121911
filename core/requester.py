"""
Advanced HTTP requester with WAF evasion capabilities.
Features: UA rotation, jitter delays, browser-like headers, retry logic.
"""
import requests
import time
import random
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


class SmartRequester:
    """HTTP wrapper designed to evade basic WAF detection."""
    
    # Real browser User-Agents for rotation
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Vivaldi/6.5.3206.39'
    ]
    
    def __init__(self, 
                 target_url: str,
                 session_cookies: Optional[Dict[str, str]] = None,
                 auth_header: Optional[str] = None,
                 proxy: Optional[str] = None,
                 jitter_range: tuple = (0.5, 1.5),
                 max_retries: int = 3):
        """
        Initialize the smart requester.
        
        Args:
            target_url: Base URL for requests
            session_cookies: Dict of cookies to maintain session
            auth_header: Authorization header value (e.g., "Bearer token")
            proxy: Proxy URL if needed (format: "http://ip:port")
            jitter_range: Tuple of (min, max) seconds for random delay
            max_retries: Maximum retry attempts on failure
        """
        self.target = target_url
        self.session = requests.Session()
        self.jitter_range = jitter_range
        self.max_retries = max_retries
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        
        # Setup session state
        if session_cookies:
            self.session.cookies.update(session_cookies)
        if auth_header:
            self.session.headers['Authorization'] = auth_header
            
        logger.info(f"SmartRequester initialized for {target_url}")
    
    def _get_browser_headers(self, content_type: str = "application/json") -> Dict[str, str]:
        """Generate realistic browser headers."""
        return {
            'User-Agent': random.choice(self.USER_AGENTS),
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Content-Type': content_type,
            'Origin': self.target.rsplit('/', 1)[0],  # Extract origin from target
            'Referer': self.target,
            'DNT': '1',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin'
        }
    
    def _apply_jitter(self):
        """Apply random delay to avoid rate limiting."""
        delay = random.uniform(*self.jitter_range)
        logger.debug(f"Applying jitter: {delay:.2f}s")
        time.sleep(delay)
    
    def send_request(self,
                     method: str = "POST",
                     payload: Optional[Dict[str, Any]] = None,
                     custom_headers: Optional[Dict[str, str]] = None,
                     content_type: str = "application/json") -> Optional[requests.Response]:
        """
        Send HTTP request with WAF evasion techniques.
        
        Args:
            method: HTTP method (GET, POST, PUT, etc.)
            payload: Request body (will be JSON-encoded for POST/PUT)
            custom_headers: Additional headers to override defaults
            content_type: Content-Type header value
            
        Returns:
            Response object or None on failure
        """
        # Apply jitter before request
        self._apply_jitter()
        
        # Build headers
        headers = self._get_browser_headers(content_type)
        if custom_headers:
            headers.update(custom_headers)
        
        # Retry logic with exponential backoff
        for attempt in range(1, self.max_retries + 1):
            try:
                logger.debug(f"Sending {method} request (attempt {attempt}/{self.max_retries})")
                
                if method.upper() == 'POST':
                    response = self.session.post(
                        self.target, 
                        json=payload, 
                        headers=headers, 
                        proxies=self.proxy,
                        timeout=10,
                        allow_redirects=False  # Don't auto-follow redirects
                    )
                elif method.upper() == 'GET':
                    response = self.session.get(
                        self.target, 
                        params=payload,
                        headers=headers, 
                        proxies=self.proxy,
                        timeout=10,
                        allow_redirects=False
                    )
                elif method.upper() == 'PUT':
                    response = self.session.put(
                        self.target, 
                        json=payload, 
                        headers=headers, 
                        proxies=self.proxy,
                        timeout=10,
                        allow_redirects=False
                    )
                else:
                    logger.error(f"Unsupported HTTP method: {method}")
                    return None
                
                logger.info(f"Response: {response.status_code} | Length: {len(response.content)}")
                return response
                
            except requests.exceptions.Timeout:
                logger.warning(f"Request timeout (attempt {attempt})")
                if attempt < self.max_retries:
                    time.sleep(2 ** attempt)  # Exponential backoff
                    continue
                    
            except requests.exceptions.ConnectionError as e:
                logger.error(f"Connection error: {e}")
                if attempt < self.max_retries:
                    time.sleep(2 ** attempt)
                    continue
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"Request failed: {e}")
                return None
        
        logger.error("Max retries exceeded")
        return None
    
    def get_session_cookies(self) -> Dict[str, str]:
        """Return current session cookies as dict."""
        return dict(self.session.cookies)
