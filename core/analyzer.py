"""
Response analyzer for detecting 2FA bypasses.
Compares attack responses against baseline to identify anomalies.
"""
import json
import logging
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
import requests

logger = logging.getLogger(__name__)


@dataclass
class ResponseSignature:
    """Stores key characteristics of an HTTP response."""
    status_code: int
    length: int
    json_body: Optional[Dict[str, Any]]
    headers: Dict[str, str]
    cookies: set
    
    @classmethod
    def from_response(cls, response: requests.Response) -> 'ResponseSignature':
        """Create signature from requests.Response object."""
        # Try to parse JSON body
        json_body = None
        try:
            json_body = response.json()
        except (json.JSONDecodeError, ValueError):
            pass
        
        return cls(
            status_code=response.status_code,
            length=len(response.content),
            json_body=json_body,
            headers=dict(response.headers),
            cookies=set(response.cookies.keys())
        )


class ResponseAnalyzer:
    """Analyzes responses to detect successful 2FA bypasses."""
    
    # Threshold for considering response length significantly different
    LENGTH_DIFF_THRESHOLD = 0.20  # 20% difference (more lenient than 10%)
    
    def __init__(self, baseline_response: Optional[requests.Response] = None):
        """
        Initialize analyzer with optional baseline.
        
        Args:
            baseline_response: Response object of a normal failed 2FA attempt
        """
        self.baseline = None
        if baseline_response:
            self.set_baseline(baseline_response)
        logger.info("ResponseAnalyzer initialized")
    
    def set_baseline(self, response: requests.Response):
        """Set baseline from a response object."""
        self.baseline = ResponseSignature.from_response(response)
        logger.info(f"Baseline set: Status {self.baseline.status_code}, Length {self.baseline.length}")
    
    def is_bypass(self, attack_response: requests.Response) -> Tuple[bool, str]:
        """
        Analyze a response against the baseline.
        
        Args:
            attack_response: Response object from attack attempt
            
        Returns:
            Tuple of (is_bypass: bool, reason: str)
        """
        if not self.baseline:
            logger.warning("No baseline set! Analysis may be inaccurate.")
            return False, "No baseline available for comparison"
        
        signature = ResponseSignature.from_response(attack_response)
        
        # 1. STATUS CODE CHANGE (Most obvious indicator)
        # If baseline is 401/403 and attack gets 200/302 -> High confidence bypass
        if self.baseline.status_code in [401, 403, 422] and signature.status_code in [200, 201, 202, 302, 303]:
            return True, f"Status Code Shift: {self.baseline.status_code} → {signature.status_code}"
        
        # 2. CONTENT LENGTH DEVIATION (Anomaly detection)
        # Different page length usually means different content (dashboard vs error page)
        if self.baseline.length > 0:
            len_diff = abs(signature.length - self.baseline.length)
            percent_diff = (len_diff / self.baseline.length) * 100
            
            if percent_diff > (self.LENGTH_DIFF_THRESHOLD * 100):
                return True, f"Length Deviation: {percent_diff:.1f}% different from baseline ({self.baseline.length} → {signature.length})"
        
        # 3. NEW SESSION COOKIES (Critical indicator)
        # If attack receives new authentication cookies -> Valid bypass
        new_cookies = signature.cookies - self.baseline.cookies
        if new_cookies:
            auth_cookie_keywords = ['session', 'auth', 'token', 'jwt', 'access']
            important_cookies = [c for c in new_cookies if any(k in c.lower() for k in auth_cookie_keywords)]
            if important_cookies:
                return True, f"New Auth Cookies Issued: {important_cookies}"
        
        # 4. SUCCESS KEYWORDS IN RESPONSE (Token/data leak)
        # Sometimes status stays same but body contains success indicators
        success_keywords = ['access_token', 'jwt', '"success":true', '"success": true', 
                           'dashboard', 'welcome', 'authenticated', '"valid":true', '"valid": true']
        
        response_text = attack_response.text.lower()
        baseline_text = getattr(self.baseline, '_text', '').lower() if hasattr(self.baseline, '_text') else ''
        
        # Cache baseline text for comparison
        if not hasattr(self.baseline, '_text'):
            # We need to store this on first run - workaround since we only have signature
            pass
        
        for keyword in success_keywords:
            if keyword.lower() in response_text:
                # Check if keyword exists in baseline
                # If not, it's a new success indicator
                return True, f"Success Keyword Found: '{keyword}'"
        
        # 5. JSON STRUCTURE CHANGES
        if self.baseline.json_body and signature.json_body:
            # Check for success flag changes
            success_keys = ['success', 'valid', 'verified', 'authenticated', 'authorized']
            for key in success_keys:
                baseline_val = self.baseline.json_body.get(key)
                response_val = signature.json_body.get(key)
                
                if baseline_val is False and response_val is True:
                    return True, f"JSON '{key}' changed: false → true"
                
                if baseline_val == "false" and response_val == "true":
                    return True, f"JSON '{key}' changed: 'false' → 'true'"
        
        return False, "No significant deviation from baseline"
    
    def analyze(self, response: requests.Response, attack_name: str = "Unknown") -> Dict[str, Any]:
        """
        Analyze a response and return detailed result dict.
        
        Args:
            response: Response object from attack attempt
            attack_name: Name of the attack technique used
            
        Returns:
            Dict containing analysis results
        """
        bypass_detected, reason = self.is_bypass(response)
        
        signature = ResponseSignature.from_response(response)
        
        # Calculate confidence score based on reason
        confidence_score = 0
        if "Status Code Shift" in reason:
            confidence_score = 90
        elif "Length Deviation" in reason:
            confidence_score = 70
        elif "New Auth Cookies" in reason:
            confidence_score = 85
        elif "Success Keyword" in reason:
            confidence_score = 75
        elif "JSON" in reason and "true" in reason:
            confidence_score = 80
        
        result = {
            'attack_name': attack_name,
            'bypass_detected': bypass_detected,
            'confidence_score': confidence_score,
            'confidence_level': self._get_confidence_level(confidence_score),
            'reason': reason,
            'response_status': signature.status_code,
            'response_length': signature.length,
            'baseline_status': self.baseline.status_code if self.baseline else 'Unknown',
            'baseline_length': self.baseline.length if self.baseline else 0
        }
        
        if bypass_detected:
            logger.warning(f"[!] BYPASS DETECTED: {attack_name}")
            logger.warning(f"    Confidence: {result['confidence_level']} ({confidence_score}%)")
            logger.warning(f"    Reason: {reason}")
        else:
            logger.debug(f"[*] No bypass: {attack_name}")
        
        return result
    
    def _get_confidence_level(self, score: int) -> str:
        """Convert numerical confidence to descriptive level."""
        if score >= 80:
            return "HIGH"
        elif score >= 60:
            return "MEDIUM"
        elif score >= 30:
            return "LOW"
        else:
            return "MINIMAL"

