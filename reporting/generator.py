"""
Enhanced reporting module with PoC generation, CWE mapping, and CVSS scoring.
"""
import json
import logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate comprehensive security reports."""
    
    # CWE mappings for common 2FA bypasses
    CWE_MAPPINGS = {
        'Missing OTP Parameter': 'CWE-306: Missing Authentication for Critical Function',
        'Null OTP Value': 'CWE-20: Improper Input Validation',
        'Array Injection': 'CWE-843: Access of Resource Using Incompatible Type',
        'Boolean': 'CWE-843: Access of Resource Using Incompatible Type',
        'CSRF': 'CWE-352: Cross-Site Request Forgery',
        'Race Condition': 'CWE-362: Concurrent Execution using Shared Resource',
        'No Session': 'CWE-306: Missing Authentication for Critical Function'
    }
    
    # CVSS base scores for bypass types
    CVSS_SCORES = {
        'Missing OTP Parameter': 9.1,
        'Null OTP Value': 9.1,
        'Array Injection': 8.8,
        'Boolean': 8.8,
        'CSRF': 8.1,
        'Race Condition': 7.5,
        'No Session': 9.1
    }
    
    @staticmethod
    def generate_curl_poc(target_url: str, payload: Dict[str, Any], 
                         headers: Dict[str, str] = None, 
                         cookies: str = None) -> str:
        """
        Generate curl command for PoC.
        
        Args:
            target_url: Target URL
            payload: Request payload
            headers: Custom headers
            cookies: Cookie string
            
        Returns:
            curl command string
        """
        curl_cmd = f"curl -X POST '{target_url}' \\\n"
        curl_cmd += "  -H 'Content-Type: application/json' \\\n"
        
        if cookies:
            curl_cmd += f"  -H 'Cookie: {cookies}' "
        
        if headers:
            for key, value in headers.items():
                curl_cmd += f"  -H '{key}: {value}' \\\n"
        
        payload_str = json.dumps(payload)
        curl_cmd += f"  -d '{payload_str}'"
        
        return curl_cmd
    
    @staticmethod
    def get_cwe(attack_name: str) -> str:
        """Get CWE for attack type."""
        for key in ReportGenerator.CWE_MAPPINGS:
            if key.lower() in attack_name.lower():
                return ReportGenerator.CWE_MAPPINGS[key]
        return "CWE-287: Improper Authentication"
    
    @staticmethod
    def get_cvss(attack_name: str) -> float:
        """Get CVSS score for attack type."""
        for key in ReportGenerator.CVSS_SCORES:
            if key.lower() in attack_name.lower():
                return ReportGenerator.CVSS_SCORES[key]
        return 7.5  # Default MEDIUM-HIGH
    
    @staticmethod
    def get_remediation(attack_name: str) -> List[str]:
        """Get remediation advice for attack type."""
        remediations = {
            'null': [
                "Implement strict null checking on OTP parameter",
                "Return identical error messages for null and invalid OTP",
                "Add server-side validation before processing"
            ],
            'missing': [
                "Enforce required parameters at API gateway level",
                "Return 400 Bad Request for missing parameters",
                "Use schema validation (JSON Schema, OpenAPI)"
            ],
            'array': [
                "Implement strict type checking (only accept string/integer)",
                "Reject array or object types for OTP parameter",
                "Use typed API frameworks (FastAPI with Pydantic)"
            ],
            'csrf': [
                "Implement CSRF tokens for state-changing operations",
                "Validate Origin and Referer headers",
                "Use SameSite cookie attribute"
            ],
            'race': [
                "Implement atomic OTP validation (use database locks)",
                "Invalidate OTP immediately after first use",
                "Add request deduplication mechanism"
            ]
        }
        
        attack_lower = attack_name.lower()
        for key, advice in remediations.items():
            if key in attack_lower:
                return advice
        
        return ["Implement proper input validation", "Follow OWASP authentication guidelines"]
    
    @staticmethod
    def enhance_result(result: Dict[str, Any], target_url: str, 
                      payload: Dict[str, Any], cookies: str = None) -> Dict[str, Any]:
        """
        Enhance result with PoC, CWE, CVSS, and remediation.
        
        Args:
            result: Original analysis result
            target_url: Target URL
            payload: Request payload
            cookies: Cookie string
            
        Returns:
            Enhanced result dict
        """
        if not result.get('bypass_detected'):
            return result
        
        attack_name = result.get('attack_name', '')
        
        # Add enhanced fields
        result['cwe'] = ReportGenerator.get_cwe(attack_name)
        result['cvss_score'] = ReportGenerator.get_cvss(attack_name)
        result['severity'] = 'CRITICAL' if result['cvss_score'] >= 9.0 else 'HIGH'
        result['remediation'] = ReportGenerator.get_remediation(attack_name)
        result['proof_of_concept'] = ReportGenerator.generate_curl_poc(
            target_url, payload, cookies=cookies
        )
        result['timestamp'] = datetime.now().isoformat()
        
        return result
    
    @staticmethod
    def generate_summary_report(results: List[Dict[str, Any]], 
                               target_name: str = "Unknown") -> str:
        """
        Generate human-readable summary report.
        
        Args:
            results: List of analysis results
            target_name: Target name
            
        Returns:
            Formatted summary string
        """
        bypasses = [r for r in results if r.get('bypass_detected')]
        
        report = f"\n{'='*70}\n"
        report += f"SECURITY ASSESSMENT REPORT - {target_name}\n"
        report += f"{'='*70}\n\n"
        report += f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Total Tests: {len(results)}\n"
        report += f"Bypasses Found: {len(bypasses)}\n\n"
        
        if bypasses:
            report += f"{'='*70}\n"
            report += "FINDINGS\n"
            report += f"{'='*70}\n\n"
            
            for i, bypass in enumerate(bypasses, 1):
                report += f"{i}. {bypass.get('attack_name', 'Unknown')}\n"
                report += f"   Severity: {bypass.get('severity', 'HIGH')}\n"
                report += f"   CVSS Score: {bypass.get('cvss_score', 'N/A')}\n"
                report += f"   CWE: {bypass.get('cwe', 'N/A')}\n"
                report += f"   Confidence: {bypass.get('confidence_level', 'N/A')}\n\n"
                
                if 'remediation' in bypass:
                    report += "   Remediation:\n"
                    for remedy in bypass['remediation']:
                        report += f"   - {remedy}\n"
                    report += "\n"
        
        report += f"{'='*70}\n"
        
        return report
