"""
Response status manipulation documentation module.

⚠️ IMPORTANT: This module documents CLIENT-SIDE response manipulation only.
These techniques require a proxy interceptor (Burp Suite, mitmproxy) to modify
responses BEFORE they reach your browser/app. This is NOT for automated testing.

For automated bypass detection, use logic.py, csrf.py, and race.py modules.
This is for MANUAL verification after automated scans find potential issues.
"""
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)


class StatusManipulationModule:
    """
    Documents response manipulation techniques.
    
    Note: This module doesn't perform automated attacks since response 
    manipulation requires a proxy/interceptor. Instead, it provides 
    guidance on what to test manually or with Burp Suite.
    """
    
    @staticmethod
    def get_techniques() -> dict:
        """
        Return dict of response manipulation techniques.
        
        Returns:
            Dict mapping technique name to description
        """
        return {
            "Status Code Manipulation": {
                "description": "Change HTTP status code in response",
                "examples": [
                    "401 Unauthorized → 200 OK",
                    "403 Forbidden → 200 OK",
                    "422 Unprocessable Entity → 200 OK"
                ],
                "tool": "Burp Suite > Proxy > Options > Match and Replace",
                "impact": "If client-side validation only, may bypass 2FA"
            },
            
            "JSON Response Manipulation": {
                "description": "Modify JSON body values in response",
                "examples": [
                    '{"success": false} → {"success": true}',
                    '{"valid": false} → {"valid": true}',
                    '{"authenticated": false} → {"authenticated": true}',
                    '{"error": "Invalid code"} → {"message": "Success"}'
                ],
                "tool": "Burp Suite > Proxy > Options > Match and Replace (regex)",
                "impact": "Client-side apps may trust response without verification"
            },
            
            "Token Injection": {
                "description": "Add authentication tokens to response",
                "examples": [
                    'Add: {"token": "fake_jwt_token"}',
                    'Add header: Set-Cookie: session=hijacked_session',
                ],
                "tool": "Burp Suite > Match and Replace > Add",
                "impact": "Test if client blindly accepts tokens from response"
            },
            
            "Error Suppression": {
                "description": "Remove error fields from response",
                "examples": [
                    'Remove "error" key from JSON',
                    'Change "errors": [...] to "errors": []'
                ],
                "tool": "Burp Suite or custom proxy script",
                "impact": "Some apps may proceed if no explicit error is present"
            }
        }
    
    @staticmethod
    def print_guide():
        """Print manual testing guide for response manipulation."""
        techniques = StatusManipulationModule.get_techniques()
        
        print("\n" + "="*70)
        print("RESPONSE MANIPULATION TESTING GUIDE")
        print("="*70)
        print("\n⚠️  These techniques require a proxy interceptor (Burp Suite, mitmproxy)")
        print("    TfaBuster cannot automate response manipulation.\n")
        
        for name, details in techniques.items():
            print(f"\n📌 {name}")
            print(f"   {details['description']}\n")
            print(f"   Examples:")
            for example in details['examples']:
                print(f"     • {example}")
            print(f"\n   Tool: {details['tool']}")
            print(f"   Impact: {details['impact']}")
            print("-" * 70)
        
        print("\n💡 TIP: Use TfaBuster for automated logic bypasses,")
        print("   then manually test response manipulation in Burp Suite.\n")
    
    @staticmethod
    def get_burp_match_replace_rules() -> List[Dict[str, str]]:
        """
        Generate Burp Suite Match & Replace rules for easy import.
        
        Returns:
            List of rule configurations
        """
        return [
            {
                "name": "2FA Bypass: 401 to 200",
                "match_type": "Response status",
                "match": "401",
                "replace": "200",
                "scope": "All"
            },
            {
                "name": "2FA Bypass: 403 to 200",
                "match_type": "Response status",
                "match": "403",
                "replace": "200",
                "scope": "All"
            },
            {
                "name": '2FA Bypass: "success":false to true',
                "match_type": "Response body (regex)",
                "match": r'"success"\s*:\s*false',
                "replace": '"success":true',
                "scope": "All"
            },
            {
                "name": '2FA Bypass: "valid":false to true',
                "match_type": "Response body (regex)",
                "match": r'"valid"\s*:\s*false',
                "replace": '"valid":true',
                "scope": "All"
            }
        ]


# Expose for CLI
def print_manual_guide():
    """CLI-friendly function to print guide."""
    StatusManipulationModule.print_guide()
