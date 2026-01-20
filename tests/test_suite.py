"""
Comprehensive automated test suite for TfaBuster.
Tests all bypass techniques against Flask lab.
"""
import requests
import time
import sys
from typing import Dict, List, Tuple
import json


class TestResult:
    """Store test result data."""
    def __init__(self, name: str, passed: bool, reason: str = "", response_code: int = 0):
        self.name = name
        self.passed = passed
        self.reason = reason
        self.response_code = response_code


class TfaBusterTestSuite:
    """Automated test suite for TfaBuster vs Flask lab."""
    
    def __init__(self, base_url: str = "http://127.0.0.1:5555"):
        self.base_url = base_url
        self.results: List[TestResult] = []
        self.passed = 0
        self.failed = 0
    
    def test_server_health(self) -> bool:
        """Test if Flask server is running."""
        try:
            resp = requests.get(f"{self.base_url}/health", timeout=3)
            return resp.status_code == 200
        except:
            return False
    
    def run_test(self, name: str, endpoint: str, payload: Dict, 
                 should_bypass: bool = True, expected_code: int = 200) -> TestResult:
        """
        Run single test case.
        
        Args:
            name: Test name
            endpoint: API endpoint
            payload: Request payload
            should_bypass: Whether bypass expected
            expected_code: Expected HTTP status code
        """
        url = f"{self.base_url}{endpoint}"
        
        try:
            resp = requests.post(url, json=payload, timeout=5)
            
            # Check status code
            if resp.status_code != expected_code:
                return TestResult(
                    name, False, 
                    f"Expected {expected_code}, got {resp.status_code}",
                    resp.status_code
                )
            
            # Check if bypass indicated in response
            try:
                data = resp.json()
                has_success = data.get('status') == 'success' or \
                             data.get('authenticated') == True or \
                             'access_token' in data
                
                if should_bypass and not has_success:
                    return TestResult(
                        name, False,
                        "Expected bypass but got failure",
                        resp.status_code
                    )
                
                if not should_bypass and has_success:
                    return TestResult(
                        name, False,
                        "Expected failure but got bypass",
                        resp.status_code
                    )
                
                return TestResult(name, True, "Pass", resp.status_code)
                
            except json.JSONDecodeError:
                return TestResult(name, False, "Invalid JSON response", resp.status_code)
                
        except requests.exceptions.Timeout:
            return TestResult(name, False, "Request timeout", 0)
        except requests.exceptions.ConnectionError:
            return TestResult(name, False, "Connection failed", 0)
        except Exception as e:
            return TestResult(name, False, f"Error: {str(e)}", 0)
    
    def test_basic_vulnerabilities(self):
        """Test basic bypass techniques."""
        endpoint = "/api/verify-basic"
        
        tests = [
            ("Missing OTP Parameter", {}, True, 200),
            ("Null OTP Value", {"otp": None}, True, 200),
            ("Array Injection", {"otp": ["1234"]}, True, 200),
            ("Boolean True", {"otp": True}, True, 200),
            ("Boolean False", {"otp": False}, True, 200),
            ("Admin Backdoor (0000)", {"otp": "0000"}, True, 200),
            ("Valid OTP (1337)", {"otp": "1337"}, True, 200),
            ("Invalid OTP", {"otp": "9999"}, False, 403),
        ]
        
        print("\n[*] Testing Basic Vulnerabilities...")
        for name, payload, should_bypass, expected_code in tests:
            result = self.run_test(name, endpoint, payload, should_bypass, expected_code)
            self.results.append(result)
            self._print_result(result)
    
    def test_csrf_bypass(self):
        """Test CSRF bypass."""
        endpoint = "/api/verify-csrf"
        
        tests = [
            ("CSRF No Session", {"otp": "9999"}, True, 200),
            ("CSRF With Data", {"otp": "any"}, True, 200),
        ]
        
        print("\n[*] Testing CSRF Bypass...")
        for name, payload, should_bypass, expected_code in tests:
            result = self.run_test(name, endpoint, payload, should_bypass, expected_code)
            self.results.append(result)
            self._print_result(result)
    
    def test_rate_limiting(self):
        """Test rate limiting detection."""
        endpoint = "/api/verify-rate-limited"
        
        print("\n[*] Testing Rate Limiting...")
        
        # First 5 requests should work
        for i in range(5):
            result = self.run_test(
                f"Rate Limit Request {i+1}/5",
                endpoint,
                {"otp": "1337"},
                True,
                200
            )
            self.results.append(result)
            if i < 3:  # Only print first few
                self._print_result(result)
        
        # 6th request should trigger 429
        time.sleep(0.5)
        result = self.run_test(
            "Rate Limit Trigger (429)",
            endpoint,
            {"otp": "1337"},
            False,
            429
        )
        self.results.append(result)
        self._print_result(result)
        
        # Reset for next tests
        requests.post(f"{self.base_url}/api/reset-rate-limit")
        time.sleep(1)
    
    def test_oauth_bypass(self):
        """Test OAuth bypass."""
        endpoint = "/api/verify-oauth-bypass"
        
        tests = [
            ("OAuth Token Bypass", {"oauth_token": "fake_token"}, True, 200),
            ("OAuth Provider Bypass", {"oauth_provider": "google"}, True, 200),
            ("Normal Flow (no bypass)", {"otp": "1337"}, True, 200),
        ]
        
        print("\n[*] Testing OAuth Bypass...")
        for name, payload, should_bypass, expected_code in tests:
            result = self.run_test(name, endpoint, payload, should_bypass, expected_code)
            self.results.append(result)
            self._print_result(result)
    
    def test_json_response_changes(self):
        """Test JSON response structure detection."""
        endpoint = "/api/verify-json-response"
        
        tests = [
            ("JSON Structure Change (null)", {"otp": None}, True, 200),
            ("JSON Valid OTP", {"otp": "1337"}, True, 200),
        ]
        
        print("\n[*] Testing JSON Response Detection...")
        for name, payload, should_bypass, expected_code in tests:
            result = self.run_test(name, endpoint, payload, should_bypass, expected_code)
            self.results.append(result)
            self._print_result(result)
    
    def _print_result(self, result: TestResult):
        """Print single test result."""
        status = "✓ PASS" if result.passed else "✗ FAIL"
        color = '\033[92m' if result.passed else '\033[91m'
        reset = '\033[0m'
        
        print(f"  {color}{status}{reset} {result.name}")
        if not result.passed and result.reason:
            print(f"      → {result.reason}")
        
        if result.passed:
            self.passed += 1
        else:
            self.failed += 1
    
    def print_summary(self):
        """Print test summary."""
        total = len(self.results)
        pass_rate = (self.passed / total * 100) if total > 0 else 0
        
        print("\n" + "="*70)
        print("TEST SUMMARY")
        print("="*70)
        print(f"Total Tests: {total}")
        print(f"Passed: {self.passed} ({pass_rate:.1f}%)")
        print(f"Failed: {self.failed}")
        print("="*70)
        
        if self.failed > 0:
            print("\nFailed Tests:")
            for result in self.results:
                if not result.passed:
                    print(f"  • {result.name}: {result.reason}")
        
        return self.failed == 0
    
    def run_all(self) -> bool:
        """
        Run all tests.
        
        Returns:
            True if all tests passed
        """
        print("="*70)
        print("TfaBuster Automated Test Suite")
        print("="*70)
        
        # Check server
        print("\n[*] Checking Flask server...")
        if not self.test_server_health():
            print("✗ Flask server not responding at", self.base_url)
            print("\nStart server with: python tests/comprehensive_lab.py")
            return False
        print("✓ Flask server is running")
        
        # Run test suites
        self.test_basic_vulnerabilities()
        self.test_csrf_bypass()
        self.test_rate_limiting()
        self.test_oauth_bypass()
        self.test_json_response_changes()
        
        # Print summary
        return self.print_summary()


if __name__ == '__main__':
    suite = TfaBusterTestSuite()
    success = suite.run_all()
    sys.exit(0 if success else 1)
