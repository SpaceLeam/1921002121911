"""
Core attack engine - orchestrates baseline capture and module execution.
"""
import logging
from typing import Optional, Dict, Any, List
from core.requester import SmartRequester
from core.analyzer import ResponseAnalyzer
from core.session_manager import SessionManager
from modules.logic import LogicBypassModule
from modules.csrf import CSRFBypassModule
from modules.race import RaceConditionModule
import json

logger = logging.getLogger(__name__)


class AttackEngine:
    """Main attack orchestration engine."""
    
    def __init__(self,
                 target_url: str,
                 session_manager: SessionManager,
                 test_payload: Dict[str, Any],
                 otp_param: str = "code",
                 proxy: Optional[str] = None):
        """
        Initialize attack engine.
        
        Args:
            target_url: Target 2FA endpoint
            session_manager: SessionManager instance
            test_payload: Baseline payload with INVALID code for baseline
            otp_param: Name of OTP parameter
            proxy: Optional proxy URL (e.g., http://127.0.0.1:8080)
        """
        self.target_url = target_url
        self.session_manager = session_manager
        self.test_payload = test_payload
        self.otp_param = otp_param
        
        # Initialize requester with proxy support
        self.requester = SmartRequester(
            target_url=target_url,
            session_cookies=session_manager.get_cookies(),
            auth_header=session_manager.get_auth_header(),
            proxy=proxy
        )
        
        # Initialize analyzer (baseline set later in establish_baseline)
        self.analyzer = ResponseAnalyzer()
        
        # Results storage
        self.results = []
        
        logger.info(f"AttackEngine initialized for {target_url}")
    
    def establish_baseline(self) -> bool:
        """
        Send baseline request with invalid code to establish normal failure response.
        
        Returns:
            True if baseline established successfully
        """
        logger.info("[*] Establishing baseline with invalid OTP...")
        
        response = self.requester.send_request(
            method="POST",
            payload=self.test_payload
        )
        
        if response is None:
            logger.error("Failed to establish baseline - no response received")  
            return False
        
        self.analyzer.set_baseline(response)
        logger.info(f"[+] Baseline established: Status {response.status_code}, Length {len(response.content)}")
        return True
    
    def run_logic_bypass(self) -> List[Dict]:
        """Execute logic bypass attacks."""
        logger.info("\n[*] Running Logic Bypass Module...")
        
        module = LogicBypassModule(self.test_payload, self.otp_param)
        payloads = module.generate_payloads()
        
        results = []
        for attack_name, payload in payloads:
            logger.debug(f"Testing: {attack_name}")
            
            response = self.requester.send_request(method="POST", payload=payload)
            if response:
                analysis = self.analyzer.analyze(response, attack_name)
                results.append(analysis)
                
                if analysis['bypass_detected']:
                    self._log_bypass(analysis, payload)
        
        return results
    
    def run_csrf_bypass(self) -> List[Dict]:
        """Execute CSRF/session manipulation attacks with proper header removal."""
        logger.info("\n[*] Running CSRF/Session Bypass Module...")
        
        module = CSRFBypassModule(self.test_payload)
        variants = module.get_header_variants()
        
        results = []
        for attack_name, headers_to_remove, headers_to_add in variants:
            logger.debug(f"Testing: {attack_name}")
            
            # Clone session to isolate modifications
            import requests
            temp_session = requests.Session()
            
            # Copy cookies from original session
            temp_session.cookies.update(self.session_manager.get_cookies())
            
            # Copy authorization if exists
            auth_header = self.session_manager.get_auth_header()
            if auth_header and 'Authorization' not in headers_to_remove:
                temp_session.headers['Authorization'] = auth_header
            
            # Build headers (use requester's header generator but override)
            base_headers = self.requester._get_browser_headers()
            
            # Remove specified headers
            for header in headers_to_remove:
                if header == 'Cookie':
                    # Clear all cookies
                    temp_session.cookies.clear()
                elif header in temp_session.headers:
                    del temp_session.headers[header]
                elif header in base_headers:
                    del base_headers[header]
            
            # Add custom headers
            base_headers.update(headers_to_add)
            
            # Execute request with modified session
            try:
                response = temp_session.post(
                    self.target_url,
                    json=self.test_payload,
                    headers=base_headers,
                    timeout=10,
                    allow_redirects=False
                )
                
                logger.info(f"Response: {response.status_code} | Length: {len(response.content)}")
                
                if response is not None:
                    analysis = self.analyzer.analyze(response, attack_name)
                    results.append(analysis)
                    
                    if analysis['bypass_detected']:
                        self._log_bypass(analysis, self.test_payload)
            except Exception as e:
                logger.error(f"CSRF test '{attack_name}' failed: {e}")
        
        return results
    
    def run_race_condition(self, num_threads: int = 10) -> Dict:
        """
        Execute race condition attack.
        
        Args:
            num_threads: Number of concurrent threads
            
        Returns:
            Analysis result dict
        """
        logger.info(f"\n[*] Running Race Condition Module ({num_threads} threads)...")
        
        module = RaceConditionModule(self.test_payload, num_threads)
        
        # Create send function for race module
        def send_func(payload):
            return self.requester.send_request(method="POST", payload=payload)
        
        responses = module.execute_race(send_func)
        
        # Analyze if multiple succeeded
        success_count = sum(1 for r in responses if r.status_code == 200)
        
        result = {
            'attack_name': f'Race Condition ({num_threads} threads)',
            'bypass_detected': success_count > 1,
            'confidence_score': 90 if success_count > 1 else 0,
            'confidence_level': 'HIGH' if success_count > 1 else 'MINIMAL',
            'anomalies': [f'{success_count}/{len(responses)} requests returned 200 OK'],
            'response_status': 'Multiple',
            'response_length': 'Multiple',
            'baseline_status': self.analyzer.baseline.status_code if self.analyzer.baseline else 'Unknown',
            'baseline_length': self.analyzer.baseline.length if self.analyzer.baseline else 0
        }
        
        if result['bypass_detected']:
            logger.warning(f"[!] RACE CONDITION DETECTED: {success_count} concurrent successes!")
        
        return result
    
    def run_all_attacks(self, include_race: bool = False) -> List[Dict]:
        """
        Run all attack modules.
        
        Args:
            include_race: Whether to include race condition test (can be noisy)
            
        Returns:
            List of all analysis results
        """
        all_results = []
        
        # Establish baseline first
        if not self.establish_baseline():
            logger.error("Cannot proceed without baseline")
            return []
        
        # Run modules
        all_results.extend(self.run_logic_bypass())
        all_results.extend(self.run_csrf_bypass())
        
        if include_race:
            race_result = self.run_race_condition()
            all_results.append(race_result)
        
        # Store results
        self.results = all_results
        
        # Summary
        bypasses_found = [r for r in all_results if r['bypass_detected']]
        logger.info(f"\n{'='*70}")
        logger.info(f"SCAN COMPLETE: {len(bypasses_found)} potential bypasses found out of {len(all_results)} tests")
        logger.info(f"{'='*70}\n")
        
        return all_results
    
    def _log_bypass(self, analysis: Dict, payload: Dict):
        """Log detailed bypass information."""
        logger.warning(f"\n{'!'*70}")
        logger.warning(f"BYPASS DETECTED: {analysis['attack_name']}")
        logger.warning(f"Confidence: {analysis['confidence_level']} ({analysis['confidence_score']}%)")
        logger.warning(f"Payload: {json.dumps(payload, indent=2)}")
        logger.warning(f"Reason: {analysis.get('reason', 'Unknown')}")
        logger.warning(f"{'!'*70}\n")
    
    def save_results(self, output_file: str = "output/results.json"):
        """Save results to JSON file."""
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            logger.info(f"Results saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
