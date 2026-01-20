"""
Race condition attack module.
Tests if OTP codes can be reused or brute-forced via concurrent requests.
"""
import logging
import concurrent.futures
from typing import Dict, Any, Callable, List
import requests

logger = logging.getLogger(__name__)


class RaceConditionModule:
    """Implements race condition testing (Turbo Intruder style)."""
    
    def __init__(self, base_payload: Dict[str, Any], num_threads: int = 10):
        """
        Initialize race condition module.
        
        Args:
            base_payload: Original request payload with valid/invalid OTP
            num_threads: Number of concurrent threads to use
        """
        self.base_payload = base_payload.copy()
        self.num_threads = num_threads
        logger.info(f"RaceConditionModule initialized with {num_threads} threads")
    
    def execute_race(self, send_func: Callable) -> List[requests.Response]:
        """
        Execute race condition attack.
        
        Args:
            send_func: Function that sends a request (from SmartRequester)
                      Should accept payload as argument and return Response
        
        Returns:
            List of Response objects from all threads
        """
        logger.info(f"Launching race condition attack with {self.num_threads} threads")
        
        responses = []
        
        # Use ThreadPoolExecutor for concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            # Submit all requests simultaneously
            futures = [
                executor.submit(send_func, self.base_payload.copy())
                for _ in range(self.num_threads)
            ]
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                try:
                    response = future.result()
                    if response:
                        responses.append(response)
                except Exception as e:
                    logger.error(f"Race thread failed: {e}")
        
        # Analyze results
        success_count = sum(1 for r in responses if r.status_code == 200)
        logger.info(f"Race results: {success_count}/{len(responses)} returned status 200")
        
        if success_count > 1:
            logger.warning(f"[!] Potential race condition: {success_count} successful responses!")
        
        return responses
    
    def get_description(self) -> str:
        """Return module description."""
        return """
        Race Condition Module - Tests OTP reuse vulnerabilities:
        - Sends same OTP code multiple times concurrently
        - Detects if server fails to invalidate code after first use
        - Can identify race windows in rate limiting
        - Useful for brute-force scenarios with predictable codes
        """
