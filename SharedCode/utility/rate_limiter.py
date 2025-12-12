"""
Global rate limiter for BloodHound API requests.
Uses token bucket algorithm to ensure we never exceed the API rate limit.
Thread-safe and shared across all BloodhoundManager instances.
"""
import threading
import time
import logging
from typing import Optional
from .utils import get_max_requests_per_second


class GlobalRateLimiter:
    """
    Thread-safe global rate limiter using token bucket algorithm.
    Ensures all BloodHound API requests across all functions stay within rate limits.
    
    The rate limiter maintains a bucket of tokens that refill at a fixed rate.
    Each API request consumes one token. If no tokens are available, the request waits.
    """
    
    _instance: Optional['GlobalRateLimiter'] = None
    _lock = threading.Lock()
    
    def __init__(self, max_requests_per_second: float = 50.0, logger: Optional[logging.Logger] = None):
        """
        Initialize the global rate limiter.
        
        Args:
            max_requests_per_second: Maximum requests per second (default: 50, well under 65 limit)
            logger: Logger instance (optional)
        """
        self.max_requests_per_second = max_requests_per_second
        self.tokens_per_second = max_requests_per_second
        self.max_tokens = max_requests_per_second  # Bucket capacity equals refill rate
        self.current_tokens = self.max_tokens  # Start with full bucket
        self.last_refill_time = time.time()
        self._lock = threading.Lock()
        self.logger = logger or logging.getLogger(__name__)
        
        # Statistics
        self.total_requests = 0
        self.total_wait_time = 0.0
        
        self.logger.info(
            f"GlobalRateLimiter initialized: {max_requests_per_second} requests/second "
            f"(max tokens: {self.max_tokens})"
        )
    
    @classmethod
    def get_instance(cls, max_requests_per_second: Optional[float] = None, 
                     logger: Optional[logging.Logger] = None) -> 'GlobalRateLimiter':
        """
        Get or create the singleton instance of GlobalRateLimiter.
        
        Args:
            max_requests_per_second: Maximum requests per second (only used on first creation)
            logger: Logger instance (optional)
        
        Returns:
            GlobalRateLimiter: The singleton instance
        """
        if cls._instance is None:
            with cls._lock:
                # Double-check locking pattern
                if cls._instance is None:
                    if max_requests_per_second is None:
                        # Get from environment variable or use default
                        max_requests_per_second = get_max_requests_per_second()
                    cls._instance = cls(max_requests_per_second, logger)
        return cls._instance
    
    def _refill_tokens(self):
        """Refill tokens based on elapsed time since last refill."""
        now = time.time()
        elapsed = now - self.last_refill_time
        
        if elapsed > 0:
            # Add tokens based on refill rate
            tokens_to_add = elapsed * self.tokens_per_second
            self.current_tokens = min(
                self.max_tokens,
                self.current_tokens + tokens_to_add
            )
            self.last_refill_time = now
    
    def acquire(self, timeout: Optional[float] = None) -> bool:
        """
        Acquire a token for making an API request.
        Blocks until a token is available or timeout occurs.
        
        Args:
            timeout: Maximum time to wait for a token (None = wait indefinitely)
        
        Returns:
            bool: True if token acquired, False if timeout
        """
        start_time = time.time()
        
        with self._lock:
            while True:
                # Refill tokens
                self._refill_tokens()
                
                # Check if we have a token available
                if self.current_tokens >= 1.0:
                    self.current_tokens -= 1.0
                    self.total_requests += 1
                    wait_time = time.time() - start_time
                    self.total_wait_time += wait_time
                    
                    if wait_time > 0.01:  # Log if we had to wait more than 10ms
                        self.logger.debug(
                            f"Rate limiter: waited {wait_time:.3f}s for token. "
                            f"Remaining tokens: {self.current_tokens:.2f}"
                        )
                    return True
                
                # No token available, calculate wait time
                tokens_needed = 1.0 - self.current_tokens
                wait_time = tokens_needed / self.tokens_per_second
                
                # Check timeout
                if timeout is not None:
                    elapsed = time.time() - start_time
                    if elapsed + wait_time > timeout:
                        self.logger.warning(
                            f"Rate limiter timeout: could not acquire token within {timeout}s"
                        )
                        return False
                
                # Release lock and wait
                self._lock.release()
                try:
                    time.sleep(wait_time)
                finally:
                    self._lock.acquire()
    
    def wait(self):
        """
        Wait until a token is available, then consume it.
        This is the main method to call before making an API request.
        """
        self.acquire()
    
    def get_stats(self) -> dict:
        """
        Get statistics about rate limiter usage.
        
        Returns:
            dict: Statistics including total requests, average wait time, etc.
        """
        with self._lock:
            avg_wait_time = (
                self.total_wait_time / self.total_requests
                if self.total_requests > 0
                else 0.0
            )
            return {
                "total_requests": self.total_requests,
                "total_wait_time": self.total_wait_time,
                "average_wait_time": avg_wait_time,
                "current_tokens": self.current_tokens,
                "max_requests_per_second": self.max_requests_per_second,
                "tokens_per_second": self.tokens_per_second,
            }
    
    def reset_stats(self):
        """Reset statistics counters."""
        with self._lock:
            self.total_requests = 0
            self.total_wait_time = 0.0


# Convenience function to get the global rate limiter instance
def get_global_rate_limiter(logger: Optional[logging.Logger] = None) -> GlobalRateLimiter:
    """
    Get the global rate limiter instance.
    
    Args:
        logger: Logger instance (optional)
    
    Returns:
        GlobalRateLimiter: The singleton rate limiter instance
    """
    return GlobalRateLimiter.get_instance(logger=logger)

