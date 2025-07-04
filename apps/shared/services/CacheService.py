from typing import Any, Optional

import structlog
from django.conf import settings
from django.core.cache import cache

# Configure structured logger
logger = structlog.get_logger(__name__)


class CacheService:
    """
    Service for caching operations with standardized patterns.

    This service provides a consistent interface for caching
    operations across the application with proper serialization,
    compression, and invalidation strategies.
    """

    def __init__(self):
        """Initialize cache service."""
        self.default_timeout = 300  # 5 minutes
        self.key_prefix = getattr(settings, 'CACHE_KEY_PREFIX', 'neubit_core')

    def get(
            self,
            key: str,
            default: Any = None,
            version: Optional[int] = None
    ) -> Any:
        """
        Get value from cache.

        Args:
            key: Cache key
            default: Default value if key not found
            version: Cache version

        Returns:
            Cached value or default
        """
        try:
            full_key = self._make_key(key)
            value = cache.get(full_key, default, version=version)

            logger.debug(
                "cache_get",
                key=full_key,
                hit=value is not default
            )

            return value

        except Exception as e:
            logger.error("cache_get_failed", key=key, error=str(e))
            return default

    def set(
            self,
            key: str,
            value: Any,
            timeout: Optional[int] = None,
            version: Optional[int] = None
    ) -> bool:
        """
        Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            timeout: Cache timeout in seconds
            version: Cache version

        Returns:
            True if value was set successfully
        """
        try:
            full_key = self._make_key(key)
            cache_timeout = timeout or self.default_timeout

            cache.set(full_key, value, timeout=cache_timeout, version=version)

            logger.debug(
                "cache_set",
                key=full_key,
                timeout=cache_timeout
            )

            return True

        except Exception as e:
            logger.error("cache_set_failed", key=key, error=str(e))
            return False

    def delete(self, key: str, version: Optional[int] = None) -> bool:
        """
        Delete value from cache.

        Args:
            key: Cache key
            version: Cache version

        Returns:
            True if value was deleted successfully
        """
        try:
            full_key = self._make_key(key)
            cache.delete(full_key, version=version)

            logger.debug("cache_delete", key=full_key)
            return True

        except Exception as e:
            logger.error("cache_delete_failed", key=key, error=str(e))
            return False

    def get_or_set(
            self,
            key: str,
            default_func: callable,
            timeout: Optional[int] = None,
            version: Optional[int] = None
    ) -> Any:
        """
        Get value from cache or set it using a function.

        Args:
            key: Cache key
            default_func: Function to call if key not in cache
            timeout: Cache timeout
            version: Cache version

        Returns:
            Cached or computed value
        """
        try:
            full_key = self._make_key(key)
            cache_timeout = timeout or self.default_timeout

            value = cache.get(full_key, version=version)
            if value is None:
                value = default_func()
                cache.set(full_key, value, timeout=cache_timeout, version=version)

                logger.debug(
                    "cache_miss_set",
                    key=full_key,
                    timeout=cache_timeout
                )
            else:
                logger.debug("cache_hit", key=full_key)

            return value

        except Exception as e:
            logger.error("cache_get_or_set_failed", key=key, error=str(e))
            return default_func()

    def invalidate_pattern(self, pattern: str) -> int:
        """
        Invalidate all cache keys matching a pattern.

        Args:
            pattern: Key pattern (supports wildcards)

        Returns:
            Number of keys invalidated
        """
        try:
            # This is a simplified implementation
            # In production, use Redis-specific commands for pattern matching
            full_pattern = self._make_key(pattern)

            # For now, we'll just log the pattern
            logger.info("cache_invalidate_pattern", pattern=full_pattern)

            # Return 0 as we don't have a generic implementation
            return 0

        except Exception as e:
            logger.error("cache_invalidate_pattern_failed", pattern=pattern, error=str(e))
            return 0

    def _make_key(self, key: str) -> str:
        """
        Create full cache key with prefix.

        Args:
            key: Base key

        Returns:
            Full cache key
        """
        return f"{self.key_prefix}:{key}"


cache_service = CacheService()
