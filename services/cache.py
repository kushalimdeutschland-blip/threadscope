"""
Simple TTL Cache
----------------
Stores results in memory to avoid hitting free API rate limits.
For production, swap this out for Redis:
    pip install redis
    cache = redis.Redis(...)
    cache.setex(key, ttl, json.dumps(value))
"""

import time
import threading


class Cache:
    def __init__(self, ttl_seconds: int = 3600):
        """
        Args:
            ttl_seconds: How long to cache results (default: 1 hour).
                         Increase to 86400 (24h) for Shodan to preserve credits.
        """
        self._store: dict[str, tuple[dict, float]] = {}
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

    def get(self, key: str) -> dict | None:
        with self._lock:
            entry = self._store.get(key)
            if not entry:
                return None
            value, expires_at = entry
            if time.time() > expires_at:
                del self._store[key]
                return None
            return dict(value)

    def set(self, key: str, value: dict, ttl: int | None = None) -> None:
        ttl = ttl or self._ttl
        with self._lock:
            self._store[key] = (value, time.time() + ttl)

    def delete(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def stats(self) -> dict:
        with self._lock:
            now = time.time()
            active = sum(1 for _, (_, exp) in self._store.items() if exp > now)
            return {"total_keys": len(self._store), "active_keys": active}
