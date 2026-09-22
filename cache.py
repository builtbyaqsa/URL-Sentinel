import redis
import os

# Connect to local Redis instance (Fallback to memory/mock if not available)
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

try:
    cache_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True, socket_timeout=2)
except Exception:
    cache_client = None

def get_cached_scan(url: str):
    if not cache_client:
        return None
    try:
        return cache_client.get(f'scan:{url}')
    except Exception:
        return None

def set_cached_scan(url: str, result: str, ttl: int = 3600):
    if not cache_client:
        return
    try:
        cache_client.setex(f'scan:{url}', ttl, result)
    except Exception:
        pass
