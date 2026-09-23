import redis
import json

try:
    cache_client = redis.Redis(host='localhost', port=6379, db=0, socket_connect_timeout=1)
    cache_client.ping()
except Exception:
    cache_client = None

def get_cached_scan(url: str):
    if not cache_client:
        return None
    try:
        data = cache_client.get(url)
        if data:
            return json.loads(data)
    except Exception:
        pass
    return None

def set_cached_scan(url: str, result: dict, ttl: int = 3600):
    if not cache_client:
        return
    try:
        cache_client.setex(url, ttl, json.dumps(result))
    except Exception:
        pass