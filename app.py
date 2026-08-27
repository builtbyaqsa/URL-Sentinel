import json
import os
from fastapi import FastAPI, BackgroundTasks, Request, HTTPException, Security
from fastapi.security import APIKeyHeader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from schemas import URLScanRequest, URLScanResponse
from rules import analyze_url_heuristics
from services import check_threat_feed

# Rate limiter setup (IP based)
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="URL-Sentinel", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

LOG_FILE = "scan_logs.json"
API_KEY = "sentinel-secret-key-123"
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def log_scan_event(url: str, is_malicious: bool, score: int):
    entry = {"url": url, "is_malicious": is_malicious, "risk_score": score}
    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
        except Exception:
            logs = []
    logs.append(entry)
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)

# 1. Health Check Endpoint
@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "URL-Sentinel API"}

# 2. Scans with Rate Limiting (5 requests per minute per IP)
@app.post("/scan", response_model=URLScanResponse)
@limiter.limit("5/minute")
def scan_url(request: Request, payload: URLScanRequest, background_tasks: BackgroundTasks):
    result = analyze_url_heuristics(payload.url)
    
    score = result.get("risk_score", 0)
    flags = list(result.get("detected_flags", []))
    max_score = result.get("max_score", 100)
    is_suspicious = result.get("is_suspicious", False)
        
    in_feed = check_threat_feed(payload.url)
    if in_feed:
        score += 80
        flags.append("URL found in threat database")
        
    is_malicious = (score >= 50) or is_suspicious or (len(flags) > 0) or bool(in_feed)
    
    background_tasks.add_task(log_scan_event, payload.url, is_malicious, score)
    
    return URLScanResponse(
        url=payload.url,
        is_malicious=is_malicious,
        risk_score=score,
        matched_rules=flags,
        max_score=max_score,
        is_suspicious=is_suspicious,
        detected_flags=flags
    )

# 3. Protected Metrics Endpoint
@app.get("/metrics")
def get_metrics(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized: Invalid API Key")
        
    if not os.path.exists(LOG_FILE):
        return {"total_scans": 0, "threats_detected": 0, "safe_urls": 0}
    try:
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)
    except Exception:
        logs = []
        
    total = len(logs)
    threats = sum(1 for log in logs if log.get("is_malicious"))
    safe = total - threats
    
    return {
        "total_scans": total,
        "threats_detected": threats,
        "safe_urls": safe
    }