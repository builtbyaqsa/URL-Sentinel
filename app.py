import json
import re
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Header, Request, status
from pydantic import BaseModel, HttpUrl
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

import models
from database import Base, engine, get_db

# Initialize database tables
Base.metadata.create_all(bind=engine)

# Initialize Rate Limiter
limiter = Limiter(key_func=get_remote_address)

# Create FastAPI app instance
app = FastAPI(
    title="URL-Sentinel",
    description="A containerized microservice for real-time URL threat detection.",
    version="1.0.0",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security Configuration
API_KEY_CREDENTIAL = "sentinel-secret-key-2026"

def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_KEY_CREDENTIAL:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key",
        )
    return x_api_key

# Request / Response Schemas
class URLScanRequest(BaseModel):
    url: HttpUrl

class URLScanResponse(BaseModel):
    url: str
    risk_score: float
    is_malicious: bool
    detected_heuristics: List[str]

# Threat Feed Loader
def load_threat_feed() -> set:
    try:
        with open("phishing_feed.json", "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return set(data)
            return set(data.get("malicious_domains", []))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()

THREAT_FEED = load_threat_feed()

# Heuristic Engine
def analyze_url_heuristics(target_url: str) -> tuple[float, List[str], bool]:
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""
    heuristics = []
    score = 0.0

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        heuristics.append("IP Address used instead of Domain")
        score += 0.4

    keywords = ["login", "verify", "secure", "banking", "update", "account"]
    if any(kw in target_url.lower() for kw in keywords):
        heuristics.append("High-risk keyword present in URL")
        score += 0.25

    if len(target_url) > 75:
        heuristics.append("Excessive URL length")
        score += 0.15

    if hostname in THREAT_FEED:
        heuristics.append("Domain listed in active malicious threat feed")
        score += 0.6

    is_malicious = score >= 0.5
    return min(score, 1.0), heuristics, is_malicious

# DB Helper
def log_scan_to_db(db: Session, url: str, risk_score: float, is_malicious: bool):
    log_entry = models.ScanLog(
        url=url,
        risk_score=risk_score,
        is_malicious=is_malicious
    )
    db.add(log_entry)
    db.commit()

# Endpoints
@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "healthy", "service": "URL-Sentinel"}

@app.post("/scan", response_model=URLScanResponse, tags=["Scanner"])
@limiter.limit("10/minute")
def scan_url(
    request: Request,
    payload: URLScanRequest,
    db: Session = Depends(get_db)
):
    target_str = str(payload.url)
    score, detected, is_malicious = analyze_url_heuristics(target_str)
    log_scan_to_db(db, url=target_str, risk_score=score, is_malicious=is_malicious)

    return URLScanResponse(
        url=target_str,
        risk_score=score,
        is_malicious=is_malicious,
        detected_heuristics=detected
    )

@app.get("/metrics", tags=["Telemetry"])
def get_metrics(
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    total_scans = db.query(models.ScanLog).count()
    flagged_scans = db.query(models.ScanLog).filter(models.ScanLog.is_malicious == True).count()

    return {
        "total_scans_processed": total_scans,
        "flagged_malicious_urls": flagged_scans,
        "database_engine": "SQLite / SQLAlchemy ORM"
    }