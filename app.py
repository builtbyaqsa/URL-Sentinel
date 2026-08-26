import json
import os
from fastapi import FastAPI, BackgroundTasks
from schemas import URLScanRequest, URLScanResponse
from rules import analyze_url_heuristics
from services import check_threat_feed

app = FastAPI(title="URL-Sentinel", version="1.0.0")

LOG_FILE = "scan_logs.json"

def log_scan_event(url: str, is_malicious: bool, score: int):
    entry = {
        "url": url,
        "is_malicious": is_malicious,
        "risk_score": score
    }
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

@app.post("/scan", response_model=URLScanResponse)
def scan_url(payload: URLScanRequest, background_tasks: BackgroundTasks):
    result = analyze_url_heuristics(payload.url)
    
    score = result.get("risk_score", 0)
    flags = list(result.get("detected_flags", []))
    max_score = result.get("max_score", 100)
    is_suspicious = result.get("is_suspicious", False)
        
    # Flexible threat feed check
    in_feed = check_threat_feed(payload.url)
    threat_found = False

    if isinstance(in_feed, dict):
        threat_found = in_feed.get("is_malicious", False) or in_feed.get("in_feed", False) or bool(in_feed)
    else:
        threat_found = bool(in_feed)

    if threat_found:
        score += 80
        flags.append("URL found in threat database")
        
    # Mark malicious if score >= 50 OR if any heuristic flags/suspicion were detected
    is_malicious = (score >= 50) or is_suspicious or len(flags) > 0 or threat_found
    
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

@app.get("/metrics")
def get_metrics():
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