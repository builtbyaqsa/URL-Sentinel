from fastapi import FastAPI
import re

app = FastAPI()

@app.get("/")
def home():
    return {"message": "URL-Sentinel API is running"}

@app.post("/scan")
def scan_url(data: dict):
    url = data.get("url", "")
    risk_score = 0
    flags = []

    if not url:
        return {"error": "URL parameter is missing"}

    # 1. Check HTTPS
    if not url.startswith("https://"):
        risk_score += 2
        flags.append("Missing HTTPS connection")

    # 2. Check URL Length
    if len(url) > 50:
        risk_score += 2
        flags.append("URL length is unusually long")

    # 3. Check for Raw IP Address
    ip_pattern = r"http[s]?://(?:\d{1,3}\.){3}\d{1,3}"
    if re.search(ip_pattern, url):
        risk_score += 3
        flags.append("Direct IP address used instead of domain")

    # Evaluation
    is_suspicious = risk_score >= 3
    
    return {
        "url": url,
        "risk_score": risk_score,
        "max_score": 7,
        "is_suspicious": is_suspicious,
        "detected_flags": flags
    }