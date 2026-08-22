from fastapi import FastAPI
from schemas import URLScanRequest, URLScanResponse
from rules import analyze_url_heuristics

app = FastAPI(
    title="URL-Sentinel API",
    description="Enterprise Phishing & Malicious URL Detection Engine",
    version="1.0.0"
)

@app.get("/")
def read_root():
    return {"message": "URL-Sentinel API is running"}

@app.post("/scan", response_model=URLScanResponse)
def scan_url(request: URLScanRequest):
    result = analyze_url_heuristics(request.url)
    return result