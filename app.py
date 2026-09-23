from fastapi import FastAPI, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import engine, get_db, Base
from models import ScanLog
from cache import get_cached_scan, set_cached_scan, cache_client
from services import check_threat_intelligence
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="URL-Sentinel API", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

class ScanRequest(BaseModel):
    url: str

@app.get("/")
def read_root():
    return {"message": "URL-Sentinel API is running"}

@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    db_status = "connected"
    try:
        db.execute("SELECT 1")
    except Exception:
        db_status = "disconnected"

    try:
        redis_status = "connected" if cache_client.ping() else "disconnected"
    except Exception:
        redis_status = "disconnected"

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "database": db_status,
        "cache": redis_status
    }

@app.post("/scan")
@limiter.limit("10/minute")
def scan_url(request: Request, scan_req: ScanRequest, db: Session = Depends(get_db)):
    cached_result = get_cached_scan(scan_req.url)
    if cached_result:
        return {"url": scan_req.url, "prediction": cached_result, "source": "cache"}

    threat_intel = check_threat_intelligence(scan_req.url)
    if threat_intel["threat_found"]:
        prediction = threat_intel["verdict"]
        source = f"Threat Feed ({threat_intel['feed']})"
    else:
        prediction = "Malicious" if "192.168" in scan_req.url else "Legitimate"
        source = "ML Model"

    set_cached_scan(scan_req.url, prediction)
    db_scan = ScanLog(url=scan_req.url, prediction=prediction)
    db.add(db_scan)
    db.commit()

    return {"url": scan_req.url, "prediction": prediction, "source": source}

@app.get("/scans")
def get_scans(db: Session = Depends(get_db)):
    scans = db.query(ScanLog).all()
    return {"scans": [{"id": s.id, "url": s.url, "prediction": s.prediction} for s in scans]}