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
from predictor import predict_url

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
        redis_status = "connected" if cache_client and cache_client.ping() else "disconnected"
    except Exception:
        redis_status = "disconnected"

    return {
        "status": "healthy" if db_status == "connected" else "unhealthy",
        "database": db_status,
        "cache": redis_status
    }

@app.post("/scan")
@limiter.limit("10/minute")
def scan_url(
    request: Request,
    scan_req: ScanRequest,
    db: Session = Depends(get_db)
):
    url = scan_req.url

    # Check cache first
    try:
        cached_result = get_cached_scan(url)

        if cached_result:
            # Cache currently stores only the verdict.
            # Recalculate ML probability for the response.
            ml_result = predict_url(url)

            return {
                "url": url,
                "prediction": cached_result,
                "phishing_probability": ml_result["phishing_probability"],
                "risk_score": ml_result["risk_score"],
                "source": "Cache (ML probability recalculated)"
            }

    except Exception:
        pass

    # Check threat intelligence
    threat_intel = check_threat_intelligence(url)

    if threat_intel["threat_found"]:

        prediction = threat_intel["verdict"]

        source = f"Threat Feed ({threat_intel['feed']})"

        # Threat feed verdict is independent of ML probability.
        phishing_probability = None
        risk_score = None

    else:

        # Random Forest prediction
        ml_result = predict_url(url)

        prediction = ml_result["prediction"]

        source = ml_result["source"]

        phishing_probability = ml_result["phishing_probability"]

        risk_score = ml_result["risk_score"]

    # Save prediction to cache
    try:
        set_cached_scan(url, prediction)

    except Exception:
        pass

    # Save scan to database
    db_scan = ScanLog(
        url=url,
        prediction=prediction
    )

    db.add(db_scan)
    db.commit()

    # Return complete response
    return {
        "url": url,
        "prediction": prediction,
        "phishing_probability": phishing_probability,
        "risk_score": risk_score,
        "source": source
    }

@app.get("/scans")
def get_scans(db: Session = Depends(get_db)):
    scans = db.query(ScanLog).all()
    return {"scans": [{"id": s.id, "url": s.url, "prediction": s.prediction} for s in scans]} 
@app.post("/predict")
def predict_phishing_url(scan_req: ScanRequest):
    result = predict_url(scan_req.url)
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)