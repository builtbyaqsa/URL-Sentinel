from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import engine, get_db, Base
from models import ScanLog
from cache import get_cached_scan, set_cached_scan

Base.metadata.create_all(bind=engine)

app = FastAPI(title='URL-Sentinel API')

class ScanRequest(BaseModel):
    url: str

@app.get('/')
def read_root():
    return {'message': 'URL-Sentinel API is running'}

@app.post('/scan')
def scan_url(request: ScanRequest, db: Session = Depends(get_db)):
    cached_result = get_cached_scan(request.url)
    if cached_result:
        return {'url': request.url, 'prediction': cached_result, 'source': 'cache'}

    # Basic structural check for demo pipeline
    prediction = 'Malicious' if '192.168' in request.url or 'login' in request.url else 'Legitimate'
    set_cached_scan(request.url, prediction)

    db_scan = ScanLog(url=request.url, prediction=prediction)
    db.add(db_scan)
    db.commit()

    return {'url': request.url, 'prediction': prediction, 'source': 'model'}

@app.get('/scans')
def get_scans(db: Session = Depends(get_db)):
    scans = db.query(ScanLog).all()
    return {'scans': [{'id': s.id, 'url': s.url, 'prediction': s.prediction} for s in scans]}
