from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
import pickle
import numpy as np
import models
from database import engine, get_db
from feature_extractor import extract_features

models.Base.metadata.create_all(bind=engine)

with open('phishing_model.pkl', 'rb') as f:
    ml_model = pickle.load(f)

app = FastAPI(title='URL-Sentinel API', version='1.0')

class URLScanRequest(BaseModel):
    url: str

@app.get('/')
def read_root():
    return {'message': 'URL-Sentinel ML Engine is Live'}

@app.post('/scan')
def scan_url(payload: URLScanRequest, db: Session = Depends(get_db)):
    ext = extract_features(payload.url)
    features_vector = np.array([[
        ext['url_length'], ext['num_dots'], ext['num_hyphens'],
        ext['num_at'], ext['has_https'], ext['has_ip'],
        ext['has_suspicious_keyword']
    ]])
    
    pred = ml_model.predict(features_vector)[0]
    prob = ml_model.predict_proba(features_vector)[0][1]
    result_label = 'Malicious' if pred == 1 else 'Safe'
    
    scan_entry = models.ScanLog(
        url=payload.url,
        prediction=result_label,
        risk_score=float(round(prob, 2))
    )
    db.add(scan_entry)
    db.commit()
    db.refresh(scan_entry)
    
    return {
        'url': payload.url,
        'prediction': result_label,
        'ml_confidence_score': float(round(prob, 2)),
        'features': ext
    }

@app.get('/scans', tags=['Telemetry'])
def get_scan_history(limit: int = 10, db: Session = Depends(get_db)):
    scans = db.query(models.ScanLog).order_by(models.ScanLog.id.desc()).limit(limit).all()
    return {'total': len(scans), 'scans': scans}
