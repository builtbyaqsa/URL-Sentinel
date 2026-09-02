from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String
from database import Base

class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True, nullable=False)
    risk_score = Column(Float, nullable=False)
    is_malicious = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)