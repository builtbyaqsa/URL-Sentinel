from pydantic import BaseModel
from typing import List, Optional

class URLScanRequest(BaseModel):
    url: str

class URLScanResponse(BaseModel):
    url: str
    is_malicious: bool
    risk_score: int
    matched_rules: List[str] = []
    max_score: Optional[int] = 100
    is_suspicious: Optional[bool] = False
    detected_flags: Optional[List[str]] = []