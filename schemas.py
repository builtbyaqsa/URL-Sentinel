from pydantic import BaseModel
from typing import List

class URLScanRequest(BaseModel):
    url: str

class URLScanResponse(BaseModel):
    url: str
    risk_score: int
    max_score: int
    is_suspicious: bool
    detected_flags: List[str]