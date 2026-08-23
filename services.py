import json
import os

FEED_FILE = "phishing_feed.json"

def load_threat_feed():
    if not os.path.exists(FEED_FILE):
        return []
    with open(FEED_FILE, "r") as f:
        return json.load(f)

def check_threat_feed(url: str) -> bool:
    feed = load_threat_feed()
    for bad_url in feed:
        if bad_url.lower() in url.lower():
            return True
    return False