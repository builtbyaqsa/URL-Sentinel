import re

def analyze_url(url):
    print(f"\n--- Analyzing: {url} ---")
    risk_score = 0
    
    # 1. Check HTTPS
    if not url.startswith("https://"):
        print("⚠️ Warning: Missing HTTPS connection.")
        risk_score += 2
    else:
        print("✅ Secure HTTPS connection present.")
        
    # 2. Check URL Length
    if len(url) > 50:
        print("⚠️ Warning: Abnormally long URL detected.")
        risk_score += 2
    else:
        print("✅ Normal URL length.")

    # 3. Check for Raw IP Address in URL
    ip_pattern = r"http[s]?://(?:\d{1,3}\.){3}\d{1,3}"
    if re.search(ip_pattern, url):
        print("🚨 Alert: Direct IP address used instead of Domain Name!")
        risk_score += 3

    # Final Risk Evaluation
    print(f"Total Risk Score: {risk_score}/7")
    if risk_score >= 3:
        print("❌ Final Result: SUSPICIOUS / HIGH RISK URL")
    else:
        print("✅ Final Result: SAFE / LOW RISK URL")

# Test URLs
analyze_url("http://192.168.1.1/login-verify-account-security-update")
analyze_url("https://google.com")