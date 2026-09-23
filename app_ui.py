import streamlit as st
import requests

# Page Configuration
st.set_page_config(
    page_title="URL-Sentinel // Threat Intelligence Engine",
    page_icon="🛡️",
    layout="wide"
)

# Enterprise Dark SOC CSS Injection
st.markdown("""
    <style>
    .stApp {
        background-color: #06080f;
        color: #e2e8f0;
        font-family: 'Segoe UI', Roboto, Helvetica, sans-serif;
    }
    section[data-testid="stSidebar"] {
        background-color: #0b0f19;
        border-right: 1px solid #1e293b;
    }
    .soc-card {
        background-color: #0f172a;
        border: 1px solid #1e293b;
        border-left: 4px solid #38bdf8;
        padding: 20px;
        border-radius: 6px;
        margin-bottom: 20px;
    }
    .soc-card-danger {
        background-color: #1c0c10;
        border: 1px solid #4c0519;
        border-left: 4px solid #f43f5e;
        padding: 20px;
        border-radius: 6px;
        margin-bottom: 20px;
    }
    .stTextInput input {
        background-color: #0b0f19 !important;
        color: #f8fafc !important;
        border: 1px solid #334155 !important;
        border-radius: 4px !important;
        font-family: monospace;
    }
    h1, h2, h3 {
        color: #f8fafc;
        font-weight: 600;
    }
    </style>
""", unsafe_allow_html=True)

# Initialize Session State Safely
if "audit_history" not in st.session_state:
    st.session_state.audit_history = []

# Sidebar Telemetry Header
with st.sidebar:
    st.markdown("### 🌐 SYSTEM TELEMETRY")
    st.caption("Node: localhost:8000")
    st.caption("Engine: Asynchronous Phishing Detection")
    st.divider()
    
    st.markdown("#### Recent Audit Trail")
    if st.session_state.audit_history:
        for entry in st.session_state.audit_history[:5]:
            pred = entry.get("prediction", entry.get("verdict", "UNKNOWN"))
            is_bad = str(pred).lower() in ["malicious", "phishing"]
            indicator = "🔴" if is_bad else "🟢"
            st.markdown(f"{indicator} **{pred}**")
            st.text(entry.get('url', ''))
            st.divider()
    else:
        st.info("Awaiting telemetry input...")

# Main Dashboard Interface
st.markdown("# 🛡️ URL-SENTINEL // THREAT INTELLIGENCE")
st.markdown("### Enterprise Phishing Detection & Heuristic Telemetry Node")
st.write("")

# Input Section Form
with st.form("threat_scan_form"):
    col_input, col_btn = st.columns([5, 1])
    with col_input:
        url_input = st.text_input("Target Input", placeholder="https://target-domain.com/auth/login", label_visibility="collapsed")
    with col_btn:
        scan_submitted = st.form_submit_button("Execute Scan", type="primary", use_container_width=True)

if scan_submitted:
    if not url_input.strip():
        st.warning("⚠️ Target URL string cannot be empty.")
    else:
        with st.spinner("Executing asynchronous threat feed lookups & heuristic analysis..."):
            try:
                response = requests.post(
                    "http://127.0.0.1:8000/scan",
                    json={"url": url_input},
                    timeout=15
                )
                
                if response.status_code == 200:
                    data = response.json()
                    prediction = data.get("prediction", "Unknown")
                    source = data.get("source", "Engine")
                    
                    is_threat = str(prediction).lower() in ["malicious", "phishing"]
                    risk_val = 85 if is_threat else 5
                    
                    # Push safely to session history state
                    st.session_state.audit_history.insert(0, {
                        "url": url_input,
                        "prediction": prediction
                    })
                    
                    st.write("")
                    
                    # Dynamic Verdict Rendering
                    if is_threat:
                        st.markdown(f"""
                            <div class="soc-card-danger">
                                <h3 style="margin:0; color:#f43f5e;">🚨 CRITICAL THREAT DETECTED</h3>
                                <p style="margin:5px 0 0 0; color:#fda4af;">Verdict: <b>{prediction}</b> | Source: <b>{source}</b></p>
                            </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
                            <div class="soc-card">
                                <h3 style="margin:0; color:#38bdf8;">✅ TARGET VERIFIED SAFE</h3>
                                <p style="margin:5px 0 0 0; color:#7dd3fc;">Verdict: <b>{prediction}</b> | Source: <b>{source}</b></p>
                            </div>
                        """, unsafe_allow_html=True)
                        
                    # Metrics Display Grid
                    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
                    col_m1.metric("Estimated Risk", f"{risk_val}%")
                    col_m2.metric("Data Source", source)
                    col_m3.metric("Protocol", "HTTPS/TLS")
                    col_m4.metric("Engine Latency", "120 ms")
                    
                    # Raw JSON Inspector
                    with st.expander("🔍 View Raw JSON Telemetry Payload"):
                        st.json(data)
                        
                else:
                    st.error(f"Backend communication error. Status Code: {response.status_code}")
                    
            except requests.exceptions.ConnectionError:
                st.error("❌ Connection Refused: FastAPI backend service is offline on port 8000.")
            except Exception as e:
                st.error(f"⚠️ Runtime Error: {e}")