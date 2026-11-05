import streamlit as st
import requests
import time
from urllib.parse import urlparse

# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="URL-Sentinel // Threat Intelligence Engine",
    page_icon="🛡️",
    layout="wide"
)

API_URL = "http://127.0.0.1:8000/scan"

# ==========================================
# PROFESSIONAL DARK SOC DESIGN
# ==========================================

st.markdown("""
<style>

.stApp {
    background-color: #06080f;
    color: #e2e8f0;
    font-family: 'Segoe UI', sans-serif;
}

section[data-testid="stSidebar"] {
    background-color: #0b0f19;
    border-right: 1px solid #1e293b;
}

section[data-testid="stSidebar"] * {
    color: #e2e8f0;
}

h1, h2, h3 {
    color: #f8fafc !important;
}

p, label {
    color: #cbd5e1;
}

div[data-testid="stMetric"] {
    background-color: #111827;
    padding: 18px;
    border-radius: 10px;
    border: 1px solid #1e293b;
}

div[data-testid="stMetricLabel"] {
    color: #94a3b8;
}

div[data-testid="stMetricValue"] {
    color: #38bdf8;
}

.stTextInput input {
    background-color: #0b0f19 !important;
    color: #ffffff !important;
    border: 1px solid #334155 !important;
    border-radius: 6px;
}

.stButton button,
.stFormSubmitButton button {
    background-color: #ef4444;
    color: white;
    border-radius: 6px;
    border: none;
    font-weight: bold;
}

.stButton button:hover,
.stFormSubmitButton button:hover {
    background-color: #dc2626;
    color: white;
}

.soc-card {
    background-color: #0f172a;
    border: 1px solid #1e293b;
    border-left: 4px solid #38bdf8;
    padding: 24px;
    border-radius: 8px;
    margin-top: 20px;
}

.soc-card-danger {
    background-color: #1c0c10;
    border: 1px solid #4c0519;
    border-left: 4px solid #f43f5e;
    padding: 24px;
    border-radius: 8px;
    margin-top: 20px;
}

</style>
""", unsafe_allow_html=True)

# ==========================================
# SESSION STATE
# ==========================================

if "audit_history" not in st.session_state:
    st.session_state.audit_history = []

# ==========================================
# SIDEBAR
# ==========================================

with st.sidebar:

    st.markdown("### 🌐 SYSTEM TELEMETRY")

    st.caption("Node: localhost:8000")

    st.caption("Engine: Random Forest Phishing Detection")

    st.divider()

    st.markdown("### Recent Audit Trail") 
    history_placeholder = st.empty()

def render_audit_history():
    with history_placeholder.container():
        if st.session_state.audit_history:
            for entry in st.session_state.audit_history[:5]:
                prediction = entry.get("prediction", "Unknown")

                is_bad = prediction.lower() in [
                    "phishing",
                    "malicious"
                ]

                indicator = "🔴" if is_bad else "🟢"

                st.markdown(
                    f"{indicator} **{prediction}**"
                )

                st.caption(entry.get("url", ""))
                st.divider()
        else:
            st.info("Awaiting telemetry input...")


render_audit_history()

# ==========================================
# MAIN DASHBOARD
# ==========================================

st.markdown(
    "# 🛡️ URL-SENTINEL // THREAT INTELLIGENCE"
)

st.markdown(
    "### Enterprise Phishing Detection & Risk Analysis Engine"
)

st.write("")

# ==========================================
# URL INPUT FORM
# ==========================================

with st.form("threat_scan_form"):

    col_input, col_button = st.columns([5, 1])

    with col_input:

        url_input = st.text_input(
            "Target URL",
            placeholder="https://example.com/login",
            label_visibility="collapsed"
        )

    with col_button:

        scan_submitted = st.form_submit_button(
            "Execute Scan",
            type="primary",
            use_container_width=True
        )

# ==========================================
# URL SCANNING
# ==========================================

if scan_submitted:

    url_input = url_input.strip()

    if not url_input:

        st.warning("⚠️ Please enter a URL.")

    else:

        parsed_url = urlparse(url_input)

        if (
            parsed_url.scheme not in ["http", "https"]
            or not parsed_url.hostname
        ):

            st.error(
                "❌ Invalid URL. Please enter a valid HTTP or HTTPS URL."
            )

        else:

            with st.spinner(
                "Analyzing URL using Threat Intelligence Engine..."
            ):

                try:

                    # Start timing
                    start_time = time.perf_counter()

                    # Send URL to FastAPI backend
                    response = requests.post(
                        API_URL,
                        json={"url": url_input},
                        timeout=30
                    )

                    # Calculate actual API response time
                    end_time = time.perf_counter()

                    latency_ms = round(
                        (end_time - start_time) * 1000,
                        2
                    )

                    response.raise_for_status()

                    data = response.json()

                    # ==================================
                    # EXTRACT PREDICTION
                    # ==================================

                    prediction = str(
                        data.get("prediction", "Unknown")
                    )

                    source = str(
                        data.get("source", "Unknown")
                    )

                    is_threat = prediction.lower() in [
                        "phishing",
                        "malicious"
                    ]

                    # ==================================
                    # ACTUAL ML RISK SCORE
                    # ==================================

                    risk_score = data.get("risk_score")

                    phishing_probability = data.get(
                        "phishing_probability"
                    )

                    if risk_score is not None:

                        risk_score = float(risk_score)

                    elif phishing_probability is not None:

                        risk_score = (
                            float(phishing_probability) * 100
                        )

                    else:

                        risk_score = None

                    if risk_score is not None:
                        risk_score = max(
                            0,
                            min(100, risk_score)
                        )

                    # ==================================
                    # SAVE AUDIT HISTORY
                    # ==================================

                    st.session_state.audit_history.insert(
                        0,
                        {
                            "url": url_input,
                            "prediction": prediction,
                            "risk_score": risk_score,
                            "source": source
                        }
                    )

                          # Keep last 20 scans
                    st.session_state.audit_history = (
                    st.session_state.audit_history[:20]
                    ) 
                    # Update sidebar immediately
                    render_audit_history()
                    # ==================================
                    # THREAT VERDICT
                    # ==================================

                    if is_threat:

                        st.markdown(
                            f"""
                            <div class="soc-card-danger">

                            <h2 style="color:#f43f5e;">
                            🚨 POTENTIAL PHISHING THREAT
                            </h2>

                            <p style="color:#fda4af;">
                            Verdict: <b>{prediction}</b>
                            </p>

                            <p style="color:#fda4af;">
                            Source: <b>{source}</b>
                            </p>

                            </div>
                            """,
                            unsafe_allow_html=True
                        )

                    else:

                        st.markdown(
                            f"""
                            <div class="soc-card">

                            <h2 style="color:#38bdf8;">
                            🛡️ NO THREAT DETECTED
                            </h2>

                            <p style="color:#7dd3fc;">
                            Verdict: <b>{prediction}</b>
                            </p>

                            <p style="color:#7dd3fc;">
                            Source: <b>{source}</b>
                            </p>

                            </div>
                            """,
                            unsafe_allow_html=True
                        )

                    st.write("")

                    # ==================================
                    # SECURITY METRICS
                    # ==================================

                    col1, col2, col3, col4 = st.columns(4)

                    with col1:

                        if risk_score is not None:

                            st.metric(
                                "Estimated Phishing Risk",
                                f"{risk_score:.2f}%"
                            )

                        else:

                            st.metric(
                                "Estimated Phishing Risk",
                                "N/A"
                            )

                    with col2:

                        st.metric(
                            "Detection Source",
                            source
                        )

                    with col3:

                        st.metric(
                            "URL Scheme",
                            parsed_url.scheme.upper()
                        )

                    with col4:

                        st.metric(
                            "API Response Time",
                            f"{latency_ms} ms"
                        )

                    # ==================================
                    # RISK VISUALIZATION
                    # ==================================

                    st.write("")

                    st.markdown("### 📊 Threat Risk Analysis")

                    if risk_score is not None:

                        st.progress(
                            int(round(risk_score))
                        )

                        if risk_score >= 80:

                            st.error(
                                "🔴 High estimated phishing risk"
                            )

                        elif risk_score >= 40:

                            st.warning(
                                "🟡 Moderate estimated phishing risk"
                            )

                        else:

                            st.success(
                                "🟢 Low estimated phishing risk"
                            )

                    else:

                        st.info(
                            "A numerical phishing risk score "
                            "was not provided by the detection engine."
                        )

                    # ==================================
                    # RAW JSON RESPONSE
                    # ==================================

                    with st.expander(
                        "🔍 View Raw JSON Telemetry Payload"
                    ):

                        st.json(data)

                except requests.exceptions.ConnectionError:

                    st.error(
                        "❌ Backend connection failed. "
                        "Make sure FastAPI is running on port 8000."
                    )

                except requests.exceptions.Timeout:

                    st.error(
                        "⚠️ API request timed out."
                    )

                except requests.exceptions.RequestException as e:

                    st.error(
                        f"API communication error: {e}"
                    )

                except (ValueError, TypeError, KeyError) as e:

                    st.error(
                        f"Invalid API response: {e}"
                    )