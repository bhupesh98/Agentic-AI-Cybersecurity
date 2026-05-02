"""
Real-Time Agentic AI Dashboard (UPDATED FOR PROJECT STRUCTURE)
===============================================================

Live monitoring dashboard for the Agentic AI Cybersecurity System.

Run from project root:
    streamlit run src/dashboard/dashboard_realtime.py --server.port 8501

Location: src/dashboard/dashboard_realtime.py

"""

# CRITICAL: Path setup MUST be done BEFORE any local imports
import sys
import time
from pathlib import Path

import streamlit as st

# Add project root to path (2 levels up from src/dashboard/)
PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Now import our dashboard modules (after path is set up)
from src.dashboard.dashboard_components import (  # noqa: E402
    render_live_counter,
    render_threat_card,
    render_principle_gauge,
    render_detection_timeline,
    render_email_log,
    render_stats_table,
    render_system_status,
    render_overall_score
)
from src.dashboard.dashboard_data_loader import DashboardDataLoader  # noqa: E402


# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="🛡️ Agentic AI Cybersecurity",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# ============================================================================
# CUSTOM CSS - CYBERPUNK THEME
# ============================================================================

st.markdown("""
<style>
    /* Main background */
    .main {
        background-color: #0E1117;
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #667eea !important;
        font-family: 'Courier New', monospace;
        text-shadow: 0 0 10px rgba(102, 126, 234, 0.5);
    }
    
    /* Metric cards */
    [data-testid="stMetricValue"] {
        font-size: 2.5rem !important;
        font-weight: bold !important;
        color: #1E88E5 !important;
    }
    
    [data-testid="stMetricLabel"] {
        font-size: 1rem !important;
        color: #AAA !important;
    }
    
    [data-testid="stMetricDelta"] {
        font-size: 1rem !important;
    }
    
    /* Dataframe styling */
    [data-testid="stDataFrame"] {
        background-color: #1E1E2E;
    }
    
    /* Buttons */
    .stButton>button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 12px 24px;
        font-weight: bold;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        transition: all 0.3s ease;
    }
    
    .stButton>button:hover {
        box-shadow: 0 6px 16px rgba(102, 126, 234, 0.4);
        transform: translateY(-2px);
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #1A1A2E;
    }
    
    /* Divider */
    hr {
        border-color: rgba(102, 126, 234, 0.3);
        margin: 32px 0;
    }
    
    /* Info boxes */
    .stAlert {
        background-color: #1E1E2E;
        border-left: 4px solid #667eea;
    }
    
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Smooth transitions */
    * {
        transition: all 0.2s ease;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================================
# AUTO-REFRESH CONFIGURATION
# ============================================================================

# Refresh every 500ms for real-time feel using native Streamlit
if "_last_refresh" not in st.session_state:
    st.session_state["_last_refresh"] = time.time()
time.sleep(0.5)
st.rerun()


# ============================================================================
# INITIALIZE DATA LOADER
# ============================================================================

@st.cache_resource
def get_data_loader():
    """Get cached data loader instance."""
    return DashboardDataLoader()


data_loader = get_data_loader()


# ============================================================================
# HEADER
# ============================================================================

st.markdown("""
<div style="text-align: center; margin-bottom: 32px;">
    <h1 style="font-size: 3rem; margin-bottom: 8px;">
        🛡️ AGENTIC AI CYBERSECURITY SYSTEM
    </h1>
    <p style="color: #888; font-size: 1.2rem;">
        Real-Time Autonomous Threat Detection & Response
    </p>
</div>
""", unsafe_allow_html=True)


# ============================================================================
# SYSTEM STATUS
# ============================================================================

# Check if system is running
live_state = data_loader.get_live_state()
is_running = live_state is not None
last_update = data_loader.get_last_update_time()

render_system_status(is_running, last_update)


# ============================================================================
# SECTION 1: LIVE METRICS (TOP - REAL-TIME)
# ============================================================================

st.markdown("---")
st.markdown("## 📊 LIVE METRICS")

if not is_running:
    st.warning(
        "⚠️ **System not running.** Start the test script to see live data:")
    st.code("sudo python3 test_complete_agentic_system.py --samples 70 --delay 1.0", language="bash")
    st.stop()

# Get live statistics
stats = data_loader.get_live_stats()
progress = data_loader.get_live_progress()

# Display in 4 columns
col1, col2, col3, col4 = st.columns(4)

with col1:
    render_live_counter(
        "🔍 Total Flows",
        stats.get('total_flows', 0),
        delta=None
    )

with col2:
    render_live_counter(
        "🚨 Threats Detected",
        stats.get('malicious_detected', 0),
        delta=None
    )

with col3:
    render_live_counter(
        "📧 Emails Sent",
        stats.get('emails_sent', 0),
        delta=None
    )

with col4:
    detection_rate = progress.get('detection_rate', 0.0)
    st.metric(
        "📈 Detection Rate",
        f"{detection_rate:.1f}%",
        delta=None
    )

# Second row of metrics
st.markdown("<br>", unsafe_allow_html=True)

col5, col6, col7, col8 = st.columns(4)

with col5:
    render_live_counter(
        "🧠 LLM Analyses",
        stats.get('llm_analyses', 0)
    )

with col6:
    render_live_counter(
        "💾 Memory Lookups",
        stats.get('memory_lookups', 0)
    )

with col7:
    render_live_counter(
        "📚 Learning Events",
        stats.get('learning_events', 0)
    )

with col8:
    render_live_counter(
        "❌ Errors",
        stats.get('errors', 0)
    )


# ============================================================================
# SECTION 2: OVERALL SCORE (PROMINENT)
# ============================================================================

st.markdown("---")
overall_score = progress.get('agentic_score', 0.0)
render_overall_score(overall_score)


# ============================================================================
# SECTION 3: LIVE THREAT FEED
# ============================================================================

st.markdown("---")
st.markdown("## 🚨 LIVE THREAT FEED")
st.markdown("*Latest detected threats (auto-refreshing)*")

# Get recent threats
recent_threats = data_loader.get_recent_threats(limit=5)

if recent_threats:
    # Display threats in a scrollable container
    for threat in recent_threats:
        render_threat_card(threat)
else:
    st.info("✅ No threats detected yet. Feed will update automatically.")


# ============================================================================
# SECTION 4: DETECTION SUMMARY
# ============================================================================

st.markdown("---")
st.markdown("## 📊 DETECTION SUMMARY")

timestamps, counts = data_loader.get_detection_timeline(minutes=10)
render_detection_timeline(timestamps, counts)


# ============================================================================
# DIVIDER - STATIC CONTENT BELOW
# ============================================================================

st.markdown("---")
st.markdown("""
<div style="text-align: center; margin: 48px 0; opacity: 0.6;">
    <p>━━━━━ DETAILED METRICS (Updated every 5 seconds) ━━━━━</p>
</div>
""", unsafe_allow_html=True)


# ============================================================================
# SECTION 5: 7 AGENTIC AI PRINCIPLES (GAUGES)
# ============================================================================

st.markdown("## 🎯 AGENTIC AI PRINCIPLES")
st.markdown(
    "*Scores calculated after test completion - check database for historical runs*")

# Get principle scores
principle_scores = data_loader.get_principle_scores()

# Display in 4 columns (first row: 4 principles)
col1, col2, col3, col4 = st.columns(4)

principles_row1 = [
    ('Self-Learning', principle_scores.get('Self-Learning', 0.0)),
    ('Contextual Awareness', principle_scores.get('Contextual Awareness', 0.0)),
    ('Goal-Directed Behavior', principle_scores.get('Goal-Directed Behavior', 0.0)),
    ('Tool Utilization', principle_scores.get('Tool Utilization', 0.0))
]

for col, (name, score) in zip([col1, col2, col3, col4], principles_row1):
    with col:
        render_principle_gauge(name, score)

# Second row: 3 principles (centered)
st.markdown("<br>", unsafe_allow_html=True)
col5, col6, col7 = st.columns(3)

principles_row2 = [
    ('Planning & Reasoning', principle_scores.get('Planning & Reasoning', 0.0)),
    ('Memory Management', principle_scores.get('Memory Management', 0.0)),
    ('Feedback Incorporation', principle_scores.get('Feedback Incorporation', 0.0))
]

for col, (name, score) in zip([col5, col6, col7], principles_row2):
    with col:
        render_principle_gauge(name, score)


# ============================================================================
# SECTION 6: DETAILED STATISTICS TABLE
# ============================================================================

st.markdown("---")
st.markdown("## 📋 DETAILED STATISTICS")

col_left, col_right = st.columns(2)

with col_left:
    st.markdown("### 🔢 Current Session Stats")
    render_stats_table(stats)

with col_right:
    st.markdown("### 📊 Progress Metrics")
    render_stats_table(progress)


# ============================================================================
# SECTION 7: EMAIL ALERT LOG
# ============================================================================

st.markdown("---")
st.markdown("## 📧 EMAIL ALERT LOG")

recent_emails = data_loader.get_recent_emails(limit=10)
render_email_log(recent_emails)


# ============================================================================
# SECTION 8: SYSTEM HEALTH & INFO
# ============================================================================

st.markdown("---")
st.markdown("## 🔧 SYSTEM INFORMATION")

health = data_loader.health_check()

col_h1, col_h2, col_h3 = st.columns(3)

with col_h1:
    status_icon = "✅" if health['dashboard_state'] else "❌"
    st.markdown(f"""
    **Dashboard State File**  
    {status_icon} {'Connected' if health['dashboard_state'] else 'Not Found'}
    """)

with col_h2:
    status_icon = "✅" if health['metrics_db'] else "❌"
    st.markdown(f"""
    **Metrics Database**  
    {status_icon} {'Connected' if health['metrics_db'] else 'Not Found'}
    """)

with col_h3:
    status_icon = "✅" if health['memory_db'] else "❌"
    st.markdown(f"""
    **Memory Database**  
    {status_icon} {'Connected' if health['memory_db'] else 'Not Found'}
    """)


# ============================================================================
# FOOTER
# ============================================================================

st.markdown("---")
st.markdown("""
<div style="text-align: center; margin-top: 48px; padding: 24px; opacity: 0.6;">
    <p style="font-size: 14px;">
        🛡️ Agentic AI Cybersecurity System | Real-Time Dashboard<br>
        Autonomous Threat Detection & Incident Response<br>
        <em>Auto-refreshing every 500ms</em>
    </p>
</div>
""", unsafe_allow_html=True)


# ============================================================================
# SIDEBAR (OPTIONAL CONTROLS)
# ============================================================================

with st.sidebar:
    st.markdown("## ⚙️ Dashboard Settings")

    st.markdown("### 🔄 Refresh Rate")
    st.info("Auto-refresh: 500ms")

    st.markdown("### 📊 Data Sources")
    st.code(f"""
Dashboard State: {health['dashboard_state']}
Metrics DB: {health['metrics_db']}
Memory DB: {health['memory_db']}
    """)

    st.markdown("### 🚀 Quick Actions")

    if st.button("🔄 Force Refresh"):
        st.rerun()

    if st.button("📥 Export Metrics"):
        st.info("Metrics are auto-exported to:\ndata/metrics/exports/")

    st.markdown("---")

    st.markdown("### 📖 Instructions")
    st.markdown("""
    **To start monitoring:**
    
    1. Run the test script:
    ```bash
    sudo python3 test_complete_agentic_system.py --samples 70
    ```
    
    2. Dashboard auto-updates every 500ms
    
    3. All metrics are saved to databases
    """)

    st.markdown("---")

    st.markdown("### 🎯 Score Legend")
    st.markdown("""
    - **≥70%**: High Quality
    - **50-70%**: Moderate Quality
    - **<50%**: Needs Improvement
    """)
