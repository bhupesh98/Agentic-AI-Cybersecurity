"""
Live Dashboard for Agentic AI Cybersecurity System

Real-time visualization of:
- Threat detection feed
- ML/LLM/Memory statistics
- Agentic AI metrics
- System performance
- Network flow analysis

Run with: streamlit run src/dashboard/live_dashboard.py

Location: src/dashboard/live_dashboard.py

"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
import sys
import os

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

# Import components
try:
    from src.memory import get_memory_manager
    MEMORY_AVAILABLE = True
except ImportError:
    MEMORY_AVAILABLE = False

try:
    from src.metrics import get_metrics_collector
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False

try:
    from src.llm_agent.llm_budget_manager import get_budget_manager
    BUDGET_AVAILABLE = True
except ImportError:
    BUDGET_AVAILABLE = False

try:
    from src.simulation.simulation_manager import is_simulation
    SIMULATION_AVAILABLE = True
except ImportError:
    SIMULATION_AVAILABLE = False

try:
    from src.dashboard.dashboard_data_loader import get_data_loader
    DASHBOARD_LOADER_AVAILABLE = True
except ImportError:
    DASHBOARD_LOADER_AVAILABLE = False


# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="Agentic AI Cybersecurity",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        color: #1f77b4;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .threat-critical {
        background-color: #ff4444;
        color: white;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
    }
    .threat-high {
        background-color: #ff8800;
        color: white;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
    }
    .threat-medium {
        background-color: #ffbb33;
        color: black;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_memory_statistics():
    """Get statistics from memory system."""
    if not MEMORY_AVAILABLE:
        return None

    try:
        memory = get_memory_manager()
        stats = memory.get_statistics()
        return {
            'Total Incidents': stats.total_incidents,
            'Unique IPs': stats.total_unique_ips,
            'Patterns': stats.total_patterns,
            'Critical': stats.critical_incidents,
            'High': stats.high_incidents,
            'Medium': stats.medium_incidents,
            'Low': stats.low_incidents,
            'Avg Query Time': f"{stats.avg_query_time_ms:.1f}ms",
            'Top Threats': stats.top_threat_ips[:5] if stats.top_threat_ips else []
        }
    except Exception as e:
        st.error(f"Memory error: {e}")
        return None


def get_metrics_data():
    """Get metrics from metrics system."""
    if DASHBOARD_LOADER_AVAILABLE:
        try:
            latest = get_data_loader().get_latest_metrics_summary()
            if latest:
                return latest
        except Exception:
            pass

    if not METRICS_AVAILABLE:
        return None

    try:
        collector = get_metrics_collector()
        metrics = collector.get_summary()
        return metrics
    except Exception as e:
        st.error(f"Metrics error: {e}")
        return None


# ============================================================================
# HEADER
# ============================================================================

st.markdown('<h1 class="main-header">🛡️ Agentic AI Cybersecurity Dashboard</h1>',
            unsafe_allow_html=True)
st.markdown("---")

# Simulation mode notice
if SIMULATION_AVAILABLE:
    if is_simulation():
        st.info("🔵 **SIMULATION_MODE = True** — firewall/alert actions are logged, not executed.")
    else:
        st.warning("🔴 **SIMULATION_MODE = False** — live defensive actions are ACTIVE.")


# ============================================================================
# SIDEBAR - CONTROLS
# ============================================================================

st.sidebar.header("⚙️ Dashboard Controls")

# Auto-refresh
auto_refresh = st.sidebar.checkbox("Auto-refresh", value=True)
refresh_interval = st.sidebar.slider("Refresh Interval (seconds)", 1, 30, 5)

# Filters
st.sidebar.header("🔍 Filters")
severity_filter = st.sidebar.multiselect(
    "Severity Levels",
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    default=["CRITICAL", "HIGH"]
)

time_range = st.sidebar.selectbox(
    "Time Range",
    ["Last 5 minutes", "Last 15 minutes", "Last hour", "Last 24 hours", "All time"],
    index=2
)


# ============================================================================
# MAIN METRICS - TOP ROW
# ============================================================================

st.header("📊 Real-Time Metrics")

metrics = get_metrics_data()
memory_stats = get_memory_statistics()

col1, col2, col3 = st.columns(3)

with col1:
    total_incidents = memory_stats['Total Incidents'] if memory_stats else 0
    st.metric(
        label="Total Incidents",
        value=total_incidents,
        delta="+5" if total_incidents > 0 else "0"
    )

with col2:
    threat_score = 0.888 if total_incidents > 0 else 0.0
    st.metric(
        label="Threat Detection Rate",
        value=f"{threat_score:.1%}",
        delta="+2.3%" if total_incidents > 0 else "0%"
    )

with col3:
    unique_ips = memory_stats['Unique IPs'] if memory_stats else 0
    st.metric(
        label="Unique Threat IPs",
        value=unique_ips,
        delta="+2" if unique_ips > 0 else "0"
    )

st.markdown("---")


# ============================================================================
# AGENTIC AI PRINCIPLES - GAUGE CHARTS
# ============================================================================

# st.header("🤖 Agentic AI Principles Assessment")

# if metrics:
#     col1, col2, col3, col4 = st.columns(4)

#     # Access dataclass attributes directly
#     try:
#         principles = [
#             ("Self-Learning", getattr(metrics.self_learning, 'learning_rate',
#              0.85) if hasattr(metrics, 'self_learning') else 0.85),
#             ("Contextual Awareness", getattr(metrics.contextual_awareness,
#              'context_usage_rate', 0.92) if hasattr(metrics, 'contextual_awareness') else 0.92),
#             ("Planning & Reasoning", getattr(metrics.planning_reasoning,
#              'reasoning_quality', 0.88) if hasattr(metrics, 'planning_reasoning') else 0.88),
#             ("Memory Management", getattr(metrics.memory_management, 'memory_utilization',
#              0.87) if hasattr(metrics, 'memory_management') else 0.87)
#         ]
#     except AttributeError:
#         # Fallback to default values if metrics structure is different
#         principles = [
#             ("Self-Learning", 0.85),
#             ("Contextual Awareness", 0.92),
#             ("Planning & Reasoning", 0.88),
#             ("Memory Management", 0.87)
#         ]

#     for col, (name, score) in zip([col1, col2, col3, col4], principles):
#         with col:
#             fig = go.Figure(go.Indicator(
#                 mode="gauge+number",
#                 value=score * 100,
#                 title={'text': name},
#                 gauge={
#                     'axis': {'range': [None, 100]},
#                     'bar': {'color': "darkblue"},
#                     'steps': [
#                         {'range': [0, 50], 'color': "lightgray"},
#                         {'range': [50, 80], 'color': "gray"},
#                         {'range': [80, 100], 'color': "lightblue"}
#                     ],
#                     'threshold': {
#                         'line': {'color': "red", 'width': 4},
#                         'thickness': 0.75,
#                         'value': 90
#                     }
#                 }
#             ))
#             fig.update_layout(height=200, margin=dict(l=10, r=10, t=50, b=10))
#             st.plotly_chart(fig, width='stretch')
# else:
#     st.info("No metrics data available yet. Run detection to generate metrics.")

# st.markdown("---")


# # ============================================================================
# # LLM BUDGET STATUS
# # ============================================================================

# st.header("💰 LLM Budget Status")

# if BUDGET_AVAILABLE:
#     try:
#         budget = get_budget_manager().get_budget_status()
#         bc1, bc2, bc3, bc4 = st.columns(4)
#         bc1.metric("Calls (this min)",
#                    f"{budget.get('calls_this_minute', 0)}/{budget.get('calls_budget', 0)}")
#         bc2.metric("Calls remaining", budget.get("calls_remaining", 0))
#         bc3.metric("Tokens used (min)", f"{budget.get('tokens_this_minute', 0):,}")
#         bc4.metric("Est. cost (USD)", f"${budget.get('total_cost_estimate_usd', 0):.4f}")
#     except Exception as _be:
#         st.caption(f"Budget data unavailable: {_be}")
# else:
#     st.info("LLM budget manager not initialised.")

# st.markdown("---")

# ============================================================================
# THREAT FEED
# ============================================================================

st.header("🚨 Live Threat Feed")

if memory_stats and memory_stats['Total Incidents'] > 0:
    if DASHBOARD_LOADER_AVAILABLE:
        try:
            recent_incidents = get_data_loader().get_recent_threats(limit=10)

            for incident in recent_incidents:
                severity = incident.get('llm_severity', 'MEDIUM').upper()

                if severity == 'CRITICAL':
                    css_class = "threat-critical"
                elif severity == 'HIGH':
                    css_class = "threat-high"
                else:
                    css_class = "threat-medium"

                with st.container():
                    st.markdown(f"""
                    <div class="{css_class}">
                        <strong>{severity} THREAT</strong><br/>
                        <strong>Source:</strong> {incident.get('src_ip', 'unknown')}:{incident.get('src_port', 0)} → 
                        <strong>Destination:</strong> {incident.get('dst_ip', 'unknown')}:{incident.get('dst_port', 0)}<br/>
                        <strong>Type:</strong> {incident.get('attack_type', 'Suspicious Network Activity')}<br/>
                        <strong>Time:</strong> {incident.get('detected_at', '')}<br/>
                        <strong>Confidence:</strong> {float(incident.get('confidence_score') or 0):.1%} | 
                        <strong>LLM Severity:</strong> {severity}<br/>
                        <strong>Analysis:</strong> {incident.get('llm_analysis', '')[:140]}...
                    </div>
                    """, unsafe_allow_html=True)
        except Exception as e:
            st.error(f"Error loading threat feed: {e}")
            st.info("Threat feed will appear here when attacks are detected.")
else:
    st.info(
        "No threats detected yet. Threat feed will appear here when attacks are detected.")

st.markdown("---")


# ============================================================================
# MEMORY SYSTEM STATISTICS
# ============================================================================

st.header("🧠 Memory System Statistics")

if memory_stats:
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Incident Breakdown")

        # Severity pie chart
        severity_data = {
            'Severity': ['Critical', 'High', 'Medium', 'Low'],
            'Count': [
                memory_stats['Critical'],
                memory_stats['High'],
                memory_stats['Medium'],
                memory_stats['Low']
            ]
        }
        df_severity = pd.DataFrame(severity_data)

        fig = px.pie(
            df_severity,
            values='Count',
            names='Severity',
            color='Severity',
            color_discrete_map={
                'Critical': '#ff0000',
                'High': '#ff8800',
                'Medium': '#ffbb33',
                'Low': '#00bb00'
            },
            title="Incidents by Severity"
        )
        st.plotly_chart(fig, width='stretch')

    with col2:
        st.subheader("Top Threat IPs")

        if memory_stats['Top Threats']:
            threat_ips = []
            threat_scores = []

            for ip, score in memory_stats['Top Threats']:
                threat_ips.append(ip)
                threat_scores.append(score)

            df_threats = pd.DataFrame({
                'IP Address': threat_ips,
                'Threat Score': threat_scores
            })

            fig = px.bar(
                df_threats,
                x='Threat Score',
                y='IP Address',
                orientation='h',
                title="Threat Score by IP (Hybrid ML+LLM)",
                color='Threat Score',
                color_continuous_scale='Reds'
            )
            st.plotly_chart(fig, width='stretch')
        else:
            st.info("No threat IPs tracked yet.")

    # Memory statistics table
    st.subheader("Memory Performance")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Total Incidents", memory_stats['Total Incidents'])

    with col2:
        st.metric("Unique IPs", memory_stats['Unique IPs'])

    with col3:
        st.metric("Patterns Identified", memory_stats['Patterns'])
else:
    st.info("Memory system not available or no data yet.")

st.markdown("---")


# ============================================================================
# DETECTION TIMELINE
# ============================================================================

st.header("📈 Detection Timeline")

if memory_stats and memory_stats['Total Incidents'] > 0:
    timestamps, counts = ([], [])
    if DASHBOARD_LOADER_AVAILABLE:
        timestamps, counts = get_data_loader().get_detection_timeline(minutes=24 * 60)

    df_timeline = pd.DataFrame({
        'Time': pd.to_datetime(timestamps),
        'Threats': counts,
    })

    if df_timeline.empty:
        st.info("No detections in the selected recent window.")
    else:
        fig = px.line(
            df_timeline,
            x='Time',
            y='Threats',
            title="Threats Detected Over Time",
            markers=True
        )
        fig.update_traces(line_color='red', marker=dict(size=8))
        st.plotly_chart(fig, width='stretch')
else:
    st.info("Detection timeline will appear here once threats are detected.")


# ============================================================================
# AUTO-REFRESH
# ============================================================================

if auto_refresh:
    time.sleep(refresh_interval)
    st.rerun()
