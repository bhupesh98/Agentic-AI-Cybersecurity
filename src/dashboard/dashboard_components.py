"""
Dashboard Components - Reusable UI Widgets
===========================================

Beautiful, reusable components for the dashboard:
- Threat cards with severity coloring
- Metric gauges (circular progress)
- Live counters with animations
- Timeline charts
- Email log tables

Author: Abhinav
Date: November 2025
"""

import streamlit as st
import pandas as pd
from typing import Dict, List, Optional
from datetime import datetime


# ============================================================================
# STYLING CONSTANTS
# ============================================================================

COLORS = {
    'critical': '#FF0000',
    'high': '#FF6600',
    'medium': '#FFBB33',
    'low': '#FFC107',
    'benign': '#4CAF50',
    'primary': '#1E88E5',
    'accent': '#667eea',
    'background': '#0E1117',
    'card_bg': '#1E1E2E'
}

SEVERITY_ICONS = {
    'CRITICAL': '🔴',
    'HIGH': '🟠',
    'MEDIUM': '🟡',
    'LOW': '🟢'
}


# ============================================================================
# LIVE COUNTER COMPONENT
# ============================================================================

def render_live_counter(label: str, value: int, delta: Optional[int] = None,
                        color: str = COLORS['primary']):
    """
    Render a big animated counter.
    
    Args:
        label: Counter label
        value: Current value
        delta: Change since last update (optional)
        color: Hex color code
    """
    # Use Streamlit's metric with custom styling
    if delta is not None:
        st.metric(
            label=label,
            value=f"{value:,}",
            delta=f"+{delta}" if delta > 0 else str(delta)
        )
    else:
        st.metric(
            label=label,
            value=f"{value:,}"
        )


# ============================================================================
# THREAT CARD COMPONENT
# ============================================================================

def render_threat_card(threat: Dict):
    """
    Render a single threat detection card using Streamlit native components.
    
    Args:
        threat: Dictionary with threat information
    """
    severity = threat.get('llm_severity', 'MEDIUM').upper()
    icon = SEVERITY_ICONS.get(severity, '🟡')

    # Extract timestamp
    timestamp_str = threat.get('timestamp', '')
    try:
        if 'T' in timestamp_str:
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            time_display = dt.strftime('%H:%M:%S')
        else:
            time_display = timestamp_str
    except Exception:
        time_display = timestamp_str

    # Truncate analysis
    analysis = threat.get('llm_analysis', 'Malicious activity detected')
    if len(analysis) > 120:
        analysis = analysis[:120] + '...'

    # Use Streamlit container with custom styling
    with st.container():
        # Create colored box using columns for layout
        col1, col2 = st.columns([4, 1])

        with col1:
            st.markdown(f"**{icon} {severity} THREAT**")
        with col2:
            st.markdown(
                f"<p style='text-align: right; color: #888; font-size: 12px;'>{time_display}</p>", unsafe_allow_html=True)

        # Connection info
        st.markdown(
            f"**Source:** `{threat['src_ip']}:{threat['src_port']}` → **Dest:** `{threat['dst_ip']}:{threat['dst_port']}`")

        # Analysis
        st.markdown(f"*{analysis}*")

        # Metrics
        col_ml, col_proto, col_spacer = st.columns([1, 1, 2])
        with col_ml:
            st.metric(
                "ML Confidence", f"{threat['ml_confidence']:.1%}", label_visibility="collapsed")
        with col_proto:
            st.markdown(f"**Protocol:** {threat['protocol']}")

        # Divider
        st.markdown("---")


# ============================================================================
# PRINCIPLE GAUGE COMPONENT
# ============================================================================

def render_principle_gauge(name: str, score: float):
    """
    Render a progress indicator for an agentic principle.
    
    Args:
        name: Principle name
        score: Score from 0.0 to 1.0
    """
    # Convert to percentage
    percentage = score * 100

    # Determine color based on score
    if percentage >= 80:
        status = '🟢'
    elif percentage >= 50:
        status = '🟡'
    else:
        status = '🔴'

    # Display using Streamlit native components
    st.markdown(f"**{status} {name}**")
    st.progress(score if score > 0 else 0.01)  # Min 1% for visibility
    st.metric(
        label="Score",  # Non-empty label (required)
        value=f"{percentage:.1f}%",
        label_visibility="collapsed"  # Hide the label
    )


# ============================================================================
# DETECTION TIMELINE CHART
# ============================================================================

def render_detection_timeline(timestamps: List[str], counts: List[int]):
    """
    Display detection summary (chart removed due to dependency issues).
    
    Args:
        timestamps: List of timestamp strings
        counts: List of detection counts
    """
    if not timestamps or not counts:
        st.info("📈 Detection summary will appear here as threats are detected.")
        return

    # Show simple statistics instead of chart
    st.markdown("**Detection Summary**")

    total_detections = sum(counts)
    max_detections = max(counts) if counts else 0
    avg_detections = sum(counts) / len(counts) if counts else 0

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Detections", total_detections)
    with col2:
        st.metric("Peak Rate", f"{max_detections}/min")
    with col3:
        st.metric("Average Rate", f"{avg_detections:.1f}/min")


# ============================================================================
# EMAIL LOG TABLE
# ============================================================================

def render_email_log(emails: List[Dict]):
    """
    Render a table of sent email alerts.
    
    Args:
        emails: List of email dictionaries
    """
    if not emails:
        st.info("📧 Email log will appear here as alerts are sent.")
        return

    # Format data for table
    rows = []
    for email in emails:
        # Format timestamp
        try:
            dt = datetime.fromisoformat(
                email['timestamp'].replace('Z', '+00:00'))
            time_str = dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            time_str = email['timestamp']

        # Status icon
        status = '✅' if email['success'] else '❌'

        rows.append({
            'Time': time_str,
            'Target': email['target'],
            'Status': status,
            'Details': email['output'][:50] + '...' if len(email['output']) > 50 else email['output']
        })

    # Create styled table
    df = pd.DataFrame(rows)

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        height=300
    )


# ============================================================================
# STATS TABLE COMPONENT
# ============================================================================

def render_stats_table(stats: Dict):
    """
    Render a formatted statistics table.
    
    Args:
        stats: Dictionary of statistics
    """

    # Format stats into rows
    rows = []
    for key, value in stats.items():
        # Format key (replace underscores, capitalize)
        formatted_key = key.replace('_', ' ').title()

        # Format value
        if isinstance(value, float):
            if 0 < value < 1:
                formatted_value = f"{value:.1%}"
            else:
                formatted_value = f"{value:.2f}"
        elif isinstance(value, int):
            formatted_value = f"{value:,}"
        else:
            formatted_value = str(value)

        rows.append({'Metric': formatted_key, 'Value': formatted_value})

    df = pd.DataFrame(rows)

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        height=min(400, len(rows) * 35 + 38)
    )


# ============================================================================
# SYSTEM STATUS INDICATOR
# ============================================================================

def render_system_status(is_running: bool, last_update: str):
    """
    Render system status indicator at top of page.
    
    Args:
        is_running: Whether test is currently running
        last_update: ISO timestamp of last update
    """
    # Determine status
    if is_running:
        status_text = "🟢 LIVE"
        pulse = "animation: pulse 2s infinite;"
    else:
        status_text = "🟡 IDLE"
        pulse = ""

    # Format last update time
    try:
        dt = datetime.fromisoformat(last_update.replace('Z', '+00:00'))
        time_display = dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        time_display = last_update

    st.markdown(f"""
    <div style="
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 24px;
        text-align: center;
        box-shadow: 0 4px 12px rgba(0,0,0,0.4);
    ">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div style="font-size: 24px; font-weight: bold; color: white; {pulse}">
                {status_text}
            </div>
            <div style="color: rgba(255,255,255,0.8); font-size: 14px;">
                Last Update: {time_display}
            </div>
        </div>
    </div>
    
    <style>
    @keyframes pulse {{
        0%, 100% {{ opacity: 1; }}
        50% {{ opacity: 0.7; }}
    }}
    </style>
    """, unsafe_allow_html=True)


# ============================================================================
# OVERALL SCORE DISPLAY
# ============================================================================

def render_overall_score(score: float):
    """
    Render the overall agentic AI score prominently.
    
    Args:
        score: Overall score from 0.0 to 1.0
    """
    percentage = score * 100

    # Determine color and message
    if percentage >= 70:
        color = COLORS['benign']
        message = "High Quality"
    elif percentage >= 50:
        color = COLORS['medium']
        message = "Moderate Quality"
    else:
        color = COLORS['high']
        message = "Needs Improvement"

    st.markdown(f"""
    <div style="
        background: linear-gradient(135deg, {color}44 0%, {color}22 100%);
        border: 3px solid {color};
        border-radius: 12px;
        padding: 24px;
        text-align: center;
        margin: 24px 0;
    ">
        <div style="font-size: 48px; font-weight: bold; color: {color};">
            {percentage:.1f}%
        </div>
        <div style="font-size: 18px; color: #DDD; margin-top: 8px;">
            Overall Agentic AI Score
        </div>
        <div style="font-size: 16px; color: {color}; margin-top: 12px; font-weight: bold;">
            {message}
        </div>
        <div style="font-size: 12px; color: #888; margin-top: 12px; font-style: italic;">
            * Score from last completed test session
        </div>
    </div>
    """, unsafe_allow_html=True)
