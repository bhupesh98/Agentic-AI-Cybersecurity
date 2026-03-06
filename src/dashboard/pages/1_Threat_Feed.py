"""
Threat Feed page — live table of detected threats.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta

st.set_page_config(page_title="Threat Feed", page_icon="🚨", layout="wide")
st.title("🚨 Live Threat Feed")

# -- Data ------------------------------------------------------------------

@st.cache_data(ttl=10)
def load_incidents(limit: int = 50):
    try:
        from src.memory import get_memory_manager  # type: ignore
        memory = get_memory_manager()
        conn = memory._get_connection()
        rows = conn.execute(
            f"SELECT incident_id, detected_at, src_ip, attack_type, severity, "
            f"confidence_score, response_taken FROM incidents "
            f"ORDER BY detected_at DESC LIMIT {limit}"
        ).fetchall()
        conn.close()
        data = [dict(r) for r in rows]
        return data
    except Exception:
        return []


incidents = load_incidents()

# -- Controls ---------------------------------------------------------------
col_f, col_r = st.columns([4, 1])
with col_f:
    severity_filter = st.multiselect(
        "Filter Severity",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH"],
    )
with col_r:
    if st.button("🔄 Refresh"):
        st.cache_data.clear()
        st.rerun()

# -- Table ------------------------------------------------------------------
if not incidents:
    st.info("No incidents in memory yet. Run the agent to generate data.")
else:
    df = pd.DataFrame(incidents)
    column_map = {
        "detected_at": "Time",
        "src_ip": "Source IP",
        "attack_type": "Attack Type",
        "severity": "Severity",
        "confidence_score": "Confidence",
        "response_taken": "Response",
    }
    df = df.rename(columns=column_map)

    # Add Agent column (hard-coded for now — all routed through InvestigationAgent)
    df["Agent"] = "InvestigationAgent"

    # Severity filter
    if severity_filter and "Severity" in df.columns:
        df = df[df["Severity"].isin(severity_filter)]

    # Colour mapping via background_gradient workaround
    display_cols = ["Time", "Source IP", "Attack Type", "Severity", "Confidence", "Response", "Agent"]
    display_cols = [c for c in display_cols if c in df.columns]

    st.dataframe(
        df[display_cols].head(50),
        use_container_width=True,
        height=520,
    )
    st.caption(f"Showing {len(df)} incidents")

# -- Summary bar chart ------------------------------------------------------
if incidents:
    df_all = pd.DataFrame(incidents)
    if "severity" in df_all.columns:
        counts = df_all["severity"].value_counts().reset_index()
        counts.columns = ["Severity", "Count"]
        import plotly.express as px
        fig = px.bar(counts, x="Severity", y="Count",
                     color="Severity",
                     color_discrete_map={"CRITICAL": "#dc3545", "HIGH": "#fd7e14",
                                         "MEDIUM": "#ffc107", "LOW": "#6c757d"},
                     title="Incidents by Severity")
        fig.update_layout(showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
