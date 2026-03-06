"""
Attack Graphs page — Plotly network graph of IP → Host → Stage + correlation chains.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

import streamlit as st
import plotly.graph_objects as go
import pandas as pd

st.set_page_config(page_title="Attack Graphs", page_icon="🕸️", layout="wide")
st.title("🕸️ Attack Graph — IP → Host → Stage")


# ---------------------------------------------------------------------------
# Load correlation data
# ---------------------------------------------------------------------------

@st.cache_data(ttl=30)
def load_chains():
    try:
        from src.correlation import IncidentCorrelationEngine  # type: ignore
        engine = IncidentCorrelationEngine()
        return engine.get_recent_chains(limit=20)
    except Exception:
        return []


@st.cache_data(ttl=30)
def load_incidents(limit: int = 200):
    try:
        from src.memory import get_memory_manager  # type: ignore
        memory = get_memory_manager()
        conn = memory._get_connection()
        rows = conn.execute(
            "SELECT src_ip, dst_ip, attack_type, severity "
            "FROM incidents ORDER BY detected_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


chains = load_chains()
incidents = load_incidents()

col_l, col_r = st.columns([3, 1])
with col_r:
    if st.button("🔄 Refresh"):
        st.cache_data.clear()
        st.rerun()

# ---------------------------------------------------------------------------
# Network graph: IP → target → attack type
# ---------------------------------------------------------------------------
st.subheader("Network Threat Graph")

if incidents:
    import plotly.express as px

    df = pd.DataFrame(incidents)
    # Build nodes + edges
    edge_x, edge_y, node_x, node_y, node_text, node_color = [], [], [], [], [], []
    node_positions: dict = {}
    idx = 0

    def get_node(label: str, x: float, y: float, color: str) -> int:
        nonlocal idx
        if label not in node_positions:
            node_positions[label] = idx
            node_x.append(x)
            node_y.append(y)
            node_text.append(label)
            node_color.append(color)
            idx += 1
        return node_positions[label]

    src_ips = df["src_ip"].dropna().unique()[:20]
    dst_ips = df["dst_ip"].dropna().unique()[:20]

    for i, ip in enumerate(src_ips):
        get_node(ip, 0.0, i / max(len(src_ips), 1), "#e74c3c")
    for i, ip in enumerate(dst_ips):
        get_node(ip, 1.0, i / max(len(dst_ips), 1), "#3498db")

    # Edges between src and dst where incident exists
    for _, row in df.head(50).iterrows():
        src = row.get("src_ip", "")
        dst = row.get("dst_ip", "")
        if src in node_positions and dst in node_positions:
            si, di = node_positions[src], node_positions[dst]
            edge_x += [node_x[si], node_x[di], None]
            edge_y += [node_y[si], node_y[di], None]

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color="#888"),
        hoverinfo="none",
        mode="lines",
    )
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        text=node_text,
        textposition="top center",
        hoverinfo="text",
        marker=dict(
            size=12,
            color=node_color,
            line=dict(width=1, color="#fff"),
        ),
    )
    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            showlegend=False,
            hovermode="closest",
            margin=dict(b=0, l=0, r=0, t=30),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=420,
            annotations=[
                dict(x=0.0, y=1.05, xref="paper", yref="paper", text="Source IPs",
                     showarrow=False, font=dict(size=13)),
                dict(x=1.0, y=1.05, xref="paper", yref="paper", text="Target IPs",
                     showarrow=False, font=dict(size=13)),
            ],
        ),
    )
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No incident data available for graph rendering.")

# ---------------------------------------------------------------------------
# Attack chains table
# ---------------------------------------------------------------------------
st.subheader("Detected Attack Chains (Correlation Engine)")

if chains:
    rows = []
    for ch in chains:
        rows.append({
            "Chain ID": ch.get("chain_id", "")[:16],
            "Campaign": ch.get("campaign_name", ""),
            "Stages": ch.get("stage_count", 0),
            "Confidence": f"{ch.get('confidence', 0):.0%}",
            "Detected": ch.get("detected_at", "")[:19],
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True)
else:
    st.info(
        "No multi-stage chains detected yet. Chains appear when ≥2 incidents "
        "originate from the same IP within 24 hours."
    )
