"""
Agent Insights page — Sankey decision flow, Autonomy Index gauge, Decision Trace log.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

import streamlit as st
import plotly.graph_objects as go
import pandas as pd

st.set_page_config(page_title="Agent Insights", page_icon="🤖", layout="wide")
st.title("🤖 Agent Insights")

# ---------------------------------------------------------------------------
# Autonomy Index
# ---------------------------------------------------------------------------
st.subheader("Agent Autonomy Index")


@st.cache_data(ttl=30)
def compute_autonomy():
    try:
        from src.metrics.autonomy_score import AutonomyScoreCalculator  # type: ignore
        from src.dashboard.dashboard_data_loader import get_data_loader  # type: ignore

        calc = AutonomyScoreCalculator()
        loader = get_data_loader()
        latest = loader.get_latest_metrics_summary()
        if latest:
            principles = {
                name.lower().replace(" & ", "_").replace("-", "_").replace(" ", "_"): data.get("score", 0.0)
                for name, data in latest.get("principles", {}).items()
            }
            scores = {
                "agent_autonomy_index": latest.get("overall_score", 0.0),
                "interpretation": "Latest persisted orchestrator metrics",
                "principles": principles,
                "session_id": latest.get("session_id", ""),
                "timestamp": latest.get("timestamp", ""),
            }
        else:
            scores = calc.get_current_scores()
        return scores, calc.get_trend_data(limit=20)
    except Exception:
        return None, []


scores, trend = compute_autonomy()

if scores:
    aai = scores.get("agent_autonomy_index", 0.0)
    interp = scores.get("interpretation", "")
    principles = scores.get("principles", {})

    col1, col2 = st.columns([1, 2])
    with col1:
        fig_gauge = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=round(aai * 100, 1),
                number={"suffix": "%"},
                title={"text": "Agent Autonomy Index"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": "#1f77b4"},
                    "steps": [
                        {"range": [0, 70], "color": "#f9c74f"},
                        {"range": [70, 85], "color": "#90be6d"},
                        {"range": [85, 100], "color": "#43aa8b"},
                    ],
                    "threshold": {
                        "line": {"color": "red", "width": 4},
                        "thickness": 0.75,
                        "value": 70,
                    },
                },
            )
        )
        fig_gauge.update_layout(height=260, margin=dict(l=10, r=10, t=30, b=10))
        st.plotly_chart(fig_gauge, width='stretch')
        st.caption(interp)

    with col2:
        # Principle bars
        labels = [p.replace("_", " ").title() for p in principles]
        values = [round(v * 100, 1) for v in principles.values()]
        import plotly.express as px

        fig_bar = px.bar(
            x=values, y=labels, orientation="h",
            labels={"x": "Score (%)", "y": "Principle"},
            color=values,
            color_continuous_scale="Blues",
            range_x=[0, 100],
            title="Principle Scores",
        )
        fig_bar.update_layout(height=260, showlegend=False,
                              margin=dict(l=10, r=10, t=40, b=10),
                              coloraxis_showscale=False)
        st.plotly_chart(fig_bar, width='stretch')

    # Trend chart
    if trend:
        df_trend = pd.DataFrame(trend)
        if "overall_agentic_score" in df_trend.columns:
            df_trend["score_pct"] = df_trend["overall_agentic_score"] * 100
            fig_trend = px.line(
                df_trend, x="timestamp", y="score_pct",
                title="Autonomy Score Trend",
                labels={"score_pct": "Score (%)", "timestamp": "Time"},
            )
            fig_trend.update_layout(height=220, margin=dict(l=10, r=10, t=40, b=10))
            st.plotly_chart(fig_trend, width='stretch')
else:
    st.info("Autonomy metrics not available yet. Run the agent pipeline first.")

st.markdown("---")

# ---------------------------------------------------------------------------
# Agent Decision Pipeline Sankey
# ---------------------------------------------------------------------------
st.subheader("Agent Decision Pipeline")


@st.cache_data(ttl=30)
def load_pipeline_counts():
    try:
        from src.metrics import get_metrics_collector  # type: ignore
        collector = get_metrics_collector()
        summary = collector.get_summary()
        tu = summary.tool_utilization
        return {
            "ML Detect": tu.ml_invocations,
            "Context": tu.ml_invocations,  # same gate
            "Memory": tu.memory_retrievals,
            "LLM Analyze": tu.llm_invocations,
            "Respond": tu.llm_invocations,  # downstream
        }
    except Exception:
        return {"ML Detect": 10, "Context": 10, "Memory": 7, "LLM Analyze": 5, "Respond": 4}


counts = load_pipeline_counts()
labels = ["Ingest", "ML Detect", "Context", "Memory", "LLM Analyze", "Respond", "END"]
# Simple left-to-right Sankey
sources = [0, 1, 2, 3, 4, 5]
targets = [1, 2, 3, 4, 5, 6]

vals = [
    counts.get("ML Detect", 1),
    counts.get("Context", 1),
    counts.get("Memory", 1),
    counts.get("LLM Analyze", 1),
    counts.get("Respond", 1),
    max(1, counts.get("Respond", 1)),
]

fig_sankey = go.Figure(
    go.Sankey(
        node=dict(
            pad=15,
            thickness=20,
            line=dict(color="black", width=0.5),
            label=labels,
            color=["#aec7e8", "#1f77b4", "#ffbb78", "#2ca02c", "#d62728", "#9467bd", "#8c564b"],
        ),
        link=dict(source=sources, target=targets, value=vals),
    )
)
fig_sankey.update_layout(title_text="Detection Pipeline Flow", height=320,
                          margin=dict(l=10, r=10, t=40, b=10))
st.plotly_chart(fig_sankey, width='stretch')

st.markdown("---")

# ---------------------------------------------------------------------------
# Decision Trace Log
# ---------------------------------------------------------------------------
st.subheader("Decision Trace Log")

session_input = st.text_input("Session ID (leave blank for recent traces)", value="")


@st.cache_data(ttl=10)
def load_traces(session_id: str, limit: int = 50):
    try:
        from src.tracing.decision_trace_manager import DecisionTraceManager  # type: ignore
        tm = DecisionTraceManager()
        if session_id.strip():
            entries = tm.get_full_trace(session_id.strip())
        else:
            entries = tm.get_recent_traces(limit=limit)
        return [
            {
                "Session": e.session_id[:12],
                "Agent": e.agent_name,
                "Decision": e.decision[:80],
                "Confidence": f"{e.confidence:.0%}",
                "Duration (ms)": f"{e.duration_ms:.0f}",
                "Time": str(e.timestamp)[:19],
            }
            for e in entries
        ]
    except Exception:
        return []


traces = load_traces(session_input)
if traces:
    st.dataframe(pd.DataFrame(traces), width='stretch', height=320)
else:
    st.info("No decision traces found. Traces are recorded during multi-agent workflow runs.")
