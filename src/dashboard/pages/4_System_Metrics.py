"""
System Metrics page — LLM budget, simulation mode status, memory stats, raw metrics.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

st.set_page_config(page_title="System Metrics", page_icon="📊", layout="wide")
st.title("📊 System Metrics")

if st.button("🔄 Refresh All"):
    st.cache_data.clear()
    st.rerun()

# ---------------------------------------------------------------------------
# Simulation mode banner
# ---------------------------------------------------------------------------
try:
    from src.simulation.simulation_manager import is_simulation  # type: ignore
    sim_on = is_simulation()
    if sim_on:
        st.info("🔵 **SIMULATION_MODE = True** — no real firewall or alert actions are executed.")
    else:
        st.warning("🔴 **SIMULATION_MODE = False** — real defensive actions are ACTIVE.")
except Exception:
    st.caption("Simulation status unavailable.")

# ---------------------------------------------------------------------------
# LLM Budget Status
# ---------------------------------------------------------------------------
st.subheader("LLM Budget Status")


@st.cache_data(ttl=5)
def load_budget():
    try:
        from src.llm_agent.llm_budget_manager import get_budget_manager  # type: ignore
        return get_budget_manager().get_budget_status()
    except Exception:
        return {}


budget = load_budget()
if budget:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Calls (this min)", f"{budget.get('calls_this_minute', 0)}/{budget.get('calls_budget', 0)}")
    c2.metric("Calls remaining", budget.get("calls_remaining", 0))
    c3.metric("Tokens used (min)", f"{budget.get('tokens_this_minute', 0):,}")
    c4.metric("Est. cost (USD)", f"${budget.get('total_cost_estimate_usd', 0):.4f}")

    # Gauge — calls remaining
    calls_pct = 0
    if budget.get("calls_budget", 0) > 0:
        calls_pct = budget.get("calls_remaining", 0) / budget["calls_budget"] * 100
    fig_g = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=round(calls_pct, 1),
            number={"suffix": "%"},
            title={"text": "Call Budget Remaining"},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "#2ca02c" if calls_pct > 50 else "#d62728"},
            },
        )
    )
    fig_g.update_layout(height=200, margin=dict(l=5, r=5, t=30, b=5))
    st.plotly_chart(fig_g, use_container_width=True)
else:
    st.info("LLM budget manager not yet initialised.")

st.markdown("---")

# ---------------------------------------------------------------------------
# Memory statistics
# ---------------------------------------------------------------------------
st.subheader("Memory Statistics")


@st.cache_data(ttl=15)
def load_memory_stats():
    try:
        from src.memory import get_memory_manager  # type: ignore
        m = get_memory_manager()
        s = m.get_statistics()
        return {
            "Total Incidents": s.total_incidents,
            "Unique IPs": s.total_unique_ips,
            "Patterns": s.total_patterns,
            "Critical": s.critical_incidents,
            "High": s.high_incidents,
            "Medium": s.medium_incidents,
            "Low": s.low_incidents,
            "Avg Query ms": round(s.avg_query_time_ms, 1),
        }
    except Exception:
        return {}


mem = load_memory_stats()
if mem:
    mc = st.columns(4)
    mc[0].metric("Total Incidents", mem.get("Total Incidents", 0))
    mc[1].metric("Unique IPs", mem.get("Unique IPs", 0))
    mc[2].metric("Patterns", mem.get("Patterns", 0))
    mc[3].metric("Avg Query (ms)", mem.get("Avg Query ms", 0))

    sev_data = pd.DataFrame({
        "Severity": ["Critical", "High", "Medium", "Low"],
        "Count": [mem.get("Critical", 0), mem.get("High", 0), mem.get("Medium", 0), mem.get("Low", 0)],
    })
    fig_sev = px.pie(sev_data, names="Severity", values="Count", title="Incidents by Severity",
                     color="Severity",
                     color_discrete_map={"Critical": "#dc3545", "High": "#fd7e14",
                                          "Medium": "#ffc107", "Low": "#6c757d"})
    fig_sev.update_layout(height=280, margin=dict(l=0, r=0, t=40, b=0))
    st.plotly_chart(fig_sev, use_container_width=True)

st.markdown("---")

# ---------------------------------------------------------------------------
# Agentic AI Metrics Table
# ---------------------------------------------------------------------------
st.subheader("Agentic AI Principles Summary")


@st.cache_data(ttl=30)
def load_principle_scores():
    try:
        from src.metrics.autonomy_score import AutonomyScoreCalculator  # type: ignore
        calc = AutonomyScoreCalculator()
        scores = calc.get_current_scores()
        principles = scores.get("principles", {})
        return [
            {
                "Principle": k.replace("_", " ").title(),
                "Score": f"{v:.1%}",
                "Weight": scores["principle_weights"].get(k, 1.0),
                "Status": "✅" if v >= 0.7 else ("⚠️" if v >= 0.4 else "❌"),
            }
            for k, v in principles.items()
        ]
    except Exception:
        return []


rows = load_principle_scores()
if rows:
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
else:
    st.info("Metrics not available yet.")
