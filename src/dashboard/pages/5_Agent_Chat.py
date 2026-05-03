import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

import streamlit as st
from src.llm_agent.llm_client import get_llm_client
from src.dashboard.dashboard_data_loader import DashboardDataLoader

st.set_page_config(page_title="Agent Chat Integration", page_icon="💬", layout="wide")
st.title("💬 Cybersecurity Agent Chat")

st.markdown("""
Ask the agent any questions regarding the current system status, detected incidents, or general cybersecurity queries. 
The agent has access to all incidents and system states.
""")

# Provider Selection
available_providers = []
if os.getenv("GEMINI_API_KEY"):
    available_providers.append("gemini")
if os.getenv("NVIDIA_API_KEY"):
    available_providers.append("nvidia")
if os.getenv("OPENAI_API_KEY"):
    available_providers.append("openai")

if not available_providers:
    st.error("No LLM API keys found. Please set NVIDIA_API_KEY, GEMINI_API_KEY, or OPENAI_API_KEY in your .env.")
    st.stop()

col1, col2 = st.columns([1, 4])
with col1:
    selected_provider = st.selectbox("Select LLM Provider", available_providers, index=0)

try:
    if "current_provider" not in st.session_state or st.session_state.current_provider != selected_provider:
        st.session_state.current_provider = selected_provider
        llm_client = get_llm_client(force_reload=True, provider=selected_provider)
    else:
        llm_client = get_llm_client()
except Exception as e:
    st.error(f"Failed to initialize LLM: {e}")
    st.stop()

if llm_client.provider == "none" or llm_client.llm is None:
    st.error("LLM Provider is not correctly configured.")
    st.stop()

if "chat_history" not in st.session_state:
    st.session_state.chat_history = []

for msg in st.session_state.chat_history:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

user_query = st.chat_input("Ask me about the incidents or cybersecurity concepts...")

if user_query:
    st.session_state.chat_history.append({"role": "user", "content": user_query})
    with st.chat_message("user"):
        st.markdown(user_query)

    # Let's collect some context for the agent
    dl = DashboardDataLoader()
    recent_threats = dl.get_recent_threats(limit=5)
    threat_summary = "No recent threats."
    if recent_threats:
        threat_summary = "\n".join([f"Incident: {t.get('incident_id')} | Type: {t.get('attack_type')} | Severity: {t.get('severity')} | Src: {t.get('src_ip')} -> Dst: {t.get('dst_ip')} | Response Plan: {t.get('response_plan')}" for t in recent_threats])

    system_prompt = (
        "You are an expert Cybersecurity AI Agent integrated into an autonomous defense system. "
        "You have access to the latest incidents in the system. Use this context to answer user queries truthfully and concisely."
        "Always reason through the incidents. For mitigations, output proper commands and reasoning.\n"
        f"\n\nSystem Context - Recent Threats:\n{threat_summary}"
    )

    with st.chat_message("assistant"):
        with st.spinner("Thinking..."):
            try:
                # Format messages
                from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
                langchain_msgs: list = [SystemMessage(content=system_prompt)]
                for msg in st.session_state.chat_history:
                    if msg["role"] == "user":
                        langchain_msgs.append(HumanMessage(content=msg["content"]))
                    elif msg["role"] == "assistant":
                        langchain_msgs.append(AIMessage(content=msg["content"]))
                
                if llm_client.llm is not None:
                    response = llm_client.llm.invoke(langchain_msgs)
                    content = response.content
                    
                    # Some providers return a string representation of a list of dicts
                    if isinstance(content, str) and content.strip().startswith("[") and "'type': 'text'" in content:
                        try:
                            import ast
                            parsed = ast.literal_eval(content.strip())
                            if isinstance(parsed, list):
                                content = parsed
                        except Exception:
                            pass

                    if isinstance(content, list):
                        text_blocks = [blk["text"] for blk in content if isinstance(blk, dict) and "text" in blk]
                        content = "\n".join(text_blocks)
                    elif not isinstance(content, str):
                        content = str(content)
                        
                    st.markdown(content)
                    st.session_state.chat_history.append({"role": "assistant", "content": content})
                else:
                    st.error("LLM client is not correctly initialized.")
            except Exception as e:
                st.error(f"Error querying agent: {e}")
