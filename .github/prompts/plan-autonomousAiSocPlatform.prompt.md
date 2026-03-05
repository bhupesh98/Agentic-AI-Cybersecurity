# Plan: Autonomous AI SOC Platform — Feature Roadmap

## TL;DR
Transform the existing single-pipeline Agentic AI Cybersecurity system into a production-grade **Autonomous AI SOC Platform** with multi-agent architecture, cost-optimized LLM usage, threat intelligence enrichment, APT correlation, Kubernetes-native deployment, and an advanced SOC dashboard. The plan is organized into 6 implementation phases, each independently verifiable, progressing from foundational refactors → intelligence features → deployment infrastructure.

---

## Phase 1: Foundation — Config, Dependencies & Simulation Mode (Features 16, partial 9)
> *No other phase depends on this being done first, but it unblocks everything. Can start in parallel with Phase 2.*

**Steps:**

1. **Create `requirements.txt`** listing all dependencies (pandas, numpy, scikit-learn, xgboost, tensorflow, langgraph, langchain-openai, faiss-cpu, sentence-transformers, scapy, streamlit, plotly, python-dotenv, requests, matplotlib, seaborn, redis, kafka-python, aiohttp, pydantic). *parallel with step 2*

2. **Create `config/settings.py`** — centralized Pydantic `Settings` class loading from `.env`. Replace scattered `os.getenv()` calls. Fields: `OPENAI_API_KEY`, `OPENAI_MODEL`, `LLM_TEMPERATURE`, `LLM_MAX_FLOWS_PER_BATCH`, `ENABLE_METRICS`, `SIMULATION_MODE`, `SMTP_*`, `SLACK_WEBHOOK_URL`, `REDIS_URL`, `KAFKA_BOOTSTRAP_SERVERS`, `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY`, `LOG_LEVEL`, `DB_PATH`, `BUDGET_TOKENS_PER_MINUTE`, `BUDGET_MAX_LLM_CALLS_PER_MINUTE`. Export a singleton `settings` object from `config/__init__.py`. *parallel with step 1*

3. **Create `src/simulation/simulation_manager.py`** — a `SimulationMode` context manager / flag that wraps action execution. When `SIMULATION_MODE=True`: firewall manager logs "Would block IP X" instead of calling pfctl/iptables; alert manager logs "Would send email to Y" instead of SMTP; all action results are marked `simulated=True`. Wire into `ActionExecutor` via a check on `settings.SIMULATION_MODE`.

**Relevant files:**
- Create: `requirements.txt`, `config/settings.py`, `src/simulation/__init__.py`, `src/simulation/simulation_manager.py`
- Modify: `config/__init__.py` (export settings), `src/actions/action_executor.py` (check simulation flag), `src/actions/firewall_manager.py` (simulation branch), `src/actions/alert_manager.py` (simulation branch)

---

## Phase 2: Multi-Agent Architecture & Decision Trace (Features 1, 7, 12)
> *Core architectural change. Phases 3-5 build on this. This is the biggest refactor.*

**Steps:**

4. **Define `src/agents/base_agent.py`** — abstract `BaseAgent` class with interface:
   - `name: str`, `role: str`, `description: str`
   - `async process(state: AgentState) -> AgentState` (main processing)
   - `get_capabilities() -> List[str]`
   - Holds reference to `DecisionTraceManager` for logging decisions.
   - Each agent is a LangGraph node internally.

5. **Create `src/agents/detection_agent.py`** — `DetectionAgent(BaseAgent)`. Wraps existing `ml_detect_node` logic + context analysis. Owns: ML model loading, ensemble prediction, context analysis, multi-layer routing decision. Emits `DecisionTrace` entries for each routing decision. *depends on step 4*

6. **Create `src/agents/investigation_agent.py`** — `InvestigationAgent(BaseAgent)`. Combines existing `llm_analyze_node` + `memory_lookup_node` logic. Pipeline: retrieve similar incidents → check IP reputation → correlate patterns → LLM analysis → generate investigation report. Emits trace entries. *depends on step 4*

7. **Create `src/agents/threat_intel_agent.py`** — `ThreatIntelAgent(BaseAgent)`. New capability: queries external APIs (AbuseIPDB, VirusTotal, Shodan) to enrich threat context. Falls back gracefully if API keys missing. Updates IP reputation in memory. *depends on step 4, implements Feature 4*

8. **Create `src/agents/response_agent.py`** — `ResponseAgent(BaseAgent)`. Wraps existing `enhanced_respond_node` + `enhanced_execute_node` from `workflow_integration.py`. Owns: policy engine, action selection, LLM-guided playbook generation (Feature 8), action execution, verification. *depends on step 4*

9. **Create `src/agents/memory_agent.py`** — `MemoryAgent(BaseAgent)`. Wraps existing memory operations. Owns: incident storage, FAISS indexing, IP reputation updates, pattern detection, correlation creation. Called by other agents as needed. *depends on step 4*

10. **Create `src/agents/governance_agent.py`** — `GovernanceAgent(BaseAgent)`. Implements Feature 12: human override capability, risk threshold enforcement, audit logging, action approval for high-risk actions. Has configurable `risk_thresholds` dict; actions above threshold require explicit approval (in non-simulation mode, logs await-approval status). *depends on step 4*

11. **Create `src/tracing/decision_trace_manager.py`** — `DecisionTraceManager` class. Collects `DecisionTraceEntry` objects: `{agent_name, timestamp, input_summary, decision, reasoning, confidence, duration_ms}`. Provides `get_full_trace(session_id) -> List[DecisionTraceEntry]` and `format_trace_summary() -> str`. Persists to SQLite (`data/traces/decision_traces.db`). *parallel with steps 5-10*

12. **Refactor `src/agent/workflow_graph.py`** — Replace the 6 inline node functions with calls to the new agent classes. New graph:
    ```
    Ingest → DetectionAgent → ThreatIntelAgent → InvestigationAgent → GovernanceAgent → ResponseAgent → END
    ```
    MemoryAgent is called internally by Investigation and Response agents (not a graph node).
    Keep backward compatibility: `create_workflow()` still returns compiled StateGraph, `run_agent()` still works. Add `create_multi_agent_workflow()` as the new default. *depends on steps 5-10*

13. **Update `src/agent/state_management.py`** — Extend `AgentState` with new fields:
    - `threat_intel_context: Dict[str, Any]` — enrichment from ThreatIntelAgent
    - `investigation_report: Dict[str, Any]` — from InvestigationAgent
    - `decision_trace: List[Dict[str, Any]]` — accumulated trace entries
    - `governance_decisions: List[Dict[str, Any]]` — approval/override records
    - `playbook: Dict[str, Any]` — dynamic playbook from ResponseAgent
    *parallel with step 12*

**Relevant files:**
- Create: `src/agents/__init__.py`, `src/agents/base_agent.py`, `src/agents/detection_agent.py`, `src/agents/investigation_agent.py`, `src/agents/threat_intel_agent.py`, `src/agents/response_agent.py`, `src/agents/memory_agent.py`, `src/agents/governance_agent.py`, `src/tracing/__init__.py`, `src/tracing/decision_trace_manager.py`
- Modify: `src/agent/workflow_graph.py` (refactor nodes → agents), `src/agent/state_management.py` (extend AgentState)
- Reference (reuse logic from): `src/agent/workflow_graph.py` (ml_detect_node L53-L290, llm_analyze_node L308-L470, memory_lookup_node L453-L610), `src/agent/workflow_integration.py` (enhanced_respond_node, enhanced_execute_node), `src/actions/response_policies.py` (PolicyEngine.suggest_actions), `src/memory/memory_manager.py` (store_incident, find_similar_incidents, get_ip_reputation)

---

## Phase 3: LLM Optimization — Context Compression & Budget Control (Features 2, 3, 13)
> *Can start in parallel with Phase 2 steps 5-10, but step 15 integration depends on Phase 2 completion.*

**Steps:**

14. **Create `src/llm_agent/context_compression_engine.py`** — `ContextCompressionEngine` class:
    - `compress(flow: NetworkFlow, ml_prediction: MLPrediction, context_flags: List[str], memory_hits: List[Dict]) -> str`
    - Produces a structured text block (~200 tokens) instead of raw JSON (~800+ tokens):
      ```
      THREAT SUMMARY
      Source: {src_ip}:{src_port} → {dst_ip}:{dst_port} ({protocol})
      ML: {ensemble_prediction} (confidence: {confidence:.0%}, agreement: {agreement:.0%})
      Context: {comma-separated flags or "none"}
      Memory: {N similar incidents, top severity, repeat offender status}
      ```
    - Benefits: 70-80% token reduction, consistent prompt format.
    *parallel with step 15*

15. **Create `src/llm_agent/llm_budget_manager.py`** — `LLMBudgetManager` class:
    - Configurable: `token_budget_per_minute` (from settings), `max_llm_calls_per_minute`, `priority_queue`
    - `request_llm_call(priority: str, estimated_tokens: int) -> bool` — returns True if budget allows
    - Priority routing: CRITICAL → always approve, HIGH → approve if >50% budget remaining, MEDIUM → probability-based (budget_remaining/total), LOW → deny (ML+memory only)
    - Tracks: calls_this_minute, tokens_this_minute, total_cost_estimate
    - Sliding window token counter (resets each minute)
    - `get_budget_status() -> Dict` for dashboard display
    *parallel with step 14*

16. **Create `src/llm_agent/prompt_sanitizer.py`** — `PromptSanitizer` class (Feature 13):
    - `sanitize(user_content: str) -> str` — strips/escapes potential prompt injection patterns
    - Checks for: hidden instructions ("ignore previous", "system:"), markdown injection, encoded commands, role-play attempts
    - Applied to all flow data before it enters LLM prompts (network payloads, flow IDs, any external string)
    - Logs warnings when injection attempts detected
    *parallel with steps 14-15*

17. **Integrate compression + budget + sanitizer into LLM pipeline**:
    - Modify `src/llm_agent/llm_client.py`: `analyze_threat()` calls `ContextCompressionEngine.compress()` to build the user prompt (instead of `_build_threat_analysis_prompt`), passes through `PromptSanitizer.sanitize()`, checks `LLMBudgetManager.request_llm_call()` before invoking LLM.
    - Modify `InvestigationAgent` (from Phase 2) to use compression engine.
    *depends on steps 14-16 and step 6*

**Relevant files:**
- Create: `src/llm_agent/context_compression_engine.py`, `src/llm_agent/llm_budget_manager.py`, `src/llm_agent/prompt_sanitizer.py`
- Modify: `src/llm_agent/llm_client.py` (integrate compression, budget, sanitizer into `analyze_threat()`)
- Reference: `src/llm_agent/llm_client.py` (`_build_threat_analysis_prompt` at L246 — replace with compressed version)

---

## Phase 4: Intelligence Features — APT Correlation & Playbooks (Features 5, 6, 8)
> *Depends on Phase 2 (agents exist). Can run in parallel with Phase 3.*

**Steps:**

18. **Create `src/correlation/incident_correlation_engine.py`** — `IncidentCorrelationEngine` class:
    - `correlate_events(incidents: List[IncidentRecord], time_window_hours: int = 24) -> List[AttackChain]`
    - `AttackChain` dataclass: `{chain_id, stages: List[ChainStage], confidence, campaign_name, source_ips, timeline}`
    - `ChainStage`: `{stage_name (MITRE ATT&CK), incident_id, timestamp, evidence}`
    - Detection logic: groups incidents by source IP within time window → orders by MITRE ATT&CK stage → scores chain completeness
    - References existing MITRE stages from `src/network/apt_test_framework.py` `APTStage` enum
    - Stores detected chains in SQLite (`data/correlations/attack_chains.db`)
    *parallel with step 19*

19. **Create `src/agents/playbook_generator.py`** — `PlaybookGenerator` class:
    - `generate_playbook(threat_context: ThreatContext, investigation_report: Dict, attack_chain: Optional[AttackChain]) -> Playbook`
    - `Playbook` dataclass: `{playbook_id, title, steps: List[PlaybookStep], severity, estimated_duration, auto_executable_steps}`
    - `PlaybookStep`: `{step_number, action, target, description, is_automated, requires_approval}`
    - Two modes: (a) rule-based from existing `ResponsePolicy` templates, (b) LLM-generated for novel threats (uses compressed context)
    - Wire into `ResponseAgent` — replaces static policy actions with dynamic playbook
    *parallel with step 18*

20. **Enhance `InvestigationAgent`** — add automated investigation pipeline:
    - On threat detection: retrieve similar incidents (FAISS) → check IP reputation → query ThreatIntelAgent for external enrichment → correlate via IncidentCorrelationEngine → generate structured investigation report
    - Report format: `{threat_type, confidence, evidence: [], attack_chain: Optional, recommendation, risk_score}`
    *depends on steps 7, 18*

**Relevant files:**
- Create: `src/correlation/__init__.py`, `src/correlation/incident_correlation_engine.py`, `src/agents/playbook_generator.py`
- Modify: `src/agents/investigation_agent.py` (add correlation + investigation pipeline), `src/agents/response_agent.py` (use playbook generator)
- Reference: `src/network/apt_test_framework.py` (APTStage enum, APTStageDefinition), `src/memory/memory_manager.py` (find_similar_incidents, get_ip_reputation), `src/actions/response_policies.py` (PolicyEngine, ThreatContext)

---

## Phase 5: SOC Dashboard & Metrics (Features 11, 15)
> *Can start after Phase 2 (needs agent trace data). Dashboard work is independent of Phases 3-4.*

**Steps:**

21. **Create `src/metrics/autonomy_score.py`** — `AutonomyScoreCalculator` class:
    - Wraps existing `AgenticAIMetricsSummary.calculate_overall_agentic_score()`
    - Exposes individual principle scores as a structured dict for dashboard consumption
    - Adds: `agent_autonomy_index` (weighted composite), `trend_data` (score over time from stored snapshots)
    *parallel with step 22*

22. **Upgrade dashboard** — Modify `src/dashboard/live_dashboard.py`:
    - **Live Threat Feed panel**: table with columns [Time, Source IP, Attack Type, Severity, Confidence, Response, Agent]
    - **Attack Graph panel**: Plotly network graph (IP → Host → Attack Stage) using correlation engine data
    - **Agent Decision Graph panel**: Sankey/flow diagram showing ML → Context → Memory → LLM → Response pipeline with counts at each stage
    - **Agent Autonomy Index panel**: gauge chart + trend line for the 7 principle scores
    - **Budget Status panel**: LLM token usage, calls remaining, cost estimate
    - **Decision Trace panel**: expandable trace log per session
    - Add new Streamlit pages (multi-page app): "Threat Feed", "Attack Graphs", "Agent Insights", "System Metrics"
    *parallel with step 21*

**Relevant files:**
- Create: `src/metrics/autonomy_score.py`
- Modify: `src/dashboard/live_dashboard.py` (major upgrade — add 6 new panels, convert to multi-page Streamlit app)
- Reference: `src/metrics/models.py` (all 7 principle dataclasses), `src/tracing/decision_trace_manager.py` (trace data), `src/correlation/incident_correlation_engine.py` (attack chain data), `src/llm_agent/llm_budget_manager.py` (budget status)

---

## Phase 6: Kubernetes-Native Deployment (Feature 9, 10, 14)
> *Depends on all prior phases being functionally complete. This is packaging & infrastructure.*

**Steps:**

23. **Create `Dockerfile`** at project root — multi-stage build:
    - Stage 1: Python 3.11-slim base, install requirements.txt
    - Stage 2: Copy src/, config/, models/ (but NOT datasets/ — mount at runtime)
    - Entrypoint configurable via ENV: `SERVICE_TYPE` = `orchestrator|ml-detection|llm-reasoning|memory|response|dashboard|metrics|packet-capture`
    - Each service type runs a different main module
    *parallel with steps 24-26*

24. **Create `src/api/` — FastAPI service layer**:
    - `src/api/app.py` — FastAPI app with health/readiness endpoints
    - `src/api/routes/detection.py` — POST `/detect` (accepts flow data, returns predictions)
    - `src/api/routes/analyze.py` — POST `/analyze` (LLM analysis)
    - `src/api/routes/memory.py` — GET/POST `/incidents`, `/reputation/{ip}`
    - `src/api/routes/actions.py` — POST `/respond` (trigger response)
    - `src/api/routes/metrics.py` — GET `/metrics`, `/health`, `/ready`
    - `src/api/routes/dashboard.py` — GET `/dashboard/data` (JSON feed for dashboard)
    - Services communicate via HTTP internally in K8s, or direct imports in monolith mode
    *parallel with step 23*

25. **Create `k8s/` directory** with Kubernetes manifests:
    - `k8s/namespace.yaml` — `agentic-cybersecurity` namespace
    - `k8s/deployments/` — one Deployment per service (8 services)
    - `k8s/services/` — ClusterIP Services for internal communication
    - `k8s/configmap.yaml` — non-secret config
    - `k8s/secret.yaml` — template for API keys
    - `k8s/hpa.yaml` — HorizontalPodAutoscaler for ml-detection and llm-reasoning
    - `k8s/ingress.yaml` — Ingress for dashboard
    - Each deployment has: resource limits/requests, liveness/readiness probes hitting `/health` and `/ready`, rolling update strategy
    *parallel with steps 23-24*

26. **Create `docker-compose.yml`** — for local development:
    - Services: orchestrator, ml-detection, llm-reasoning, memory (with SQLite volume), response, dashboard, redis (for hot memory cache)
    - Shared `.env` file
    - Volume mounts for models/ and data/
    *parallel with steps 23-25*

27. **Implement tiered memory** (Feature 14):
    - Add Redis as hot cache in `src/memory/memory_manager.py`: recent incidents (last 1 hour) and IP reputation cached in Redis with TTL
    - SQLite + FAISS remain as cold storage
    - `MemoryManager` checks Redis first → falls back to SQLite
    - Redis is optional (graceful fallback if REDIS_URL not set)
    *depends on step 26 for Redis availability*

28. **Implement streaming pipeline** (Feature 10) — optional, for Kafka-based deployment:
    - Create `src/streaming/kafka_producer.py` — captures network flows, publishes to `network-flows` topic
    - Create `src/streaming/kafka_consumer.py` — ML detection workers consume from `network-flows`, publish results to `detection-results`
    - Create `src/streaming/event_router.py` — routes detection results to appropriate agents
    - Kafka is optional — system works without it via direct function calls
    *depends on step 24*

**Relevant files:**
- Create: `Dockerfile`, `docker-compose.yml`, `k8s/` (directory tree), `src/api/__init__.py`, `src/api/app.py`, `src/api/routes/*.py`, `src/streaming/__init__.py`, `src/streaming/kafka_producer.py`, `src/streaming/kafka_consumer.py`, `src/streaming/event_router.py`
- Modify: `src/memory/memory_manager.py` (add Redis hot cache layer)
- Reference: `src/agent/workflow_graph.py` (create_workflow for monolith mode), all agent classes (for service-mode execution)

---

## Verification

1. **Phase 1**: Run `python -c "from config import settings; print(settings.SIMULATION_MODE)"` → prints True. Run existing `test_complete_response.py` with `SIMULATION_MODE=True` → actions log "Would block" instead of executing.
2. **Phase 2**: Run `python -c "from src.agents import DetectionAgent, InvestigationAgent, ThreatIntelAgent, ResponseAgent, GovernanceAgent"` → no import errors. Run refactored `create_multi_agent_workflow()` with existing APT test → same detection results + decision trace populated.
3. **Phase 3**: Compare token count of compressed vs uncompressed prompt for same flow → verify ≥60% reduction. Run budget manager with limit=5 calls/min → 6th call returns `False`. Run sanitizer on `"ignore previous instructions"` → returns sanitized string with warning logged.
4. **Phase 4**: Run correlation engine on APT28 scenario incidents → detects multi-stage chain. Run playbook generator for SSH brute force → returns structured playbook with ≥3 steps.
5. **Phase 5**: Run `streamlit run src/dashboard/live_dashboard.py` → see new panels (Threat Feed, Attack Graph, Agent Decision Graph, Autonomy Index).
6. **Phase 6**: `docker-compose up` → all services start, health checks pass. `curl localhost:8000/health` → 200 OK. Run detection via API: `curl -X POST localhost:8000/detect -d '{"flows": [...]}'` → returns predictions.

---

## Decisions

- **LangGraph retained** as orchestration framework — agents are LangGraph nodes, not independent microprocesses. This keeps the proven state-passing pattern while adding specialization.
- **Multi-agent is a refactor, not a rewrite** — each agent wraps existing node logic. No functionality is lost.
- **Kafka/Redis are optional** — system works in monolith mode without them, scaling to distributed only when deployed on K8s.
- **ThreatIntelAgent uses free API tiers** — AbuseIPDB (1000 checks/day free), VirusTotal (500 lookups/day free), Shodan (community API).
- **Simulation mode is the default** for local testing — no sudo required, no firewall changes.
- **FastAPI is the service boundary** for K8s, but the system also works as a single-process Python application (monolith mode).
- **Excluded**: Real model retraining pipeline (out of scope for semester project), SMS alerting via Twilio (cost), custom ML model architecture changes.

---

## Further Considerations

1. **Testing strategy**: Should we create a proper `pytest` test suite under `tests/` mirroring the module structure, or continue with the root-level test scripts? Recommendation: migrate to pytest with fixtures for memory/metrics cleanup between tests.
2. **LLM provider flexibility**: Currently hardcoded to OpenAI. Consider abstracting to support local models (Ollama/vLLM) for K8s deployment where you control the infra. This would eliminate API costs entirely.
3. **Dataset size for K8s demo**: The CSV datasets are large (>100MB). For K8s demo, consider a pre-processed subset or synthetic data generator that produces flows on-demand rather than mounting full datasets.
