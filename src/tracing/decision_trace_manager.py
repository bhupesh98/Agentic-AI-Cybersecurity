"""
DecisionTraceManager — persists agent decisions for auditability.

Phase 2: Multi-Agent Architecture — Feature 7 (explainable decisions).

Each agent calls trace_manager.log_entry() after making a significant
routing or response decision.  The trace is readable via:
  - get_full_trace(session_id) → List[DecisionTraceEntry]
  - format_trace_summary(session_id) → str  (for dashboard display)

Storage: SQLite at data/traces/decision_traces.db
"""

from __future__ import annotations

import sqlite3
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

_DB_PATH = Path("data/traces/decision_traces.db")


@dataclass
class DecisionTraceEntry:
    """Single decision trace record."""

    session_id: str
    agent_name: str
    input_summary: str
    decision: str
    reasoning: str
    confidence: float
    duration_ms: float
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    entry_id: Optional[int] = None  # set after DB insert

    def to_dict(self) -> dict:
        return asdict(self)


class DecisionTraceManager:
    """Collects and persists agent decision trace entries."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or _DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        logger.info(f"DecisionTraceManager initialized — DB: {self.db_path}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_entry(
        self,
        session_id: str,
        agent_name: str,
        input_summary: str,
        decision: str,
        reasoning: str,
        confidence: float,
        duration_ms: float,
    ) -> DecisionTraceEntry:
        """
        Persist one trace entry and return it.

        Args:
            session_id:    Workflow session that produced this decision.
            agent_name:    Name of the agent (e.g. "DetectionAgent").
            input_summary: Brief description of the input (e.g. "3 flows, 1 threat").
            decision:      What the agent decided (e.g. "route to LLM").
            reasoning:     Why it decided that.
            confidence:    0.0–1.0 confidence in the decision.
            duration_ms:   Wall-clock time the agent spent on this decision.

        Returns:
            The persisted DecisionTraceEntry.
        """
        entry = DecisionTraceEntry(
            session_id=session_id,
            agent_name=agent_name,
            input_summary=input_summary,
            decision=decision,
            reasoning=reasoning,
            confidence=confidence,
            duration_ms=duration_ms,
        )
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute(
                """INSERT INTO decision_traces
                   (session_id, agent_name, input_summary, decision,
                    reasoning, confidence, duration_ms, timestamp)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    entry.session_id,
                    entry.agent_name,
                    entry.input_summary,
                    entry.decision,
                    entry.reasoning,
                    entry.confidence,
                    entry.duration_ms,
                    entry.timestamp,
                ),
            )
            conn.commit()
            entry.entry_id = cur.lastrowid
            conn.close()
        except Exception as exc:
            logger.error(f"Failed to persist trace entry: {exc}")
        return entry

    def get_full_trace(self, session_id: str) -> List[DecisionTraceEntry]:
        """Return all trace entries for a given session, ordered by timestamp."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute(
                """SELECT entry_id, session_id, agent_name, input_summary,
                          decision, reasoning, confidence, duration_ms, timestamp
                   FROM decision_traces
                   WHERE session_id = ?
                   ORDER BY timestamp ASC""",
                (session_id,),
            )
            rows = cur.fetchall()
            conn.close()
            return [
                DecisionTraceEntry(
                    entry_id=r[0],
                    session_id=r[1],
                    agent_name=r[2],
                    input_summary=r[3],
                    decision=r[4],
                    reasoning=r[5],
                    confidence=r[6],
                    duration_ms=r[7],
                    timestamp=r[8],
                )
                for r in rows
            ]
        except Exception as exc:
            logger.error(f"Failed to fetch trace: {exc}")
            return []

    def get_recent_traces(self, limit: int = 50) -> List[DecisionTraceEntry]:
        """Return the most recent trace entries across all sessions."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute(
                """SELECT entry_id, session_id, agent_name, input_summary,
                          decision, reasoning, confidence, duration_ms, timestamp
                   FROM decision_traces
                   ORDER BY timestamp DESC
                   LIMIT ?""",
                (limit,),
            )
            rows = cur.fetchall()
            conn.close()
            return [
                DecisionTraceEntry(
                    entry_id=r[0],
                    session_id=r[1],
                    agent_name=r[2],
                    input_summary=r[3],
                    decision=r[4],
                    reasoning=r[5],
                    confidence=r[6],
                    duration_ms=r[7],
                    timestamp=r[8],
                )
                for r in rows
            ]
        except Exception as exc:
            logger.error(f"Failed to fetch recent traces: {exc}")
            return []

    def format_trace_summary(self, session_id: str) -> str:
        """Return a human-readable multi-line summary of the trace."""
        entries = self.get_full_trace(session_id)
        if not entries:
            return f"No trace found for session {session_id}"

        lines = [f"Decision Trace — session: {session_id}", "=" * 60]
        for e in entries:
            lines.append(
                f"[{e.timestamp}] {e.agent_name:22s} | {e.decision[:50]:50s} "
                f"| conf={e.confidence:.2f} | {e.duration_ms:.0f}ms"
            )
            if e.reasoning:
                lines.append(f"   reasoning: {e.reasoning[:120]}")
        lines.append("=" * 60)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        conn = sqlite3.connect(str(self.db_path))
        conn.execute(
            """CREATE TABLE IF NOT EXISTS decision_traces (
                entry_id      INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id    TEXT    NOT NULL,
                agent_name    TEXT    NOT NULL,
                input_summary TEXT,
                decision      TEXT,
                reasoning     TEXT,
                confidence    REAL,
                duration_ms   REAL,
                timestamp     TEXT
            )"""
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_session ON decision_traces(session_id)"
        )
        conn.commit()
        conn.close()
