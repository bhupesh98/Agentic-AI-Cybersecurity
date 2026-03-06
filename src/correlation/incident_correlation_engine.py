"""
IncidentCorrelationEngine — detects multi-stage APT attack chains.

Groups incidents by source IP within a configurable time window,
maps each to a MITRE ATT&CK stage, and scores the resulting chain
for completeness and stage ordering.

Results are persisted to SQLite (data/correlations/attack_chains.db).
"""

import json
import logging
import sqlite3
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# MITRE ATT&CK stage name → canonical ordering index
STAGE_ORDER: Dict[str, int] = {
    "RECONNAISSANCE": 0,
    "INITIAL_ACCESS": 1,
    "EXECUTION": 2,
    "PERSISTENCE": 3,
    "PRIVILEGE_ESCALATION": 4,
    "DEFENSE_EVASION": 5,
    "CREDENTIAL_ACCESS": 6,
    "LATERAL_MOVEMENT": 7,
    "COLLECTION": 8,
    "COMMAND_AND_CONTROL": 9,
    "DATA_EXFILTRATION": 10,
    "IMPACT": 11,
}

# Attack-type keyword → MITRE stage
_STAGE_KEYWORD_MAP: List[tuple] = [
    (["SCAN", "RECON", "PROBE", "DISCOVERY"], "RECONNAISSANCE"),
    (["BRUTE", "AUTH", "LOGIN", "SSH", "FTP", "TELNET", "RDP_LOGIN"], "INITIAL_ACCESS"),
    (["EXEC", "SHELL", "CMD", "COMMAND_INJECTION", "RCE"], "EXECUTION"),
    (["BACKDOOR", "PERSISTENCE", "CRON", "STARTUP", "REGISTRY"], "PERSISTENCE"),
    (["PRIVILEGE", "ESCALAT", "SUDO", "ROOT", "UAC"], "PRIVILEGE_ESCALATION"),
    (["EVASION", "OBFUSC", "DISABLE_AV", "CLEAR_LOG"], "DEFENSE_EVASION"),
    (["CREDENTIAL", "PASS_HASH", "KERBEROAST", "MIMIKATZ"], "CREDENTIAL_ACCESS"),
    (["LATERAL", "PIVOT", "RDP", "SMB", "WMIC", "PSEXEC"], "LATERAL_MOVEMENT"),
    (["COLLECT", "STAGING", "SCREEN", "KEYLOG"], "COLLECTION"),
    (["C2", "C&C", "BEACON", "COMMAND_AND_CONTROL", "COVERT_CHANNEL"], "COMMAND_AND_CONTROL"),
    (["EXFIL", "DATA_THEFT", "TRANSFER", "DNS_TUNNEL"], "DATA_EXFILTRATION"),
    (["RANSOMWARE", "WIPER", "DOS", "DDOS", "DENIAL"], "IMPACT"),
]


@dataclass
class ChainStage:
    """A single stage within an attack chain."""
    stage_name: str         # MITRE ATT&CK tactic name
    incident_id: str
    timestamp: str
    evidence: str           # e.g. attack_type from the incident


@dataclass
class AttackChain:
    """A correlated sequence of incidents forming a suspected APT campaign."""
    chain_id: str
    stages: List[ChainStage] = field(default_factory=list)
    confidence: float = 0.0
    campaign_name: str = ""
    source_ips: List[str] = field(default_factory=list)
    timeline: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "confidence": self.confidence,
            "campaign_name": self.campaign_name,
            "source_ips": self.source_ips,
            "stage_count": len(self.stages),
            "stages": [
                {
                    "stage_name": s.stage_name,
                    "incident_id": s.incident_id,
                    "timestamp": s.timestamp,
                    "evidence": s.evidence,
                }
                for s in self.stages
            ],
            "timeline": self.timeline,
        }


class IncidentCorrelationEngine:
    """
    Groups incidents into ATT&CK-mapped attack chains.

    Usage:
        engine = IncidentCorrelationEngine()
        chains = engine.correlate_events(incidents, time_window_hours=24)
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_dir = Path("data/correlations")
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / "attack_chains.db")
        self.db_path = db_path
        self._init_db()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def correlate_events(
        self,
        incidents: List[Dict[str, Any]],
        time_window_hours: int = 24,
    ) -> List[AttackChain]:
        """
        Correlate a list of incident dicts into attack chains.

        Args:
            incidents: List of incident dicts with keys:
                       incident_id, src_ip, attack_type, detected_at, severity
            time_window_hours: Look-back window in hours.

        Returns:
            List of AttackChain objects (confidence > 0, multi-stage).
        """
        if not incidents:
            return []

        cutoff = datetime.utcnow() - timedelta(hours=time_window_hours)

        # Group by source IP; skip single-IP entries older than window
        by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for inc in incidents:
            src_ip = inc.get("src_ip", "unknown")
            ts_raw = inc.get("detected_at", datetime.utcnow().isoformat())
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                if ts.tzinfo is not None:
                    ts = ts.replace(tzinfo=None)
            except Exception:
                ts = datetime.utcnow()
            if ts >= cutoff:
                by_ip[src_ip].append({**inc, "_ts": ts})

        chains: List[AttackChain] = []

        for src_ip, ip_incidents in by_ip.items():
            if len(ip_incidents) < 2:
                continue  # need at least 2 events for a chain

            # Sort chronologically
            ip_incidents.sort(key=lambda i: i["_ts"])

            # Map each incident to a MITRE stage
            stages: List[ChainStage] = [
                ChainStage(
                    stage_name=self._infer_stage(inc),
                    incident_id=inc.get("incident_id", str(uuid.uuid4())[:8]),
                    timestamp=inc.get("detected_at", ""),
                    evidence=inc.get("attack_type", "unknown"),
                )
                for inc in ip_incidents
            ]

            chain = self._build_chain(src_ip, stages)
            if chain.confidence > 0:
                chains.append(chain)
                self._store_chain(chain)
                logger.info(
                    "Attack chain detected: %s  IP=%s  stages=%d  confidence=%.2f",
                    chain.chain_id,
                    src_ip,
                    len(stages),
                    chain.confidence,
                )

        return chains

    def get_recent_chains(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Return most recent attack chains from the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM attack_chains ORDER BY detected_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            conn.close()
            result = []
            for row in rows:
                d = dict(row)
                try:
                    d["stages_json"] = json.loads(d.get("chain_data", "[]"))
                except Exception:
                    pass
                result.append(d)
            return result
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_chain(
        self, src_ip: str, stages: List[ChainStage]
    ) -> AttackChain:
        """Score and assemble an AttackChain from a list of stages."""
        unique_stage_names = list({s.stage_name for s in stages})
        n_unique = len(unique_stage_names)

        # Stage ordering bonus: do the stages appear in MITRE order?
        indices = sorted(
            STAGE_ORDER.get(sn, -1) for sn in unique_stage_names
            if STAGE_ORDER.get(sn, -1) >= 0
        )
        is_ordered = indices == sorted(indices) and len(indices) >= 2

        # Confidence = 25% per unique stage + 10% for proper ordering
        confidence = min(0.95, n_unique * 0.25 + (0.10 if is_ordered else 0.0))

        stage_label = "_".join(
            sn.split("_")[0] for sn in unique_stage_names[:3]
        )

        return AttackChain(
            chain_id=f"chain-{uuid.uuid4().hex[:8]}",
            stages=stages,
            confidence=confidence,
            campaign_name=f"Campaign-{src_ip}-{stage_label}",
            source_ips=[src_ip],
            timeline=[s.timestamp for s in stages],
        )

    @staticmethod
    def _infer_stage(incident: Dict[str, Any]) -> str:
        """Map incident attack_type to MITRE ATT&CK stage."""
        attack_type = incident.get("attack_type", "").upper()
        threat_type = incident.get("threat_type", "").upper()
        combined = attack_type + " " + threat_type

        for keywords, stage_name in _STAGE_KEYWORD_MAP:
            if any(kw in combined for kw in keywords):
                return stage_name
        return "INITIAL_ACCESS"  # safe default

    def _store_chain(self, chain: AttackChain) -> None:
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                """
                INSERT OR REPLACE INTO attack_chains
                    (chain_id, source_ips, confidence, campaign_name,
                     stage_count, detected_at, chain_data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chain.chain_id,
                    json.dumps(chain.source_ips),
                    chain.confidence,
                    chain.campaign_name,
                    len(chain.stages),
                    datetime.utcnow().isoformat(),
                    json.dumps(chain.to_dict()),
                ),
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.error("Failed to store attack chain: %s", exc)

    def _init_db(self) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attack_chains (
                chain_id     TEXT PRIMARY KEY,
                source_ips   TEXT,
                confidence   REAL,
                campaign_name TEXT,
                stage_count  INTEGER,
                detected_at  TEXT,
                chain_data   TEXT
            )
            """
        )
        conn.commit()
        conn.close()
