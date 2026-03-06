"""
ThreatIntelAgent — external threat intelligence enrichment.

Queries AbuseIPDB, VirusTotal, and Shodan for each detected threat IP,
gracefully degrading when API keys are absent.  Results are written to
state['threat_intel_context'].
"""

import logging
import time
from typing import Any, Dict, List, Optional

from .base_agent import BaseAgent

logger = logging.getLogger(__name__)

# Maximum IPs to enrich per session (API budget conservation)
_MAX_IPS_PER_SESSION = 5


class ThreatIntelAgent(BaseAgent):
    """
    Enriches detected threat IPs with external intelligence feeds.

    Data sources (all use free community tiers):
    - AbuseIPDB  — abuse confidence score, ISP, usage type
    - VirusTotal — vendor detections count
    - Shodan     — open ports, banner info

    All sources are optional; missing API keys → graceful skip.
    """

    name = "ThreatIntelAgent"
    role = "Threat Intelligence Enrichment"
    description = (
        "Queries AbuseIPDB, VirusTotal, and Shodan to enrich detected "
        "threat IPs with external reputation data."
    )

    def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        start = time.perf_counter()

        threats = state.get("detected_threats", [])
        unique_ips: List[str] = list(
            {t.get("src_ip", "") for t in threats if t.get("src_ip")}
        )[:_MAX_IPS_PER_SESSION]

        enrichments: Dict[str, Dict[str, Any]] = {}
        for ip in unique_ips:
            enrichments[ip] = self._enrich_ip(ip)

        state["threat_intel_context"] = {
            "enrichments": enrichments,
            "total_ips_checked": len(unique_ips),
            "apis_available": self._apis_available(),
        }

        duration_ms = (time.perf_counter() - start) * 1000
        session_id = state.get("session_id", "unknown")
        high_risk = sum(
            1
            for e in enrichments.values()
            if self._is_high_risk(e)
        )

        self._emit_trace(
            session_id=session_id,
            input_summary=f"unique_threat_ips={len(unique_ips)}",
            decision=f"enriched {len(enrichments)} IPs; {high_risk} flagged high-risk",
            reasoning="AbuseIPDB + VirusTotal + Shodan lookups",
            confidence=0.85 if enrichments else 0.0,
            duration_ms=duration_ms,
        )
        return state

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _enrich_ip(self, ip: str) -> Dict[str, Any]:
        return {
            "ip": ip,
            "abuseipdb": self._check_abuseipdb(ip),
            "virustotal": self._check_virustotal(ip),
            "shodan": self._check_shodan(ip),
        }

    def _check_abuseipdb(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            from config import settings  # type: ignore
            import requests  # type: ignore

            if not settings.ABUSEIPDB_API_KEY:
                return None

            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 30},
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "isp": data.get("isp", ""),
                    "usage_type": data.get("usageType", ""),
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode", ""),
                }
        except Exception as exc:
            logger.debug("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return None

    def _check_virustotal(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            from config import settings  # type: ignore
            import requests  # type: ignore

            if not settings.VIRUSTOTAL_API_KEY:
                return None

            resp = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                timeout=5,
            )
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                last_analysis = attrs.get("last_analysis_stats", {})
                return {
                    "malicious": last_analysis.get("malicious", 0),
                    "suspicious": last_analysis.get("suspicious", 0),
                    "harmless": last_analysis.get("harmless", 0),
                    "reputation": attrs.get("reputation", 0),
                    "country": attrs.get("country", ""),
                }
        except Exception as exc:
            logger.debug("VirusTotal lookup failed for %s: %s", ip, exc)
        return None

    def _check_shodan(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            from config import settings  # type: ignore
            import requests  # type: ignore

            if not settings.SHODAN_API_KEY:
                return None

            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": settings.SHODAN_API_KEY},
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "open_ports": data.get("ports", [])[:10],
                    "hostnames": data.get("hostnames", [])[:5],
                    "org": data.get("org", ""),
                    "os": data.get("os", ""),
                    "vulns": list(data.get("vulns", {}).keys())[:5],
                }
        except Exception as exc:
            logger.debug("Shodan lookup failed for %s: %s", ip, exc)
        return None

    @staticmethod
    def _is_high_risk(enrichment: Dict[str, Any]) -> bool:
        abdb = enrichment.get("abuseipdb") or {}
        vt = enrichment.get("virustotal") or {}
        return (
            abdb.get("abuse_confidence_score", 0) >= 50
            or vt.get("malicious", 0) >= 3
        )

    def _apis_available(self) -> List[str]:
        available = []
        try:
            from config import settings  # type: ignore
            if settings.ABUSEIPDB_API_KEY:
                available.append("abuseipdb")
            if settings.VIRUSTOTAL_API_KEY:
                available.append("virustotal")
            if settings.SHODAN_API_KEY:
                available.append("shodan")
        except Exception:
            pass
        return available

    def get_capabilities(self) -> List[str]:
        return ["ip_reputation", "external_threat_intel", "abuse_scoring", "vuln_tracking"]
