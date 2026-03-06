"""
Kafka event producer — publishes raw network flow records to the 'network-flows' topic.

Usage (imperative):
    producer = get_kafka_producer()
    producer.publish_flow(flow_dict)

The producer gracefully degrades when Kafka is unavailable (logs a warning, returns False).
KAFKA_BOOTSTRAP_SERVERS env var (or settings.KAFKA_BOOTSTRAP_SERVERS) controls the broker.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_FLOWS_TOPIC = "network-flows"
_ALERTS_TOPIC = "soc-alerts"

_producer_instance: "KafkaFlowProducer | None" = None


class KafkaFlowProducer:
    """Thin wrapper around kafka-python-ng KafkaProducer."""

    def __init__(self, bootstrap_servers: str) -> None:
        self._bootstrap = bootstrap_servers
        self._producer: Any = None
        self._available = False
        self._init()

    # ── Initialisation ────────────────────────────────────────────────────────

    def _init(self) -> None:
        try:
            from kafka import KafkaProducer  # type: ignore

            self._producer = KafkaProducer(
                bootstrap_servers=self._bootstrap.split(","),
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                retries=3,
                request_timeout_ms=5000,
                connections_max_idle_ms=60_000,
            )
            self._available = True
            logger.info("KafkaProducer connected to %s", self._bootstrap)
        except Exception as exc:
            logger.warning("Kafka unavailable — producer disabled: %s", exc)
            self._available = False

    # ── Public API ────────────────────────────────────────────────────────────

    def publish_flow(self, flow: dict[str, Any]) -> bool:
        """Publish a single network flow record. Returns True on success."""
        if not self._available or self._producer is None:
            return False
        try:
            event = {
                "event_type": "network_flow",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": flow,
            }
            self._producer.send(_FLOWS_TOPIC, value=event)
            return True
        except Exception as exc:
            logger.error("Failed to publish flow: %s", exc)
            return False

    def publish_alert(self, alert: dict[str, Any]) -> bool:
        """Publish a SOC alert event to the alerts topic."""
        if not self._available or self._producer is None:
            return False
        try:
            event = {
                "event_type": "soc_alert",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": alert,
            }
            self._producer.send(_ALERTS_TOPIC, value=event)
            return True
        except Exception as exc:
            logger.error("Failed to publish alert: %s", exc)
            return False

    def flush(self) -> None:
        if self._available and self._producer:
            self._producer.flush()

    def close(self) -> None:
        if self._available and self._producer:
            self._producer.close()
            self._available = False


# ── Singleton accessor ────────────────────────────────────────────────────────

def get_kafka_producer() -> KafkaFlowProducer:
    global _producer_instance
    if _producer_instance is None:
        try:
            from config import settings  # type: ignore
            servers = settings.KAFKA_BOOTSTRAP_SERVERS or "localhost:9092"
        except Exception:
            import os
            servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
        _producer_instance = KafkaFlowProducer(servers)
    return _producer_instance
