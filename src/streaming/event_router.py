"""
Event router — consumes detection results from 'detection-results' topic and
dispatches each detected threat to the appropriate downstream agent (investigation,
threat-intel, governance, response) via further Kafka topics or direct in-process calls.

This component runs as a single-threaded event loop worker.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

_IN_TOPIC = "detection-results"
_INVESTIGATE_TOPIC = "investigation-queue"
_RESPONSE_TOPIC = "response-queue"
_CONSUMER_GROUP = "soc-router-group"

# Route thresholds
_MIN_CONFIDENCE_FOR_INVESTIGATION = 0.3
_MIN_CONFIDENCE_FOR_RESPONSE = 0.7


class EventRouter:
    """Reads detection results and routes threats to downstream topics."""

    def __init__(self, bootstrap_servers: str) -> None:
        self._bootstrap = bootstrap_servers
        self._consumer: Any = None
        self._producer: Any = None
        self._available = False
        self._init()

    def _init(self) -> None:
        try:
            from kafka import KafkaConsumer, KafkaProducer  # type: ignore

            self._consumer = KafkaConsumer(
                _IN_TOPIC,
                bootstrap_servers=self._bootstrap.split(","),
                group_id=_CONSUMER_GROUP,
                value_deserializer=lambda b: json.loads(b.decode("utf-8")),
                auto_offset_reset="latest",
                enable_auto_commit=True,
                consumer_timeout_ms=1000,
            )
            self._producer = KafkaProducer(
                bootstrap_servers=self._bootstrap.split(","),
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            )
            self._available = True
            logger.info("EventRouter connected — consuming %s", _IN_TOPIC)
        except Exception as exc:
            logger.warning("Kafka unavailable — event router disabled: %s", exc)

    def run_forever(self) -> None:
        if not self._available:
            time.sleep(30)
            return

        logger.info("EventRouter loop starting...")
        try:
            for message in self._consumer:  # type: ignore[union-attr]
                try:
                    self._route(message.value)
                except Exception as exc:
                    logger.error("Routing error: %s", exc)
        except Exception as exc:
            logger.error("EventRouter loop exited: %s", exc)
        finally:
            self.close()

    def _route(self, event: dict[str, Any]) -> None:
        threats: list[dict[str, Any]] = event.get("threats", [])
        if not threats:
            return

        for threat in threats:
            confidence = float(threat.get("confidence", threat.get("ml_score", 0.0)))
            payload = {"threat": threat, "source_event": event}

            # Always send to investigation if confidence exceeds minimum
            if confidence >= _MIN_CONFIDENCE_FOR_INVESTIGATION and self._producer:
                self._producer.send(_INVESTIGATE_TOPIC, value=payload)
                logger.debug("Routed threat (conf=%.2f) → investigation", confidence)

            # Only trigger response for high-confidence threats
            if confidence >= _MIN_CONFIDENCE_FOR_RESPONSE and self._producer:
                self._producer.send(_RESPONSE_TOPIC, value=payload)
                logger.debug("Routed threat (conf=%.2f) → response", confidence)

    def close(self) -> None:
        if self._consumer:
            self._consumer.close()
        if self._producer:
            self._producer.flush()
            self._producer.close()
        self._available = False


# ── Entry-point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os
    logging.basicConfig(level=logging.INFO)
    try:
        from config import settings  # type: ignore
        servers = settings.KAFKA_BOOTSTRAP_SERVERS or "localhost:9092"
    except Exception:
        servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    router = EventRouter(servers)
    router.run_forever()
