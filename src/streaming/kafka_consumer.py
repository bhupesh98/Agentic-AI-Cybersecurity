"""
Kafka consumer — reads from 'network-flows', runs detection, publishes to
'detection-results'.  Designed to run as a standalone worker process.

Run as worker:
    python -m src.streaming.kafka_consumer

The consumer gracefully degrades (busy-wait log) when Kafka is unavailable.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

_FLOWS_TOPIC = "network-flows"
_RESULTS_TOPIC = "detection-results"
_CONSUMER_GROUP = "soc-detection-group"


class KafkaFlowConsumer:
    """Consumes network-flow events and routes them through the detection agent."""

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
                _FLOWS_TOPIC,
                bootstrap_servers=self._bootstrap.split(","),
                group_id=_CONSUMER_GROUP,
                value_deserializer=lambda b: json.loads(b.decode("utf-8")),
                auto_offset_reset="earliest",
                enable_auto_commit=True,
                consumer_timeout_ms=1000,
                session_timeout_ms=30_000,
            )
            self._producer = KafkaProducer(
                bootstrap_servers=self._bootstrap.split(","),
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            )
            self._available = True
            logger.info("KafkaConsumer ready — topic=%s group=%s", _FLOWS_TOPIC, _CONSUMER_GROUP)
        except Exception as exc:
            logger.warning("Kafka unavailable — consumer disabled: %s", exc)

    def run_forever(self) -> None:
        """Blocking event loop. Call from a dedicated thread or process."""
        if not self._available:
            logger.warning("Consumer not available; retrying in 30 s...")
            time.sleep(30)
            return

        logger.info("Consumer loop starting...")
        try:
            for message in self._consumer:  # type: ignore[union-attr]
                try:
                    self._handle(message.value)
                except Exception as exc:
                    logger.error("Error handling Kafka message: %s", exc)
        except Exception as exc:
            logger.error("Consumer loop exited: %s", exc)
        finally:
            self.close()

    def _handle(self, event: dict[str, Any]) -> None:
        flow = event.get("data", event)

        from src.agent.state_management import create_initial_state  # type: ignore
        from src.agents.detection_agent import DetectionAgent  # type: ignore

        agent = DetectionAgent()
        state = create_initial_state()
        state["network_flows"] = [flow]
        out = agent.process(state)

        result_event = {
            "event_type": "detection_result",
            "source_event": event,
            "threats": out.get("detected_threats", []),
            "candidates": out.get("threat_candidates", []),
        }
        if self._producer:
            self._producer.send(_RESULTS_TOPIC, value=result_event)
            logger.debug("Detection result published for flow from %s", flow.get("src_ip"))

    def close(self) -> None:
        if self._consumer:
            self._consumer.close()
        if self._producer:
            self._producer.close()
        self._available = False


# ── Entry-point ───────────────────────────────────────────────────────────────

def _get_servers() -> str:
    try:
        from config import settings  # type: ignore
        return settings.KAFKA_BOOTSTRAP_SERVERS or "localhost:9092"
    except Exception:
        import os
        return os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    consumer = KafkaFlowConsumer(_get_servers())
    consumer.run_forever()
