"""
sentinel/daemon.py
Master Sentinel Daemon orchestrating in-kernel event consumption, container cgroup tracking,
and real-time threat response.
"""

from __future__ import annotations
import time
from typing import List, Dict, Any, Optional, Callable
from .models import KernelEvent, SecurityAlert
from .threat_engine import ContainerThreatEngine
from .ring_buffer_consumer import RingBufferConsumer


class SentinelDaemon:
    """
    Userland daemon managing container observability policies, ring buffer polling,
    and alert dispatch.
    """

    def __init__(
        self,
        threat_engine: Optional[ContainerThreatEngine] = None,
        ring_consumer: Optional[RingBufferConsumer] = None,
        alert_callback: Optional[Callable[[SecurityAlert], None]] = None,
    ):
        self.threat_engine = threat_engine or ContainerThreatEngine()
        self.ring_consumer = ring_consumer or RingBufferConsumer()
        self.alert_callback = alert_callback

        self.monitored_cgroups: Dict[int, str] = {}  # cgroup_id -> container_name
        self.alerts: List[SecurityAlert] = []
        self.processed_events = 0
        self.start_time = time.time()

    def enroll_container(self, cgroup_id: int, container_name: str) -> None:
        """Registers a container cgroup for in-kernel tracepoint monitoring."""
        self.monitored_cgroups[cgroup_id] = container_name

    def process_raw_kernel_event(self, raw_bytes: bytes) -> Optional[SecurityAlert]:
        """Consumes a raw ring buffer record and applies detection rules."""
        event = self.ring_consumer.parse_raw_record(raw_bytes)
        return self.process_kernel_event(event)

    def process_kernel_event(self, event: KernelEvent) -> Optional[SecurityAlert]:
        """Evaluates a decoded kernel event."""
        self.processed_events += 1
        alert = self.threat_engine.evaluate_event(event)

        if alert:
            self.alerts.append(alert)
            if self.alert_callback:
                try:
                    self.alert_callback(alert)
                except Exception:
                    pass

        return alert

    @property
    def metrics(self) -> Dict[str, Any]:
        elapsed = max(0.001, time.time() - self.start_time)
        return {
            "monitored_containers": len(self.monitored_cgroups),
            "processed_events": self.processed_events,
            "total_alerts": len(self.alerts),
            "events_per_second": round(self.processed_events / elapsed, 1),
            "mean_decode_latency_us": round(self.ring_consumer.average_decode_latency_us, 3),
        }
