"""
eBPF Container Sentinel
Low-Overhead In-Kernel Observability and Security Telemetry Engine for Containerized Workloads.
"""

from .models import (
    KernelEvent,
    SecurityAlert,
    EventType,
    AlertSeverity,
)
from .threat_engine import ContainerThreatEngine
from .ring_buffer_consumer import RingBufferConsumer
from .daemon import SentinelDaemon

__version__ = "1.0.0"
__author__ = "Md Habibur Rahaman Rana"

__all__ = [
    "KernelEvent",
    "SecurityAlert",
    "EventType",
    "AlertSeverity",
    "ContainerThreatEngine",
    "RingBufferConsumer",
    "SentinelDaemon",
]
