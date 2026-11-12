"""
sentinel/models.py
Data models and schemas for the eBPF Container Sentinel userland telemetry engine.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, List
import time
import socket


class EventType(str, Enum):
    PROCESS_EXEC = "PROCESS_EXEC"
    SOCKET_CONNECT = "SOCKET_CONNECT"
    FILE_OPEN = "FILE_OPEN"
    UNKNOWN = "UNKNOWN"


class AlertSeverity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class KernelEvent:
    """Represents a raw telemetry event received from the in-kernel eBPF ring buffer."""
    event_id: str
    timestamp_ns: int
    cgroup_id: int
    pid: int
    ppid: int
    uid: int
    event_type: EventType
    comm: str
    path: str = ""
    daddr: str = ""
    dport: int = 0
    is_container: bool = True
    received_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp_ns": self.timestamp_ns,
            "cgroup_id": self.cgroup_id,
            "pid": self.pid,
            "ppid": self.ppid,
            "uid": self.uid,
            "event_type": self.event_type.value,
            "comm": self.comm,
            "path": self.path,
            "daddr": self.daddr,
            "dport": self.dport,
            "is_container": self.is_container,
        }


@dataclass
class SecurityAlert:
    """Represents a detected MITRE ATT&CK container security incident."""
    alert_id: str
    mitre_technique_id: str
    technique_name: str
    severity: AlertSeverity
    message: str
    trigger_event: KernelEvent
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "mitre_technique_id": self.mitre_technique_id,
            "technique_name": self.technique_name,
            "severity": self.severity.value,
            "message": self.message,
            "trigger_event": self.trigger_event.to_dict(),
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }
