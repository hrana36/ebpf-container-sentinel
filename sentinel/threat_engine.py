"""
sentinel/threat_engine.py
Detection engine mapping in-kernel eBPF telemetry to MITRE ATT&CK for Containers.
Detects Container Escapes (T1611), Reverse Shells (T1059), and Cryptojacking (T1496).
"""

from __future__ import annotations
import uuid
import re
from typing import List, Optional, Set
from .models import KernelEvent, EventType, SecurityAlert, AlertSeverity


class ContainerThreatEngine:
    """
    Evaluates streaming kernel events and flags adversarial tactics within container cgroups.
    """

    # T1611: Dangerous paths indicative of container escape / host namespace breakout
    ESCAPE_HOST_PATHS = [
        re.compile(r"^/var/run/docker\.sock", re.IGNORECASE),
        re.compile(r"^/run/containerd/containerd\.sock", re.IGNORECASE),
        re.compile(r"^/proc/sysrq-trigger", re.IGNORECASE),
        re.compile(r"^/dev/(?:kmem|mem|port)", re.IGNORECASE),
        re.compile(r"^/proc/kcore", re.IGNORECASE),
        re.compile(r"^/etc/shadow", re.IGNORECASE),
    ]

    # T1496: Known cryptomining process identifiers
    MINER_SIGNATURES: Set[str] = {
        "xmrig",
        "minerd",
        "kdevtmpfsi",
        "kinsing",
        "stratum",
        "cryptonight",
    }

    # Shell processes commonly used in reverse shells
    SHELL_COMMS: Set[str] = {"sh", "bash", "zsh", "dash", "python", "python3", "nc", "ncat", "perl"}

    # Suspicious reverse shell listener ports
    SUSPICIOUS_PORTS: Set[int] = {4444, 1337, 9001, 8888, 31337, 5555}

    def __init__(self):
        self.total_alerts_generated = 0

    def evaluate_event(self, event: KernelEvent) -> Optional[SecurityAlert]:
        """
        Evaluates a single kernel telemetry event and returns an alert if an attack is detected.
        """
        if not event.is_container:
            return None

        # Rule 1: Container Escape / Host Breakout Attempt (T1611)
        if event.event_type in (EventType.FILE_OPEN, EventType.PROCESS_EXEC):
            for pattern in self.ESCAPE_HOST_PATHS:
                if pattern.search(event.path):
                    return self._create_alert(
                        mitre_id="T1611",
                        technique_name="Escape to Host",
                        severity=AlertSeverity.CRITICAL,
                        message=f"Container escape attempt detected! Access to sensitive host path: {event.path}",
                        trigger_event=event,
                        evidence={"matched_path": event.path, "process": event.comm, "cgroup_id": event.cgroup_id},
                    )

        # Rule 2: Cryptomining / Resource Hijacking (T1496)
        if event.event_type == EventType.PROCESS_EXEC:
            comm_clean = event.comm.lower().strip()
            if comm_clean in self.MINER_SIGNATURES:
                return self._create_alert(
                    mitre_id="T1496",
                    technique_name="Resource Hijacking (Cryptomining)",
                    severity=AlertSeverity.HIGH,
                    message=f"Unauthorized cryptominer execution detected in container: {event.comm}",
                    trigger_event=event,
                    evidence={"binary": event.comm, "path": event.path, "cgroup_id": event.cgroup_id},
                )

        # Rule 3: Interactive Reverse Shell Outbound Connection (T1059 / T1571)
        if event.event_type == EventType.SOCKET_CONNECT:
            if event.comm.lower() in self.SHELL_COMMS and event.dport in self.SUSPICIOUS_PORTS:
                return self._create_alert(
                    mitre_id="T1059",
                    technique_name="Command and Scripting Interpreter (Reverse Shell)",
                    severity=AlertSeverity.CRITICAL,
                    message=f"Active reverse shell connection detected! Shell '{event.comm}' connected to {event.daddr}:{event.dport}",
                    trigger_event=event,
                    evidence={
                        "shell_comm": event.comm,
                        "destination_ip": event.daddr,
                        "destination_port": event.dport,
                        "cgroup_id": event.cgroup_id,
                    },
                )

        return None

    def _create_alert(
        self,
        mitre_id: str,
        technique_name: str,
        severity: AlertSeverity,
        message: str,
        trigger_event: KernelEvent,
        evidence: dict,
    ) -> SecurityAlert:
        self.total_alerts_generated += 1
        return SecurityAlert(
            alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
            mitre_technique_id=mitre_id,
            technique_name=technique_name,
            severity=severity,
            message=message,
            trigger_event=trigger_event,
            evidence=evidence,
        )
