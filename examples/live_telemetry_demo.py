"""
examples/live_telemetry_demo.py
Demonstration of eBPF Container Sentinel:
Enrolling container cgroups, streaming kernel tracepoints, and intercepting container breakout attacks.
"""

import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel import (
    SentinelDaemon,
    KernelEvent,
    EventType,
    AlertSeverity,
)


def run_demo():
    print("\n" + "=" * 78)
    print(" 🛡️  eBPF CONTAINER SENTINEL: IN-KERNEL TELEMETRY DEMONSTRATION")
    print("=" * 78)

    daemon = SentinelDaemon(
        alert_callback=lambda alert: print(
            f"🚨 [ALERT DISPATCHED] [{alert.severity.value}] {alert.mitre_technique_id} - {alert.technique_name}\n"
            f"   Message : {alert.message}\n"
            f"   Process : {alert.trigger_event.comm} (PID: {alert.trigger_event.pid})\n"
        )
    )

    # 1. Enroll Container CGroup
    cgroup_id = 4096182
    container_name = "k8s-pod-ecommerce-checkout"
    daemon.enroll_container(cgroup_id, container_name)
    print(f"Enrolled container namespace: '{container_name}' (CGroup ID: {cgroup_id})")

    # 2. Simulate Benign Workload Ingestion
    print("\n[Step 1] Ingesting benign container microservice executions...")
    benign_ev = KernelEvent(
        event_id="EVT-001",
        timestamp_ns=time.perf_counter_ns(),
        cgroup_id=cgroup_id,
        pid=1204,
        ppid=1200,
        uid=1000,
        event_type=EventType.PROCESS_EXEC,
        comm="python3",
        path="/app/worker.py",
        is_container=True,
    )
    alert = daemon.process_kernel_event(benign_ev)
    print(f"  • Process: {benign_ev.comm} ({benign_ev.path}) -> Status: {'ALERT' if alert else 'VERIFIED_SAFE'}")

    # 3. Simulate Container Escape Attack (T1611)
    print("\n[Step 2] Attacker executes container breakout payload targeting host Docker socket...")
    escape_ev = KernelEvent(
        event_id="EVT-002",
        timestamp_ns=time.perf_counter_ns(),
        cgroup_id=cgroup_id,
        pid=1390,
        ppid=1204,
        uid=0,
        event_type=EventType.FILE_OPEN,
        comm="breakout_poc",
        path="/var/run/docker.sock",
        is_container=True,
    )
    daemon.process_kernel_event(escape_ev)

    # 4. Simulate Reverse Shell (T1059)
    print("[Step 3] Attacker spawns interactive reverse shell to external C2 server...")
    shell_ev = KernelEvent(
        event_id="EVT-003",
        timestamp_ns=time.perf_counter_ns(),
        cgroup_id=cgroup_id,
        pid=1401,
        ppid=1390,
        uid=0,
        event_type=EventType.SOCKET_CONNECT,
        comm="sh",
        daddr="198.51.100.42",
        dport=4444,
        is_container=True,
    )
    daemon.process_kernel_event(shell_ev)

    print("-" * 78)
    print("Daemon Telemetry Metrics:")
    for k, v in daemon.metrics.items():
        print(f"  • {k:<25} : {v}")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    run_demo()
