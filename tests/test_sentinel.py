"""
tests/test_sentinel.py
Comprehensive Pytest test suite for eBPF Container Sentinel.
Tests binary decoding, CGroup isolation, threat engine rules, and daemon lifecycle.
"""

import pytest
import struct
import time
from sentinel import (
    SentinelDaemon,
    ContainerThreatEngine,
    RingBufferConsumer,
    KernelEvent,
    SecurityAlert,
    EventType,
    AlertSeverity,
)


@pytest.fixture
def consumer():
    return RingBufferConsumer()


@pytest.fixture
def threat_engine():
    return ContainerThreatEngine()


@pytest.fixture
def daemon():
    return SentinelDaemon()


def test_ring_buffer_binary_decoding(consumer):
    fmt = "<QQIIII16s256sIHHB"
    ts = 1234567890
    comm = b"python3\x00".ljust(16, b"\x00")
    path = b"/usr/bin/python3\x00".ljust(256, b"\x00")
    raw = struct.pack(fmt, ts, 4096, 501, 500, 1000, 1, comm, path, 0x7F000001, 8080, 0, 1)

    event = consumer.parse_raw_record(raw)
    assert event.pid == 501
    assert event.ppid == 500
    assert event.uid == 1000
    assert event.event_type == EventType.PROCESS_EXEC
    assert event.comm == "python3"
    assert event.path == "/usr/bin/python3"
    assert event.is_container is True
    assert event.dport == 8080


def test_container_escape_detection(threat_engine):
    event = KernelEvent(
        event_id="EVT-ESC",
        timestamp_ns=time.perf_counter_ns(),
        cgroup_id=101,
        pid=2001,
        ppid=2000,
        uid=0,
        event_type=EventType.FILE_OPEN,
        comm="exploit",
        path="/var/run/docker.sock",
        is_container=True,
    )
    alert = threat_engine.evaluate_event(event)
    assert alert is not None
    assert alert.mitre_technique_id == "T1611"
    assert alert.severity == AlertSeverity.CRITICAL


def test_cryptominer_detection(threat_engine):
    event = KernelEvent(
        event_id="EVT-MINE",
        timestamp_ns=time.perf_counter_ns(),
        cgroup_id=101,
        pid=2002,
        ppid=2000,
        uid=1000,
        event_type=EventType.PROCESS_EXEC,
        comm="xmrig",
        path="/tmp/xmrig",
        is_container=True,
    )
    alert = threat_engine.evaluate_event(event)
    assert alert is not None
    assert alert.mitre_technique_id == "T1496"
    assert alert.severity == AlertSeverity.HIGH


def test_reverse_shell_detection(threat_engine):
    event = KernelEvent(
        event_id="EVT-SHELL",
        timestamp_ns=time.perf_counter_ns(),
        cgroup_id=101,
        pid=2003,
        ppid=2000,
        uid=0,
        event_type=EventType.SOCKET_CONNECT,
        comm="bash",
        daddr="198.51.100.2",
        dport=4444,
        is_container=True,
    )
    alert = threat_engine.evaluate_event(event)
    assert alert is not None
    assert alert.mitre_technique_id == "T1059"
    assert alert.severity == AlertSeverity.CRITICAL


def test_benign_event_no_alert(threat_engine):
    event = KernelEvent(
        event_id="EVT-BENIGN",
        timestamp_ns=time.perf_counter_ns(),
        cgroup_id=101,
        pid=2004,
        ppid=2000,
        uid=1000,
        event_type=EventType.PROCESS_EXEC,
        comm="python3",
        path="/app/server.py",
        is_container=True,
    )
    alert = threat_engine.evaluate_event(event)
    assert alert is None


def test_daemon_container_enrollment_and_metrics(daemon):
    daemon.enroll_container(5001, "k8s-pod-web")
    event = KernelEvent(
        event_id="EVT-METRIC",
        timestamp_ns=time.perf_counter_ns(),
        cgroup_id=5001,
        pid=3001,
        ppid=3000,
        uid=1000,
        event_type=EventType.PROCESS_EXEC,
        comm="nginx",
        path="/usr/sbin/nginx",
        is_container=True,
    )
    daemon.process_kernel_event(event)
    metrics = daemon.metrics
    assert metrics["monitored_containers"] == 1
    assert metrics["processed_events"] == 1
    assert metrics["total_alerts"] == 0
