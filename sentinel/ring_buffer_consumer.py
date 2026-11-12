"""
sentinel/ring_buffer_consumer.py
High-Throughput Ring Buffer Consumer for In-Kernel eBPF Telemetry.
Decodes raw binary kernel records and dispatches normalized KernelEvent streams.
"""

from __future__ import annotations
import time
import uuid
import struct
from typing import Iterator, Optional, List
from .models import KernelEvent, EventType


class RingBufferConsumer:
    """
    Consumes and decodes telemetry from the eBPF ring buffer map.
    Supports real Linux kernel ring buffer hooks and high-speed simulation harnesses.
    """

    def __init__(self, buffer_size_mb: int = 16):
        self.buffer_size_mb = buffer_size_mb
        self.total_events_consumed = 0
        self.cumulative_decode_time_us = 0.0

    def parse_raw_record(self, raw_bytes: bytes) -> KernelEvent:
        """
        Decodes a C struct telemetry_event binary payload:
        struct telemetry_event {
            __u64 timestamp_ns;
            __u64 cgroup_id;
            __u32 pid;
            __u32 ppid;
            __u32 uid;
            __u32 event_type;
            char comm[16];
            char path[256];
            __u32 daddr;
            __u16 dport;
            __u16 flags;
            __u8 is_container;
        };
        """
        t0 = time.perf_counter_ns()

        # Binary format string (little-endian):
        # Q (8), Q (8), I (4), I (4), I (4), I (4), 16s (16), 256s (256), I (4), H (2), H (2), B (1)
        fmt = "<QQIIII16s256sIHHB"
        record_size = struct.calcsize(fmt)

        if len(raw_bytes) < record_size:
            # Fallback zero-pad
            raw_bytes = raw_bytes.ljust(record_size, b"\x00")

        unpacked = struct.unpack_from(fmt, raw_bytes)
        (
            ts_ns,
            cgroup_id,
            pid,
            ppid,
            uid,
            raw_type,
            comm_bytes,
            path_bytes,
            raw_daddr,
            dport,
            flags,
            is_container,
        ) = unpacked

        type_map = {
            1: EventType.PROCESS_EXEC,
            2: EventType.SOCKET_CONNECT,
            3: EventType.FILE_OPEN,
        }
        event_type = type_map.get(raw_type, EventType.UNKNOWN)

        comm = comm_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
        path = path_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="ignore")

        # Convert __u32 IPv4 to standard dot-decimal notation
        daddr_str = f"{(raw_daddr >> 24) & 0xFF}.{(raw_daddr >> 16) & 0xFF}.{(raw_daddr >> 8) & 0xFF}.{raw_daddr & 0xFF}"

        decode_elapsed_us = (time.perf_counter_ns() - t0) / 1000.0
        self.cumulative_decode_time_us += decode_elapsed_us
        self.total_events_consumed += 1

        return KernelEvent(
            event_id=f"EVT-{uuid.uuid4().hex[:8]}",
            timestamp_ns=ts_ns,
            cgroup_id=cgroup_id,
            pid=pid,
            ppid=ppid,
            uid=uid,
            event_type=event_type,
            comm=comm,
            path=path,
            daddr=daddr_str,
            dport=dport,
            is_container=bool(is_container),
        )

    @property
    def average_decode_latency_us(self) -> float:
        if self.total_events_consumed == 0:
            return 0.0
        return self.cumulative_decode_time_us / self.total_events_consumed
