import argparse
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class GuardConfig:
    upstream: str
    host: str = "0.0.0.0"
    port: int = 8080
    rate: float = 100.0
    burst: float = 200.0
    max_clients: int = 10_000
    max_concurrency: int = 64
    max_queue: int = 256
    queue_timeout: float = 1.0
    upstream_timeout: float = 5.0
    connect_timeout: float = 1.0
    max_body_bytes: int = 10 * 1024 * 1024
    trust_forwarded_for: bool = False
    metrics_window: int = 120


def parse_args(argv: Optional[List[str]] = None) -> GuardConfig:
    p = argparse.ArgumentParser(
        prog="traffic-guard",
        description="Reverse proxy that keeps latency bounded under heavy traffic, with a live dashboard at /__guard/.",
    )
    p.add_argument("--upstream", required=True, help="Backend base URL, e.g. http://127.0.0.1:9000")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--rate", type=float, default=100.0, help="Per-client sustained requests/second")
    p.add_argument("--burst", type=float, default=200.0, help="Per-client burst size (token bucket capacity)")
    p.add_argument("--max-clients", type=int, default=10_000, help="Max tracked client buckets (LRU)")
    p.add_argument("--max-concurrency", type=int, default=64, help="Max requests in flight to the upstream")
    p.add_argument("--max-queue", type=int, default=256, help="Max requests waiting for a slot")
    p.add_argument("--queue-timeout", type=float, default=1.0, help="Max seconds a request may wait in queue")
    p.add_argument("--upstream-timeout", type=float, default=5.0, help="Total deadline for the upstream call")
    p.add_argument("--connect-timeout", type=float, default=1.0)
    p.add_argument("--max-body-bytes", type=int, default=10 * 1024 * 1024)
    p.add_argument("--trust-forwarded-for", action="store_true",
                   help="Use X-Forwarded-For as the client key (only behind a trusted LB)")
    p.add_argument("--metrics-window", type=int, default=120, help="Seconds of history kept for metrics")
    a = p.parse_args(argv)
    return GuardConfig(**{k: v for k, v in vars(a).items()})
