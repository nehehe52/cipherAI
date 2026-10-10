import math
import random
import time
from collections import Counter, deque
from typing import Callable, Deque, Dict, List, Optional


def percentile(sorted_values: List[float], q: float) -> Optional[float]:
    if not sorted_values:
        return None
    idx = max(0, min(len(sorted_values) - 1, math.ceil(q / 100.0 * len(sorted_values)) - 1))
    return sorted_values[idx]


class _Second:
    __slots__ = ("ts", "requests", "statuses", "rejections", "latencies", "seen", "queue_wait")

    def __init__(self, ts: int):
        self.ts = ts
        self.requests = 0
        self.statuses: Counter = Counter()
        self.rejections: Counter = Counter()
        self.latencies: List[float] = []
        self.seen = 0
        self.queue_wait = 0.0


class Metrics:
    """Rolling per-second traffic and latency stats over a fixed window.

    Latencies are reservoir-sampled per second so memory stays bounded at any request rate.
    """

    def __init__(self, window_seconds: int = 120, samples_per_second: int = 2000,
                 clock: Callable[[], float] = time.time):
        self.window = window_seconds
        self.samples_per_second = samples_per_second
        self._clock = clock
        self._seconds: Deque[_Second] = deque()
        self.started = clock()
        self.totals: Counter = Counter()

    def _bucket(self) -> _Second:
        now = int(self._clock())
        if not self._seconds or self._seconds[-1].ts != now:
            self._seconds.append(_Second(now))
        while self._seconds and self._seconds[0].ts <= now - self.window:
            self._seconds.popleft()
        return self._seconds[-1]

    def record(self, status: int, latency_s: float, queue_wait_s: float = 0.0,
               rejection: Optional[str] = None) -> None:
        b = self._bucket()
        b.requests += 1
        b.statuses[f"{status // 100}xx"] += 1
        b.queue_wait += queue_wait_s
        self.totals["requests"] += 1
        self.totals[f"{status // 100}xx"] += 1
        if rejection:
            b.rejections[rejection] += 1
            self.totals[rejection] += 1
            return
        ms = latency_s * 1000.0
        b.seen += 1
        if len(b.latencies) < self.samples_per_second:
            b.latencies.append(ms)
        else:
            j = random.randrange(b.seen)
            if j < self.samples_per_second:
                b.latencies[j] = ms

    def _window(self, seconds: int) -> List[_Second]:
        now = int(self._clock())
        return [b for b in self._seconds if b.ts > now - seconds]

    def summary(self, seconds: int) -> Dict:
        buckets = self._window(seconds)
        lat = sorted(x for b in buckets for x in b.latencies)
        requests = sum(b.requests for b in buckets)
        statuses: Counter = Counter()
        rejections: Counter = Counter()
        for b in buckets:
            statuses.update(b.statuses)
            rejections.update(b.rejections)
        elapsed = max(1.0, min(seconds, self._clock() - self.started))
        return {
            "window_s": seconds,
            "requests": requests,
            "rps": round(requests / elapsed, 2),
            "statuses": dict(statuses),
            "rejections": dict(rejections),
            "error_rate": round((statuses.get("5xx", 0) + statuses.get("4xx", 0)) / requests, 4) if requests else 0.0,
            "latency_ms": {
                "p50": _r(percentile(lat, 50)),
                "p90": _r(percentile(lat, 90)),
                "p95": _r(percentile(lat, 95)),
                "p99": _r(percentile(lat, 99)),
                "max": _r(lat[-1] if lat else None),
                "mean": _r(sum(lat) / len(lat) if lat else None),
            },
        }

    def timeseries(self, seconds: int = 60) -> List[Dict]:
        now = int(self._clock())
        by_ts = {b.ts: b for b in self._seconds}
        out = []
        for ts in range(now - seconds + 1, now + 1):
            b = by_ts.get(ts)
            if b is None:
                out.append({"ts": ts, "requests": 0, "ok": 0, "rejected": 0, "errors": 0,
                            "p50": None, "p95": None, "p99": None})
                continue
            lat = sorted(b.latencies)
            rejected = sum(b.rejections.values())
            out.append({
                "ts": ts,
                "requests": b.requests,
                "ok": b.statuses.get("2xx", 0) + b.statuses.get("3xx", 0),
                "rejected": rejected,
                "errors": b.statuses.get("5xx", 0) + b.statuses.get("4xx", 0) - rejected,
                "p50": _r(percentile(lat, 50)),
                "p95": _r(percentile(lat, 95)),
                "p99": _r(percentile(lat, 99)),
            })
        return out


def _r(v: Optional[float]) -> Optional[float]:
    return None if v is None else round(v, 2)
