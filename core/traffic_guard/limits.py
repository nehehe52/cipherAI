import asyncio
import time
from collections import OrderedDict, deque
from contextlib import asynccontextmanager
from typing import Callable, Deque, Optional


class Rejected(Exception):
    def __init__(self, reason: str, retry_after: float = 1.0):
        super().__init__(reason)
        self.reason = reason
        self.retry_after = retry_after


class TokenBucket:
    def __init__(self, rate: float, burst: float, clock: Callable[[], float] = time.monotonic):
        if rate <= 0 or burst <= 0:
            raise ValueError("rate and burst must be positive")
        self.rate = rate
        self.burst = burst
        self._clock = clock
        self._tokens = burst
        self._updated = clock()

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self.burst, self._tokens + (now - self._updated) * self.rate)
        self._updated = now

    def try_acquire(self, tokens: float = 1.0) -> bool:
        self._refill()
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False

    def retry_after(self, tokens: float = 1.0) -> float:
        self._refill()
        missing = max(0.0, tokens - self._tokens)
        return missing / self.rate


class PerClientRateLimiter:
    """One token bucket per client key, with LRU eviction to bound memory."""

    def __init__(self, rate: float, burst: float, max_clients: int = 10_000,
                 clock: Callable[[], float] = time.monotonic):
        self.rate = rate
        self.burst = burst
        self.max_clients = max_clients
        self._clock = clock
        self._buckets: "OrderedDict[str, TokenBucket]" = OrderedDict()

    def check(self, key: str) -> None:
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = TokenBucket(self.rate, self.burst, self._clock)
            self._buckets[key] = bucket
            if len(self._buckets) > self.max_clients:
                self._buckets.popitem(last=False)
        else:
            self._buckets.move_to_end(key)
        if not bucket.try_acquire():
            raise Rejected("rate_limited", retry_after=max(bucket.retry_after(), 0.001))

    def __len__(self) -> int:
        return len(self._buckets)


class AdmissionController:
    """Caps in-flight work and bounds both the length and the wait time of the queue.

    Requests beyond ``max_concurrency`` wait in a FIFO queue. If the queue already holds
    ``max_queue`` requests, new arrivals are rejected immediately ("queue_full"); if a
    queued request waits longer than ``queue_timeout`` it is rejected ("queue_timeout").
    Failing fast keeps latency bounded for the requests that are admitted.
    """

    def __init__(self, max_concurrency: int, max_queue: int, queue_timeout: float):
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        self.max_concurrency = max_concurrency
        self.max_queue = max_queue
        self.queue_timeout = queue_timeout
        self.in_flight = 0
        self._waiters: Deque[asyncio.Future] = deque()

    @property
    def queued(self) -> int:
        return sum(1 for w in self._waiters if not w.done())

    async def acquire(self) -> float:
        """Returns seconds spent queued."""
        if self.in_flight < self.max_concurrency:
            self.in_flight += 1
            return 0.0
        if self.queued >= self.max_queue:
            raise Rejected("queue_full", retry_after=self.queue_timeout or 1.0)

        start = time.monotonic()
        fut = asyncio.get_running_loop().create_future()
        self._waiters.append(fut)
        try:
            await asyncio.wait_for(asyncio.shield(fut), timeout=self.queue_timeout)
        except asyncio.TimeoutError:
            if fut.done() and not fut.cancelled():
                return time.monotonic() - start
            fut.cancel()
            raise Rejected("queue_timeout", retry_after=self.queue_timeout or 1.0)
        except asyncio.CancelledError:
            if fut.done() and not fut.cancelled():
                self.release()
            else:
                fut.cancel()
            raise
        return time.monotonic() - start

    def resize(self, max_concurrency: int) -> None:
        """Change the concurrency cap at runtime, admitting queued requests if it grew."""
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        self.max_concurrency = max_concurrency
        while self.in_flight < self.max_concurrency and self._waiters:
            fut = self._waiters.popleft()
            if not fut.done():
                self.in_flight += 1
                fut.set_result(None)

    def release(self) -> None:
        if self.in_flight <= self.max_concurrency:
            while self._waiters:
                fut = self._waiters.popleft()
                if not fut.done():
                    fut.set_result(None)
                    return
        self.in_flight -= 1

    @asynccontextmanager
    async def slot(self):
        waited = await self.acquire()
        try:
            yield waited
        finally:
            self.release()


def client_key(forwarded_for: Optional[str], remote: Optional[str]) -> str:
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return remote or "unknown"
