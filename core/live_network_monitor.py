"""
Live Network Traffic & Latency Guard.

Runs the traffic-guard reverse proxy (per-client rate limiting, concurrency cap, bounded queue
with timeout, upstream deadline, load shedding) in a background thread, together with a demo
backend that slows down under contention and a configurable traffic generator. The Streamlit
dashboard reads live latency / throughput / shedding metrics from it.
"""

import asyncio
import math
import random
import socket
import threading
import time
from typing import Dict, Optional

import aiohttp
from aiohttp import web

from core.traffic_guard.config import GuardConfig
from core.traffic_guard.limits import PerClientRateLimiter
from core.traffic_guard.proxy import ADMISSION, CONFIG, LIMITER, create_app, snapshot

TRAFFIC_PATTERNS = ["Wave (rising & falling)", "Steady", "Spikes (burst every 30s)"]
FLOOD_SOURCE_IP = "203.0.113.66"
MAX_OUTSTANDING = 3000


def _free_port(preferred: Optional[int] = None) -> int:
    for port in ([preferred] if preferred else []) + [0]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return s.getsockname()[1]
            except OSError:
                continue
    raise RuntimeError("no free port")


class LiveNetworkMonitor:
    def __init__(self, guard_port: int = 8765):
        self.preferred_guard_port = guard_port
        self.guard_port: Optional[int] = None
        self.backend_port: Optional[int] = None
        self.demo_upstream: Optional[str] = None

        self.load_enabled = True
        self.pattern = TRAFFIC_PATTERNS[0]
        self.target_rps = 150.0
        self.clients = 40
        self.flood_enabled = False
        self.flood_rps = 40.0
        self.backend_contention_ms = 4.0

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._guard_app: Optional[web.Application] = None
        self._runners = []
        self._tasks = []
        self._session: Optional[aiohttp.ClientSession] = None
        self._backend_in_flight = 0
        self._started_at = time.monotonic()

    # ---------- lifecycle ----------
    @property
    def running(self) -> bool:
        return self._loop is not None and self._loop.is_running()

    def start(self) -> "LiveNetworkMonitor":
        if self.running:
            return self
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, name="live-network-monitor", daemon=True)
        self._thread.start()
        asyncio.run_coroutine_threadsafe(self._startup(), self._loop).result(timeout=15)
        return self

    def stop(self) -> None:
        if not self.running:
            return
        asyncio.run_coroutine_threadsafe(self._shutdown(), self._loop).result(timeout=15)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
        self._loop = None

    async def _startup(self) -> None:
        self.backend_port = _free_port()
        self.demo_upstream = f"http://127.0.0.1:{self.backend_port}"
        backend = web.AppRunner(self._demo_backend())
        await backend.setup()
        await web.TCPSite(backend, "127.0.0.1", self.backend_port).start()

        self.guard_port = _free_port(self.preferred_guard_port)
        cfg = GuardConfig(
            upstream=self.demo_upstream, rate=10, burst=20, max_concurrency=16, max_queue=32,
            queue_timeout=0.25, upstream_timeout=2.0, trust_forwarded_for=True,
        )
        self._guard_app = create_app(cfg)
        guard = web.AppRunner(self._guard_app)
        await guard.setup()
        await web.TCPSite(guard, "127.0.0.1", self.guard_port).start()
        self._runners = [guard, backend]

        self._session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=0), timeout=aiohttp.ClientTimeout(total=10)
        )
        self._started_at = time.monotonic()
        self._tasks = [
            asyncio.create_task(self._generate(self._client_rps, self._random_client)),
            asyncio.create_task(self._generate(self._flood_rps, lambda: FLOOD_SOURCE_IP)),
        ]

    async def _shutdown(self) -> None:
        for t in self._tasks:
            t.cancel()
        if self._session:
            await self._session.close()
        for r in self._runners:
            await r.cleanup()

    # ---------- demo backend & traffic ----------
    def _demo_backend(self) -> web.Application:
        async def handle(request: web.Request) -> web.Response:
            self._backend_in_flight += 1
            try:
                delay_ms = 20 + self.backend_contention_ms * self._backend_in_flight + random.uniform(0, 10)
                await asyncio.sleep(delay_ms / 1000)
                return web.json_response({"path": request.path, "simulated_ms": round(delay_ms, 1)})
            finally:
                self._backend_in_flight -= 1

        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", handle)
        return app

    def _random_client(self) -> str:
        n = random.randrange(max(1, self.clients))
        return f"10.0.{n // 250}.{n % 250 + 1}"

    def _client_rps(self, t: float) -> float:
        if not self.load_enabled:
            return 0.0
        base = self.target_rps
        if self.pattern.startswith("Wave"):
            return base * (0.2 + 1.6 * (0.5 - 0.5 * math.cos(2 * math.pi * t / 120)))
        if self.pattern.startswith("Spikes"):
            return base * (3.0 if (t % 30) < 5 else 0.6)
        return base

    def _flood_rps(self, _t: float) -> float:
        return self.flood_rps if self.flood_enabled else 0.0

    async def _generate(self, rps_fn, client_fn) -> None:
        outstanding: set = set()

        async def one() -> None:
            try:
                async with self._session.get(
                    f"http://127.0.0.1:{self.guard_port}/api/live", headers={"X-Forwarded-For": client_fn()}
                ) as r:
                    await r.read()
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

        next_at = time.monotonic()
        while True:
            rps = rps_fn(time.monotonic() - self._started_at)
            if rps <= 0:
                await asyncio.sleep(0.2)
                next_at = time.monotonic()
                continue
            now = time.monotonic()
            if now < next_at:
                await asyncio.sleep(next_at - now)
            next_at = max(next_at + 1.0 / rps, time.monotonic() - 0.5)
            if len(outstanding) < MAX_OUTSTANDING:
                task = asyncio.create_task(one())
                outstanding.add(task)
                task.add_done_callback(outstanding.discard)

    # ---------- thread-safe API for the dashboard ----------
    def _call(self, fn, timeout: float = 5.0):
        async def runner():
            return fn()
        return asyncio.run_coroutine_threadsafe(runner(), self._loop).result(timeout=timeout)

    def snapshot(self) -> Dict:
        def build():
            s = snapshot(self._guard_app)
            s["backend_in_flight"] = self._backend_in_flight
            s["offered_rps"] = round(self._client_rps(time.monotonic() - self._started_at) + self._flood_rps(0), 1)
            return s
        return self._call(build)

    def configure_guard(self, *, rate: float, burst: float, max_concurrency: int, max_queue: int,
                        queue_timeout: float, upstream_timeout: float, upstream: Optional[str] = None) -> None:
        def apply():
            cfg: GuardConfig = self._guard_app[CONFIG]
            if (cfg.rate, cfg.burst) != (rate, burst):
                self._guard_app[LIMITER] = PerClientRateLimiter(rate, burst, cfg.max_clients)
            cfg.rate, cfg.burst = rate, burst
            cfg.max_concurrency, cfg.max_queue = max_concurrency, max_queue
            cfg.queue_timeout, cfg.upstream_timeout = queue_timeout, upstream_timeout
            cfg.upstream = (upstream or self.demo_upstream).rstrip("/")
            adm = self._guard_app[ADMISSION]
            adm.max_queue, adm.queue_timeout = max_queue, queue_timeout
            adm.resize(max_concurrency)
        self._call(apply)

    @property
    def dashboard_url(self) -> str:
        return f"http://localhost:{self.guard_port}/__guard/"
