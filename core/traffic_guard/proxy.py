import asyncio
import time
from pathlib import Path

import aiohttp
from aiohttp import web

from .config import GuardConfig
from .limits import AdmissionController, PerClientRateLimiter, Rejected, client_key
from .metrics import Metrics

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade", "content-length", "content-encoding", "host",
}
GUARD_PREFIX = "/__guard"
DASHBOARD_HTML = (Path(__file__).parent / "dashboard.html").read_text()

CONFIG = web.AppKey("config", GuardConfig)
METRICS = web.AppKey("metrics", Metrics)
LIMITER = web.AppKey("limiter", PerClientRateLimiter)
ADMISSION = web.AppKey("admission", AdmissionController)
SESSION = web.AppKey("session", aiohttp.ClientSession)


def _reject(metrics: Metrics, exc: Rejected, status: int, started: float) -> web.Response:
    metrics.record(status, time.monotonic() - started, rejection=exc.reason)
    return web.json_response(
        {"error": exc.reason, "retry_after_s": round(exc.retry_after, 3)},
        status=status,
        headers={"Retry-After": str(max(1, int(exc.retry_after + 0.999)))},
    )


async def proxy_handler(request: web.Request) -> web.StreamResponse:
    app = request.app
    cfg, metrics = app[CONFIG], app[METRICS]
    started = time.monotonic()

    fwd = request.headers.get("X-Forwarded-For") if cfg.trust_forwarded_for else None
    key = client_key(fwd, request.remote)
    try:
        app[LIMITER].check(key)
    except Rejected as exc:
        return _reject(metrics, exc, 429, started)

    try:
        async with app[ADMISSION].slot() as waited:
            return await _forward(request, cfg, metrics, started, waited)
    except Rejected as exc:
        return _reject(metrics, exc, 503, started)


async def _forward(request: web.Request, cfg: GuardConfig, metrics: Metrics,
                   started: float, waited: float) -> web.Response:
    remaining = cfg.upstream_timeout
    if request.content_length and request.content_length > cfg.max_body_bytes:
        metrics.record(413, time.monotonic() - started, waited)
        return web.json_response({"error": "body_too_large"}, status=413)
    body = await request.read() if request.can_read_body else None

    headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP}
    headers["X-Forwarded-For"] = client_key(request.headers.get("X-Forwarded-For"), request.remote)
    url = cfg.upstream.rstrip("/") + request.rel_url.path_qs
    timeout = aiohttp.ClientTimeout(total=remaining, sock_connect=cfg.connect_timeout)

    try:
        async with request.app[SESSION].request(
            request.method, url, headers=headers, data=body, timeout=timeout, allow_redirects=False
        ) as resp:
            payload = await resp.read()
            out_headers = {k: v for k, v in resp.headers.items() if k.lower() not in HOP_BY_HOP}
            status = resp.status
    except asyncio.TimeoutError:
        metrics.record(504, time.monotonic() - started, waited)
        return web.json_response({"error": "upstream_timeout"}, status=504)
    except aiohttp.ClientError as exc:
        metrics.record(502, time.monotonic() - started, waited)
        return web.json_response({"error": "upstream_unavailable", "detail": type(exc).__name__}, status=502)

    elapsed = time.monotonic() - started
    metrics.record(status, elapsed, waited)
    out_headers["X-Guard-Latency-Ms"] = f"{elapsed * 1000:.1f}"
    out_headers["X-Guard-Queue-Ms"] = f"{waited * 1000:.1f}"
    return web.Response(body=payload, status=status, headers=out_headers)


def snapshot(app: web.Application) -> dict:
    cfg, metrics, adm = app[CONFIG], app[METRICS], app[ADMISSION]
    return {
        "uptime_s": round(time.time() - metrics.started, 1),
        "upstream": cfg.upstream,
        "in_flight": adm.in_flight,
        "queued": adm.queued,
        "tracked_clients": len(app[LIMITER]),
        "limits": {
            "rate": cfg.rate, "burst": cfg.burst, "max_concurrency": cfg.max_concurrency,
            "max_queue": cfg.max_queue, "queue_timeout_s": cfg.queue_timeout,
            "upstream_timeout_s": cfg.upstream_timeout,
        },
        "totals": dict(metrics.totals),
        "last_10s": metrics.summary(10),
        "last_60s": metrics.summary(60),
        "timeseries": metrics.timeseries(60),
    }


async def metrics_handler(request: web.Request) -> web.Response:
    return web.json_response(snapshot(request.app))


def prometheus_text(app: web.Application) -> str:
    s = snapshot(app)
    lines = [
        "# TYPE traffic_guard_in_flight gauge", f"traffic_guard_in_flight {s['in_flight']}",
        "# TYPE traffic_guard_queued gauge", f"traffic_guard_queued {s['queued']}",
        "# TYPE traffic_guard_requests_total counter",
    ]
    for k, v in sorted(s["totals"].items()):
        if k == "requests":
            lines.append(f'traffic_guard_requests_total {v}')
    lines.append("# TYPE traffic_guard_responses_total counter")
    for k, v in sorted(s["totals"].items()):
        if k.endswith("xx"):
            lines.append(f'traffic_guard_responses_total{{class="{k}"}} {v}')
    lines.append("# TYPE traffic_guard_rejections_total counter")
    for k, v in sorted(s["totals"].items()):
        if k in ("rate_limited", "queue_full", "queue_timeout"):
            lines.append(f'traffic_guard_rejections_total{{reason="{k}"}} {v}')
    lines.append("# TYPE traffic_guard_latency_ms gauge")
    for q, v in s["last_60s"]["latency_ms"].items():
        if v is not None:
            lines.append(f'traffic_guard_latency_ms{{quantile="{q}",window="60s"}} {v}')
    return "\n".join(lines) + "\n"


async def prometheus_handler(request: web.Request) -> web.Response:
    return web.Response(text=prometheus_text(request.app), content_type="text/plain")


async def dashboard_handler(request: web.Request) -> web.Response:
    return web.Response(text=DASHBOARD_HTML, content_type="text/html")


async def health_handler(request: web.Request) -> web.Response:
    return web.json_response({"ok": True})


def create_app(cfg: GuardConfig) -> web.Application:
    app = web.Application(client_max_size=cfg.max_body_bytes)
    app[CONFIG] = cfg
    app[METRICS] = Metrics(window_seconds=cfg.metrics_window)
    app[LIMITER] = PerClientRateLimiter(cfg.rate, cfg.burst, cfg.max_clients)
    app[ADMISSION] = AdmissionController(cfg.max_concurrency, cfg.max_queue, cfg.queue_timeout)

    async def session_ctx(app: web.Application):
        connector = aiohttp.TCPConnector(limit=cfg.max_concurrency, keepalive_timeout=30)
        app[SESSION] = aiohttp.ClientSession(connector=connector, auto_decompress=False)
        yield
        await app[SESSION].close()

    app.cleanup_ctx.append(session_ctx)
    app.router.add_get(GUARD_PREFIX + "/", dashboard_handler)
    app.router.add_get(GUARD_PREFIX, dashboard_handler)
    app.router.add_get(GUARD_PREFIX + "/metrics", metrics_handler)
    app.router.add_get(GUARD_PREFIX + "/prometheus", prometheus_handler)
    app.router.add_get(GUARD_PREFIX + "/health", health_handler)
    app.router.add_route("*", "/{tail:.*}", proxy_handler)
    return app
