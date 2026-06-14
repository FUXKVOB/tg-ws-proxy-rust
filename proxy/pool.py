import asyncio
import logging
import time

from collections import deque
from urllib.parse import urlencode
from typing import Any, Coroutine, Dict, List, Optional, Tuple, Set

from .raw_websocket import RawWebSocket, WsHandshakeError
from .stats import stats
from .config import proxy_config
from .utils import ws_domains, DC_DEFAULT_IPS

log = logging.getLogger('tg-mtproto-proxy')

WS_POOL_MAX_AGE = 120.0


class _BasePool:
    """Generic connection pool keyed by an arbitrary hashable key.

    Subclasses only need to implement:
      - ``_connect_one(...)`` — create a single connection.
      - ``_refill_args(key)`` — return keyword arguments for ``_connect_one``.
      - ``_log_prefix(key)`` — human-readable label for log lines.
      - ``_inc_hit()`` / ``_inc_miss()`` — bump the right stats counter.
    """

    def __init__(self, key_type=Any):
        self._idle: Dict[Any, deque] = {}
        self._refilling: Set[Any] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get(self, key, *args, **kwargs) -> Optional[RawWebSocket]:
        now = time.monotonic()
        bucket = self._idle.get(key)
        if bucket is None:
            bucket = deque()
            self._idle[key] = bucket

        while bucket:
            ws, created = bucket.popleft()
            age = now - created
            if age > WS_POOL_MAX_AGE or ws._closed or ws.writer.transport.is_closing():
                asyncio.create_task(self._quiet_close(ws))
                continue
            self._inc_hit()
            log.debug("%s pool hit %s (age=%.1fs, left=%d)",
                      self._log_prefix(key), key, age, len(bucket))
            self._schedule_refill(key, *args, **kwargs)
            return ws

        self._inc_miss()
        self._schedule_refill(key, *args, **kwargs)
        return None

    async def warmup(self) -> None:
        tasks = self._schedule_all_refills()
        if tasks:
            await asyncio.wait(tasks)
            log.info("%s pool warmup complete (%d DC(s))",
                     self._name, self._count_keys())
        else:
            log.info("%s pool warmup: nothing to do", self._name)

    def reset(self) -> None:
        self._idle.clear()
        self._refilling.clear()

    # ------------------------------------------------------------------
    # Internals — subclasses override the hooks
    # ------------------------------------------------------------------

    _name: str = "base"

    def _schedule_all_refills(self) -> List[asyncio.Task]:
        raise NotImplementedError

    def _connect_one(self, *args, **kwargs) -> Coroutine:
        raise NotImplementedError

    def _refill_args(self, key) -> Tuple[tuple, dict]:
        raise NotImplementedError

    def _log_prefix(self, key) -> str:
        return self._name

    def _count_keys(self) -> int:
        raise NotImplementedError

    def _inc_hit(self) -> None:
        pass

    def _inc_miss(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Shared mechanics
    # ------------------------------------------------------------------

    def _schedule_refill(self, key, *args, **kwargs) -> None:
        if key in self._refilling:
            return
        self._refilling.add(key)
        asyncio.create_task(self._refill(key, *args, **kwargs))

    async def _refill(self, key, *args, **kwargs) -> None:
        try:
            bucket = self._idle.setdefault(key, deque())
            needed = proxy_config.pool_size - len(bucket)
            if needed <= 0:
                return
            args, kwargs = self._refill_args(key)
            connect_tasks = [
                asyncio.create_task(self._connect_one(*args, **kwargs))
                for _ in range(needed)
            ]
            for t in connect_tasks:
                try:
                    ws = await t
                    if ws:
                        bucket.append((ws, time.monotonic()))
                except Exception:
                    pass
            log.debug("%s pool refilled %s: %d ready",
                      self._log_prefix(key), key, len(bucket))
        finally:
            self._refilling.discard(key)

    @staticmethod
    async def _quiet_close(ws: RawWebSocket) -> None:
        try:
            await ws.close()
        except Exception:
            pass


class _WsPool(_BasePool):
    _name = "WS"

    def __init__(self):
        super().__init__()

    def _inc_hit(self) -> None:
        stats.pool_hits += 1

    def _inc_miss(self) -> None:
        stats.pool_misses += 1

    def _log_prefix(self, key) -> str:
        dc, is_media = key
        return f"DC{dc}{'m' if is_media else ''}"

    def _count_keys(self) -> int:
        return len(proxy_config.dc_redirects)

    def _refill_args(self, key) -> Tuple[tuple, dict]:
        dc, is_media = key
        target_ip = proxy_config.dc_redirects[dc]
        domains = ws_domains(dc, is_media)
        return (target_ip, domains), {}

    async def _connect_one(self, target_ip: str, domains: List[str]) -> Optional[RawWebSocket]:
        for domain in domains:
            try:
                return await RawWebSocket.connect(target_ip, domain, timeout=8)
            except WsHandshakeError as exc:
                if exc.is_redirect:
                    continue
                return None
            except Exception:
                return None
        return None

    def _schedule_all_refills(self) -> List[asyncio.Task]:
        tasks = []
        for dc, target_ip in proxy_config.dc_redirects.items():
            if target_ip is None:
                continue
            for is_media in (False, True):
                key = (dc, is_media)
                if key in self._refilling:
                    continue
                self._refilling.add(key)
                tasks.append(asyncio.create_task(self._refill(key, target_ip, ws_domains(dc, is_media))))
        log.info("WS pool warmup started for %d DC(s)", self._count_keys())
        return tasks


class _CfWorkerPool(_BasePool):
    _name = "CF"

    def __init__(self):
        super().__init__()

    def _inc_hit(self) -> None:
        stats.cf_pool_hits += 1

    def _inc_miss(self) -> None:
        stats.cf_pool_misses += 1

    def _log_prefix(self, key) -> str:
        dc, worker_domain = key
        return f"DC{dc}"

    def _count_keys(self) -> int:
        cf_fallbacks = {
            dc for dc in DC_DEFAULT_IPS
            if dc not in proxy_config.dc_redirects
        }
        return len(cf_fallbacks)

    def _refill_args(self, key) -> Tuple[tuple, dict]:
        dc, worker_domain = key
        fallback_dst = DC_DEFAULT_IPS.get(dc, '')
        return (worker_domain, fallback_dst, dc), {}

    async def _connect_one(self, worker_domain: str, fallback_dst: str, dc: int) -> Optional[RawWebSocket]:
        query = urlencode({'dst': fallback_dst, 'dc': str(dc)})
        path = f'/apiws?{query}'
        try:
            return await RawWebSocket.connect(worker_domain, worker_domain, timeout=8, path=path)
        except Exception:
            return None

    def _schedule_all_refills(self) -> List[asyncio.Task]:
        cf_fallbacks = {
            dc: ip for dc, ip in DC_DEFAULT_IPS.items()
            if dc not in proxy_config.dc_redirects
        }
        if not cf_fallbacks or not proxy_config.cfproxy_worker_domains:
            return []

        tasks = []
        for worker_domain in proxy_config.cfproxy_worker_domains:
            for dc, fallback_dst in cf_fallbacks.items():
                key = (dc, worker_domain)
                if key in self._refilling:
                    continue
                self._refilling.add(key)
                tasks.append(asyncio.create_task(self._refill(key, worker_domain, fallback_dst, dc)))
        log.info("CF worker pool warmup started for %d DC(s)", len(cf_fallbacks))
        return tasks


ws_pool = _WsPool()
cf_worker_pool = _CfWorkerPool()
