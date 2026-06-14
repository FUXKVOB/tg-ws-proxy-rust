import time
from .utils import human_bytes


class _Stats:
    def __init__(self):
        self.connections_total = 0
        self.connections_active = 0
        self.connections_ws = 0
        self.connections_tcp_fallback = 0
        self.connections_cfproxy = 0
        self.connections_bad = 0
        self.connections_masked = 0
        self.ws_errors = 0
        self.bytes_up = 0
        self.bytes_down = 0
        self.pool_hits = 0
        self.pool_misses = 0
        self.cf_pool_hits = 0
        self.cf_pool_misses = 0
        self._start_time: float = time.monotonic()
        # per-DC counters: {dc_key: count} e.g. {'2': 5, '4m': 2}
        self.dc_connections: dict = {}

    def reset_counters(self) -> None:
        """Reset all cumulative counters (but keep connections_active)."""
        active = self.connections_active
        self.__init__()
        self.connections_active = active

    def record_dc(self, dc: int, is_media: bool) -> None:
        key = f"{dc}{'m' if is_media else ''}"
        self.dc_connections[key] = self.dc_connections.get(key, 0) + 1

    def uptime_seconds(self) -> float:
        return time.monotonic() - self._start_time

    def uptime_str(self) -> str:
        total = int(self.uptime_seconds())
        h, rem = divmod(total, 3600)
        m, s = divmod(rem, 60)
        if h:
            return f"{h}ч {m:02d}м {s:02d}с"
        if m:
            return f"{m}м {s:02d}с"
        return f"{s}с"

    def tray_tooltip(self) -> str:
        """Short one-line summary for the tray icon tooltip."""
        return (
            f"TG WS Proxy  |  "
            f"активных: {self.connections_active}  "
            f"всего: {self.connections_total}  "
            f"↑{human_bytes(self.bytes_up)} ↓{human_bytes(self.bytes_down)}"
        )

    def summary(self) -> str:
        pool_total = self.pool_hits + self.pool_misses
        pool_s = (f"{self.pool_hits}/{pool_total}"
                  if pool_total else "n/a")
        cf_pool_total = self.cf_pool_hits + self.cf_pool_misses
        cf_pool_s = (f"{self.cf_pool_hits}/{cf_pool_total}"
                     if cf_pool_total else "n/a")
        return (f"total={self.connections_total} "
                f"active={self.connections_active} "
                f"ws={self.connections_ws} "
                f"tcp_fb={self.connections_tcp_fallback} "
                f"cf={self.connections_cfproxy} "
                f"bad={self.connections_bad} "
                f"masked={self.connections_masked} "
                f"err={self.ws_errors} "
                f"pool={pool_s} "
                f"cf_pool={cf_pool_s} "
                f"up={human_bytes(self.bytes_up)} "
                f"down={human_bytes(self.bytes_down)}")


stats = _Stats()