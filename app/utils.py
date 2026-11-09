import threading
import time
from collections import defaultdict, deque

from fastapi import Request


def client_ip(request: Request) -> str | None:
    # Nếu chạy sau reverse proxy, cấu hình uvicorn --proxy-headers và FORWARDED_ALLOW_IPS
    # để request.client.host phản ánh IP thật (chỉ tin header từ proxy tin cậy).
    return request.client.host if request.client else None


class RateLimiter:
    """Giới hạn tần suất trong bộ nhớ (sliding window). Đủ cho 1 tiến trình;
    nhiều instance thì nên chuyển sang Redis hoặc rate limit ở reverse proxy."""

    def __init__(self) -> None:
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 10000:
                for k in [k for k, v in self._hits.items() if not v or v[-1] <= now - window_seconds]:
                    del self._hits[k]
            dq = self._hits[key]
            while dq and dq[0] <= now - window_seconds:
                dq.popleft()
            if len(dq) >= limit:
                return False
            dq.append(now)
            return True
