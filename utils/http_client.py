"""HTTP 客户端：带速率限制与超时的轻量封装。

优先使用 requests；未安装时回退到 urllib。
"""
from __future__ import annotations

import time
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional
from urllib.parse import urlparse

try:
    import requests  # type: ignore
    _HAS_REQUESTS = True
except ImportError:  # pragma: no cover
    _HAS_REQUESTS = False
    import urllib.request
    import urllib.error


@dataclass
class HttpResponse:
    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed: float = 0.0
    url: str = ""
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def header(self, name: str) -> Optional[str]:
        # 大小写不敏感查 header
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None


class HTTPClient:
    """带速率限制的同步 HTTP 客户端。"""

    def __init__(self, qps: float = 8.0, timeout: int = 15,
                 proxy: Optional[str] = None) -> None:
        self.qps = qps
        self.timeout = timeout
        self.proxy = proxy
        self._min_interval = 1.0 / qps if qps > 0 else 0
        self._last_request = 0.0
        self._lock = threading.Lock()
        self._session = requests.Session() if _HAS_REQUESTS else None
        if self._session and proxy:
            self._session.proxies = {"http": proxy, "https": proxy}

    def _throttle(self) -> None:
        with self._lock:
            now = time.time()
            wait = self._min_interval - (now - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.time()

    def request(self, method: str, url: str, *,
                params: Optional[dict] = None,
                headers: Optional[dict] = None,
                data: Optional[dict] = None,
                json_body: Optional[dict] = None,
                allow_redirects: bool = True,
                timeout: Optional[int] = None) -> HttpResponse:
        self._throttle()
        to = timeout or self.timeout
        if _HAS_REQUESTS:
            try:
                resp = self._session.request(  # type: ignore[union-attr]
                    method, url, params=params, headers=headers,
                    data=data, json=json_body,
                    allow_redirects=allow_redirects, timeout=to,
                )
                return HttpResponse(
                    status=resp.status_code,
                    headers=dict(resp.headers),
                    body=resp.text[:20000],  # 截断防止超大响应
                    elapsed=resp.elapsed.total_seconds(),
                    url=resp.url,
                )
            except requests.RequestException as e:  # type: ignore[attr-defined]
                return HttpResponse(status=0, url=url, error=str(e))
        else:  # urllib 回退
            try:
                full_url = url
                if params:
                    from urllib.parse import urlencode
                    sep = "&" if "?" in url else "?"
                    full_url = f"{url}{sep}{urlencode(params)}"
                req = urllib.request.Request(
                    full_url, method=method,
                    headers=headers or {},
                    data=(data.encode() if isinstance(data, str) else None),
                )
                with urllib.request.urlopen(req, timeout=to) as r:
                    body = r.read().decode("utf-8", errors="replace")[:20000]
                    return HttpResponse(
                        status=r.status,
                        headers=dict(r.headers),
                        body=body,
                        url=full_url,
                    )
            except urllib.error.HTTPError as e:
                body = ""
                try:
                    body = e.read().decode("utf-8", errors="replace")[:20000]
                except Exception:
                    pass
                return HttpResponse(status=e.code, url=url, body=body, error=str(e))
            except urllib.error.URLError as e:
                return HttpResponse(status=0, url=url, error=str(e))

    def get(self, url: str, **kw) -> HttpResponse:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> HttpResponse:
        return self.request("POST", url, **kw)

    @staticmethod
    def host_of(url: str) -> str:
        return urlparse(url).hostname or ""
