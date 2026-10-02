"""带外（OOB）回调监听器：用于 SSRF / 盲注 / Log4Shell 等的误报过滤。

提供轻量内置实现：启动一个本地 HTTP 监听端口，记录被触发的回调标签。
真实环境可替换为 interactsh / Burp Collaborator 等外部服务。

用法：
    listener = OOBListener(host="127.0.0.1", port=9999)
    listener.start()
    tag = listener.new_tag("ssrf")
    url = f"http://127.0.0.1:9999/{tag}"
    # ... 触发请求 ...
    hit = listener.wait_hit(tag, timeout=10)
    listener.stop()
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional

from .logger import get_logger

logger = get_logger("oob_listener")


@dataclass
class OOBHit:
    tag: str
    src_ip: str
    path: str
    timestamp: float


class _Handler(BaseHTTPRequestHandler):
    """记录所有入站请求到共享 registry。"""

    def do_GET(self):  # noqa: N802
        self._record()

    def do_POST(self):  # noqa: N802
        self._record()

    def _record(self):
        listener: "OOBListener" = self.server.listener  # type: ignore[attr-defined]
        path = self.path
        # tag 取路径首段
        tag = path.strip("/").split("/")[0] or path
        hit = OOBHit(
            tag=tag,
            src_ip=self.client_address[0],
            path=path,
            timestamp=time.time(),
        )
        listener._register(hit)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):  # 静默
        pass


class OOBListener:
    """内置 OOB 回调接收器。"""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        # port=0 让系统自动分配可用端口
        self._port = port
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._hits: Dict[str, OOBHit] = {}
        self._lock = threading.Lock()

    @property
    def port(self) -> int:
        return self._port

    @property
    def endpoint(self) -> str:
        return f"http://{self.host}:{self._port}"

    def start(self) -> None:
        self._server = ThreadingHTTPServer((self.host, self._port), _Handler)
        self._server.listener = self  # type: ignore[attr-defined]
        self._port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()
        logger.info("OOB 监听器已启动: %s", self.endpoint)

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def new_tag(self, category: str = "x") -> str:
        """生成唯一回调标签，同时作为 URL 路径段。"""
        return f"{category}-{secrets.token_hex(4)}"

    def callback_url(self, tag: str) -> str:
        return f"{self.endpoint}/{tag}"

    def _register(self, hit: OOBHit) -> None:
        with self._lock:
            self._hits[hit.tag] = hit
        logger.info("OOB 回调命中: tag=%s src=%s", hit.tag, hit.src_ip)

    def wait_hit(self, tag: str, timeout: float = 10.0) -> Optional[OOBHit]:
        """轮询等待指定 tag 的回调命中。"""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if tag in self._hits:
                    return self._hits[tag]
            time.sleep(0.3)
        return None

    def has_hit(self, tag: str) -> bool:
        with self._lock:
            return tag in self._hits
