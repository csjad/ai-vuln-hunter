"""本地演示靶标：含反射型 XSS 与 SQL 注入错误回显。

仅用于本机端到端测试，启动后监听 127.0.0.1:8765。
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/":
            # 反射型 XSS：直接回显 q 参数到页面
            q = params.get("q", ["world"])[0]
            body = (
                f"<html><body><h1>Search: {q}</h1>"
                f"<form><input name='q'><button>go</button></form>"
                f"</body></html>"
            )
            self._send(body)

        elif parsed.path == "/search":
            q = params.get("q", [""])[0]
            # 模拟 SQL 注入错误回显
            if "'" in q:
                body = (
                    "<html><body>SQL syntax error near '"
                    f"{q}' at line 1<br>mysql_query failed</body></html>"
                )
            else:
                body = f"<html><body>results for {q}: no rows</body></html>"
            self._send(body)

        elif parsed.path == "/redirect":
            nxt = params.get("next", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", nxt)
            self.end_headers()

        else:
            self._send("<html><body>404 not found</body></html>", code=404)

    def _send(self, body: str, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Apache/2.4.41")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    print("演示靶标启动: http://127.0.0.1:8765")
    srv.serve_forever()
