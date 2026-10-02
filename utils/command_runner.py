"""外部工具命令执行器：Nmap / Subfinder / httpx / Nuclei 等。

统一封装：查找二进制、构造命令、超时、解析输出。工具缺失时优雅降级
并返回空结果而非崩溃，便于在无工具环境下走纯 HTTP 检测路径。
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from .logger import get_logger

logger = get_logger("command_runner")


class CommandRunner:
    """外部安全工具的统一调用入口。"""

    def __init__(self, tool_paths: Optional[Dict[str, Optional[str]]] = None) -> None:
        self.tool_paths = tool_paths or {}

    def _resolve(self, tool: str) -> Optional[str]:
        path = self.tool_paths.get(tool) or shutil.which(tool)
        if not path:
            logger.warning("工具未安装或未在 PATH 中: %s，跳过相关检测", tool)
        return path

    def _run(self, args: List[str], timeout: int = 120) -> Optional[str]:
        try:
            proc = subprocess.run(
                args, capture_output=True, text=True,
                timeout=timeout, check=False, errors="replace",
            )
            if proc.returncode != 0 and proc.stderr:
                logger.debug("命令返回非零: %s | stderr: %s",
                             " ".join(args[:3]), proc.stderr[:200])
            return proc.stdout
        except subprocess.TimeoutExpired:
            logger.warning("命令超时: %s", " ".join(args[:3]))
            return None
        except FileNotFoundError:
            return None

    # ── 子域名发现 ─────────────────────────────────────────────────
    def subfinder(self, domain: str, timeout: int = 120) -> List[str]:
        exe = self._resolve("subfinder")
        if not exe:
            return []
        out = self._run([exe, "-d", domain, "-silent"], timeout=timeout)
        if not out:
            return []
        return [line.strip() for line in out.splitlines() if line.strip()]

    # ── HTTP 探活 ──────────────────────────────────────────────────
    def httpx(self, hosts: List[str], timeout: int = 120) -> List[Dict[str, Any]]:
        exe = self._resolve("httpx")
        if not exe or not hosts:
            return []
        out = self._run(
            [exe, "-json", "-silent", "-title", "-tech-detect",
             "-status-code"] + hosts,
            timeout=timeout,
        )
        results: List[Dict[str, Any]] = []
        if not out:
            return results
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results

    # ── 端口扫描 ───────────────────────────────────────────────────
    def nmap(self, target: str, ports: str = "top-1000",
             timeout: int = 300) -> str:
        exe = self._resolve("nmap")
        if not exe:
            return ""
        args = [exe, "-sV", "-T4"]
        if ports == "top-1000":
            args.append("--top-ports")
            args.append("1000")
        else:
            args += ["-p", ports]
        args.append(target)
        return self._run(args, timeout=timeout) or ""

    # ── Nuclei 模板扫描 ────────────────────────────────────────────
    def nuclei(self, url: str, severity: str = "low,medium,high,critical",
               timeout: int = 600) -> List[Dict[str, Any]]:
        exe = self._resolve("nuclei")
        if not exe:
            return []
        out = self._run(
            [exe, "-u", url, "-json", "-silent",
             "-severity", severity],
            timeout=timeout,
        )
        results: List[Dict[str, Any]] = []
        if not out:
            return results
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results
