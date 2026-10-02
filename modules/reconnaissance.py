"""目标识别模块：资产发现 + 指纹识别 + 攻击面建模。

流程：
1. 输入目标（域名/IP/URL）
2. 子域名发现（subfinder，缺失则用内置常见前缀补全）
3. HTTP 探活与技术栈指纹（httpx 或内置 HTTP 客户端 + 启发式）
4. 端口扫描（nmap，缺失则跳过）
5. 输出 AttackSurface，含资产列表与向量先验权重
"""
from __future__ import annotations

import re
from typing import List, Optional, Set
from urllib.parse import urlparse

from config import Settings
from core.models import Asset, AttackSurface, ScanContext
from knowledge import KnowledgeBase
from utils import CommandRunner, HTTPClient, SafetyGuard
from utils.logger import get_logger

logger = get_logger("recon")

# 内置常见子域前缀，subfinder 不可用时作为兜底
_COMMON_PREFIXES = [
    "www", "api", "admin", "dev", "test", "staging", "mail",
    "vpn", "git", "ci", "jenkins", "grafana", "kibana",
]

# 指纹启发式：header/server/body 关键字 → 组件
_FP_RULES = [
    # (字段, 关键字(小写), 组件, 版本正则)
    ("header:server", "nginx", "nginx", r"nginx/([\d.]+)"),
    ("header:server", "apache", "apache", r"apache/([\d.]+)"),
    ("header:server", "microsoft-iis", "iis", r"microsoft-iis/([\d.]+)"),
    ("header:x-powered-by", "php", "php", r"php/([\d.]+)"),
    ("header:x-powered-by", "asp.net", "asp.net", r"asp\.net"),
    ("header:x-aspnet-version", "asp.net", "asp.net", r"([\d.]+)"),
    ("header:server", "tomcat", "tomcat", r"tomcat/([\d.]+)"),
    ("header:set-cookie", "jsessionid", "java", None),
    ("header:x-generator", "drupal", "drupal", r"drupal\s+([\d.]+)"),
    ("body", "powered by wordpress", "wordpress", None),
    ("body", "joomla", "joomla", None),
    ("header:server", "cowboy", "elixir", None),
    ("header:server", "gunicorn", "python", None),
]


class ReconnaissanceModule:
    """目标识别 / 侦察模块。"""

    def __init__(self, settings: Settings, kb: KnowledgeBase,
                 runner: CommandRunner, http: HTTPClient,
                 guard: SafetyGuard) -> None:
        self.settings = settings
        self.kb = kb
        self.runner = runner
        self.http = http
        self.guard = guard

    def run(self, ctx: ScanContext) -> AttackSurface:
        target = ctx.target
        self.guard.assert_authorized(target)
        ctx.log("recon", "start", {"target": target})
        surface = AttackSurface(target=target)

        # 1. 若目标是带 scheme 的 URL，直接探活该 URL（保留端口）
        probed_urls = set()
        if "://" in target:
            self._probe_url(target, surface, ctx)
            probed_urls.add(_normalize_url(target))

        # 2. 资产发现：子域名 / 同 host 其他资产
        hosts = self._discover_hosts(target)
        ctx.log("recon", "hosts_found", {"count": len(hosts)})

        # 3. HTTP 探活 + 指纹（子域名走默认 80/443）
        for host in hosts:
            self._probe_http(host, surface, ctx, exclude=probed_urls)

        # 4. 端口扫描（可选）
        if self.settings.scan_depth in ("normal", "deep"):
            self._scan_ports(target, surface, ctx)

        # 5. 攻击面建模：根据指纹给出向量先验
        surface.vector_priors = self._build_priors(surface)
        ctx.surface = surface
        ctx.log("recon", "done", {
            "assets": len(surface.assets),
            "vectors": surface.vector_priors,
        })
        logger.info("侦察完成: %d 资产, 向量先验=%s",
                    len(surface.assets), surface.vector_priors)
        return surface

    # ── 资产发现 ───────────────────────────────────────────────────
    def _discover_hosts(self, target: str) -> List[str]:
        # 若是 URL，取 host
        parsed = urlparse(target if "://" in target else f"http://{target}")
        host = parsed.hostname or target
        hosts = [host]

        # IP 直接返回
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            return hosts

        # 子域名发现
        subdomains = self.runner.subfinder(host)
        if not subdomains:
            # 兜底：内置前缀 + DNS 猜测（仅对域名）
            subdomains = []
            for prefix in _COMMON_PREFIXES:
                cand = f"{prefix}.{host}"
                subdomains.append(cand)
            logger.info("subfinder 不可用，使用内置 %d 个前缀兜底",
                        len(_COMMON_PREFIXES))
        # 主域优先，去重
        seen = {host}
        for sd in subdomains:
            if sd not in seen:
                seen.add(sd)
                hosts.append(sd)
        return hosts

    # ── HTTP 探活与指纹 ────────────────────────────────────────────
    def _probe_url(self, url: str, surface: AttackSurface,
                   ctx: ScanContext) -> None:
        """直接探活指定 URL（保留端口），用于目标本身是 URL 的情况。"""
        resp = self.http.get(url, timeout=10, allow_redirects=True)
        if resp.error or resp.status == 0:
            return
        fingerprint = self._fingerprint(resp)
        asset = Asset(
            type="url",
            value=url,
            service="https" if url.startswith("https://") else "http",
            banner=resp.header("Server"),
            fingerprint=fingerprint,
            tags=["live", "target"],
            meta={"status": resp.status, "title": _extract_title(resp.body)},
        )
        surface.add(asset)
        ctx.log("recon", "http_probe", {
            "url": url, "status": resp.status, "fp": fingerprint,
        })

    def _probe_http(self, host: str, surface: AttackSurface,
                    ctx: ScanContext, exclude: Optional[set] = None) -> None:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            if exclude and _normalize_url(url) in exclude:
                continue
            resp = self.http.get(url, timeout=10, allow_redirects=True)
            if resp.error or resp.status == 0:
                continue
            fingerprint = self._fingerprint(resp)
            asset = Asset(
                type="url",
                value=url,
                service="http" if scheme == "http" else "https",
                banner=resp.header("Server"),
                fingerprint=fingerprint,
                tags=["live"],
                meta={"status": resp.status, "title": _extract_title(resp.body)},
            )
            surface.add(asset)
            ctx.log("recon", "http_probe", {
                "url": url, "status": resp.status, "fp": fingerprint,
            })
            break  # 命中一个 scheme 即可

    def _fingerprint(self, resp) -> dict:
        fp: dict = {}
        for field, keyword, component, ver_regex in _FP_RULES:
            value = ""
            if field.startswith("header:"):
                hname = field.split(":", 1)[1]
                value = resp.header(hname) or ""
            elif field == "body":
                value = resp.body
            if keyword in value.lower():
                version = ""
                if ver_regex:
                    m = re.search(ver_regex, value, re.IGNORECASE)
                    if m:
                        version = m.group(1)
                # 同组件只保留第一个命中（通常更准确）
                if component not in fp:
                    fp[component] = version or "unknown"
        return fp

    # ── 端口扫描 ───────────────────────────────────────────────────
    def _scan_ports(self, target: str, surface: AttackSurface,
                    ctx: ScanContext) -> None:
        parsed = urlparse(target if "://" in target else f"http://{target}")
        host = parsed.hostname or target
        out = self.runner.nmap(host, timeout=self.settings.safety.poc_timeout * 20)
        if not out:
            return
        # 简易解析 nmap 文本输出中的开放端口
        for line in out.splitlines():
            m = re.match(
                r"(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?", line.strip()
            )
            if m:
                port = int(m.group(1))
                svc = m.group(2)
                product = m.group(3) or ""
                asset = Asset(
                    type="service",
                    value=host,
                    port=port,
                    service=svc,
                    banner=product,
                )
                surface.add(asset)
                ctx.log("recon", "port_open", {"port": port, "svc": svc})

    # ── 攻击面建模 ─────────────────────────────────────────────────
    def _build_priors(self, surface: AttackSurface) -> dict:
        """基于指纹与历史发现给出各类漏洞的先验权重 [0,1]。"""
        priors: dict = {
            "sqli": 0.3, "xss": 0.4, "ssrf": 0.2,
            "cmd_injection": 0.1, "path_traversal": 0.2,
            "open_redirect": 0.2,
        }
        # 指纹加权
        for asset in surface.assets:
            fp = asset.fingerprint
            if "php" in fp or "asp.net" in fp:
                priors["sqli"] = min(1.0, priors["sqli"] + 0.15)
                priors["xss"] = min(1.0, priors["xss"] + 0.1)
            if "java" in fp or "tomcat" in fp or "struts" in fp:
                priors["cmd_injection"] = min(1.0, priors["cmd_injection"] + 0.2)
            if "nginx" in fp or "apache" in fp:
                priors["path_traversal"] = min(1.0, priors["path_traversal"] + 0.05)
        # 历史发现加权
        stats = self.kb.stats()
        total = sum(stats.values()) or 1
        for vt, cnt in stats.items():
            if vt in priors:
                boost = 0.1 * (cnt / total)
                priors[vt] = min(1.0, priors[vt] + boost)
        return priors


def _extract_title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    return (m.group(1).strip()[:100] if m else "")


def _normalize_url(url: str) -> str:
    """归一化 URL 用于去重：去除尾部斜杠，小写 scheme+host。"""
    p = urlparse(url)
    return f"{p.scheme.lower()}://{p.hostname or ''}{':' + str(p.port) if p.port not in (None, 0) else ''}".rstrip("/")
