"""漏洞扫描模块：CVE 匹配 + 模式扫描 + 智能 Fuzz。

输入：ScanContext（含 AttackSurface 与向量先验）
输出：向 ctx.findings 追加 Finding 候选项（状态=CANDIDATE）

扫描器只负责"发现候选"，是否真漏洞交由 VerifierModule 判定。
"""
from __future__ import annotations

import itertools
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlencode, urljoin

from config import Settings
from core.models import (
    Asset, Confidence, Finding, ScanContext, Severity, VulnStatus,
)
from knowledge import KnowledgeBase, PayloadStore
from utils import HTTPClient, SafetyGuard
from utils.logger import get_logger

logger = get_logger("scanner")

# 用于 fuzz 的常见测试参数名
_INJECT_PARAMS = [
    "id", "q", "search", "query", "name", "user", "file",
    "url", "redirect", "next", "page", "cmd", "path", "doc",
]

# 智能 payload 种子（按类型）
_PAYLOAD_SEEDS: Dict[str, List[str]] = {
    "sqli": [
        "'", "'--", "' AND SLEEP(5)-- -", "1' OR '1'='1",
        "1 UNION SELECT NULL--", "admin'--",
    ],
    "xss": [
        "<svg/onload=alert(1)>", "\"><script>alert(1)</script>",
        "javascript:alert(1)", "<img src=x onerror=alert(1)>",
    ],
    "ssrf": [
        "http://127.0.0.1", "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd", "dict://127.0.0.1:6379/INFO",
    ],
    "cmd_injection": [
        ";id", "|id", "`id`", "$(id)", ";sleep 5;", "&&id",
    ],
    "path_traversal": [
        "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
        "....//....//etc/passwd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ],
    "open_redirect": [
        "//evil.example.com", "https://evil.example.com",
        "/\\evil.example.com", "javascript:alert(1)",
    ],
}


class ScannerModule:
    """漏洞扫描器：CVE 匹配 + 模式扫描 + 智能 Fuzz。"""

    def __init__(self, settings: Settings, kb: KnowledgeBase,
                 payloads: PayloadStore, http: HTTPClient,
                 guard: SafetyGuard) -> None:
        self.settings = settings
        self.kb = kb
        self.payloads = payloads
        self.http = http
        self.guard = guard
        # 注入种子到 payload 库
        self._seed_payloads()

    def _seed_payloads(self) -> None:
        for vt, seeds in _PAYLOAD_SEEDS.items():
            for p in seeds:
                self.payloads.add(vt, p, vector="query")

    # ── 主入口 ─────────────────────────────────────────────────────
    def run(self, ctx: ScanContext) -> List[Finding]:
        surface = ctx.surface
        if not surface:
            logger.warning("扫描器：攻击面为空，跳过")
            return []
        ctx.log("scanner", "start", {"assets": len(surface.assets)})

        findings: List[Finding] = []
        # 1. CVE 匹配（基于指纹）
        findings += self._scan_cve(ctx)
        # 2. 模式扫描（按先验权重排序）
        findings += self._scan_patterns(ctx)
        # 3. 智能 Fuzz（参数级）
        if self.settings.scan_depth in ("normal", "deep"):
            findings += self._smart_fuzz(ctx)

        ctx.findings.extend(findings)
        ctx.log("scanner", "done", {"candidates": len(findings)})
        logger.info("扫描完成: 产生 %d 个候选漏洞", len(findings))
        return findings

    # ── CVE 匹配 ───────────────────────────────────────────────────
    def _scan_cve(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        surface = ctx.surface
        for asset in surface.assets:
            if asset.type != "url":
                continue
            for component, version in asset.fingerprint.items():
                if version in ("unknown", ""):
                    continue
                cves = self.kb.cve_by_fingerprint(component, version)
                for cve in cves:
                    f = Finding(
                        asset=asset,
                        vuln_type=cve["cve"].lower(),
                        title=cve["name"],
                        severity=Severity.from_cvss(cve.get("cvss", 0)),
                        cvss=cve.get("cvss", 0),
                        confidence=Confidence.MEDIUM,
                        status=VulnStatus.CANDIDATE,
                        cve=cve["cve"],
                        description=cve.get("description", ""),
                        remediation=cve.get("remediation", ""),
                        payload=cve.get("oob_probe"),
                    )
                    f.add_evidence("fingerprint", f"{component}={version}")
                    findings.append(f)
                    ctx.log("scanner", "cve_match", {"cve": cve["cve"]})
        return findings

    # ── 模式扫描：对每个 URL 资产按先验投放 payload ───────────────
    def _scan_patterns(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        surface = ctx.surface
        # 按先验权重排序向量
        vectors = sorted(surface.vector_priors.items(),
                         key=lambda x: x[1], reverse=True)
        url_assets = [a for a in surface.assets if a.type == "url"]
        if not url_assets:
            return findings

        for vuln_type, weight in vectors:
            if weight < 0.15:
                continue
            pattern = self.kb.get_pattern(vuln_type)
            if not pattern:
                continue
            # 取该类型 payload（优先历史命中率高的）
            ranked = self.payloads.ranked(vuln_type, limit=5)
            pload_list = [it["payload"] for it in ranked] or \
                         _PAYLOAD_SEEDS.get(vuln_type, [])[:3]
            for asset in url_assets:
                for payload in pload_list:
                    self.guard.assert_payload_safe(payload)
                    hit = self._probe_pattern(asset, vuln_type, payload, pattern)
                    if hit:
                        findings.append(hit)
                        ctx.log("scanner", "pattern_hit", {
                            "vuln": vuln_type, "url": asset.value,
                        })
        return findings

    def _probe_pattern(self, asset: Asset, vuln_type: str,
                       payload: str, pattern: dict) -> Optional[Finding]:
        url = asset.value
        resp = self.http.get(url, params={"q": payload}, timeout=self.guard.poc_timeout)
        if resp.error:
            self.payloads.record_miss(vuln_type, payload)
            return None
        body = resp.body.lower()
        hit_signals = [s.lower() for s in pattern.get("hit_signals", [])]
        # 命中信号匹配
        if hit_signals and any(sig in body for sig in hit_signals):
            self.payloads.record_hit(vuln_type, payload)
            return Finding(
                asset=asset, vuln_type=vuln_type,
                title=f"{pattern.get('name', vuln_type)} 候选",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                status=VulnStatus.CANDIDATE,
                payload=payload,
                request=f"GET {url}?q={payload}",
                response_snippet=body[:500],
                description=pattern.get("name", ""),
                remediation=pattern.get("remediation", ""),
            )
        # 反射型检测（XSS 等）
        if vuln_type == "xss" and payload.lower() in body:
            self.payloads.record_hit(vuln_type, payload)
            return Finding(
                asset=asset, vuln_type="xss",
                title="反射型 XSS 候选",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                status=VulnStatus.CANDIDATE,
                payload=payload,
                request=f"GET {url}?q={payload}",
                response_snippet=body[:500],
                remediation=pattern.get("remediation", ""),
            )
        self.payloads.record_miss(vuln_type, payload)
        return None

    # ── 智能 Fuzz：参数发现 + 变异 ─────────────────────────────────
    def _smart_fuzz(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        surface = ctx.surface
        for asset in list(surface.assets):
            if asset.type != "url":
                continue
            # 抓取页面发现参数
            params = self._discover_params(asset)
            if not params:
                params = _INJECT_PARAMS[:5]
            # 对每个参数尝试 SQLi/XSS/路径穿越变异
            for param, vt in itertools.product(params[:8],
                                                ("sqli", "xss", "path_traversal")):
                seeds = self.payloads.ranked(vt, limit=3) or \
                        [{"payload": p} for p in _PAYLOAD_SEEDS.get(vt, [])[:3]]
                for item in seeds:
                    payload = item["payload"]
                    self.guard.assert_payload_safe(payload)
                    resp = self.http.get(
                        asset.value, params={param: payload},
                        timeout=self.guard.poc_timeout,
                    )
                    if resp.error:
                        continue
                    hit = self._evaluate_fuzz(asset, param, payload, vt, resp.body)
                    if hit:
                        findings.append(hit)
                        ctx.log("scanner", "fuzz_hit", {
                            "param": param, "vuln": vt,
                        })
        return findings

    def _discover_params(self, asset: Asset) -> List[str]:
        """从页面表单/链接中发现参数名。"""
        resp = self.http.get(asset.value, timeout=10)
        if resp.error:
            return []
        params: List[str] = []
        # 表单 input name
        for m in re.finditer(r'<input[^>]+name=["\']?([^"\'\s>]+)', resp.body, re.I):
            params.append(m.group(1))
        # URL 中的参数
        for m in re.finditer(r'[?&]([a-zA-Z0-9_]+)=', resp.body):
            params.append(m.group(1))
        # 去重保序
        seen, out = set(), []
        for p in params:
            if p not in seen:
                seen.add(p)
                out.append(p)
        return out

    def _evaluate_fuzz(self, asset: Asset, param: str, payload: str,
                       vt: str, body: str) -> Optional[Finding]:
        body_lc = body.lower()
        pattern = self.kb.get_pattern(vt) or {}
        signals = [s.lower() for s in pattern.get("hit_signals", [])]
        if signals and any(s in body_lc for s in signals):
            self.payloads.record_hit(vt, payload)
            return Finding(
                asset=asset, vuln_type=vt,
                title=f"{pattern.get('name', vt)} (参数 {param})",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                status=VulnStatus.CANDIDATE,
                payload=payload,
                request=f"GET {asset.value}?{param}={payload}",
                response_snippet=body[:500],
                remediation=pattern.get("remediation", ""),
            )
        if vt == "xss" and payload.lower() in body_lc:
            self.payloads.record_hit(vt, payload)
            return Finding(
                asset=asset, vuln_type="xss",
                title=f"反射型 XSS (参数 {param})",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                status=VulnStatus.CANDIDATE,
                payload=payload,
                request=f"GET {asset.value}?{param}={payload}",
                response_snippet=body[:500],
                remediation=pattern.get("remediation", ""),
            )
        self.payloads.record_miss(vt, payload)
        return None
