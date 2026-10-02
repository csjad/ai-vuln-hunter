"""报告生成模块：结构化输出 Markdown / HTML / JSON。

含漏洞去重、按严重度排序、风险评分汇总、修复建议聚合。
"""
from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from config import Settings
from core.models import Finding, ScanContext, Severity, VulnStatus
from utils.logger import get_logger

logger = get_logger("reporter")

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0, Severity.HIGH: 1,
    Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4,
}
_SEVERITY_LABEL = {
    Severity.CRITICAL: "严重", Severity.HIGH: "高危",
    Severity.MEDIUM: "中危", Severity.LOW: "低危", Severity.INFO: "信息",
}


class ReporterModule:
    """报告生成器。"""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def run(self, ctx: ScanContext) -> Path:
        findings = self._dedupe(ctx.findings)
        findings = self._sort(findings)
        md = self._to_markdown(ctx, findings)
        json_doc = self._to_json(ctx, findings)
        html_doc = self._to_html(ctx, findings)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = "".join(c if c.isalnum() else "_" for c in ctx.target)[:40]
        base = self.settings.report_dir / f"report_{safe_target}_{ts}"
        md_path = base.with_suffix(".md")
        json_path = base.with_suffix(".json")
        html_path = base.with_suffix(".html")
        md_path.write_text(md, encoding="utf-8")
        json_path.write_text(json_doc, encoding="utf-8")
        html_path.write_text(html_doc, encoding="utf-8")
        ctx.log("reporter", "done", {
            "md": str(md_path), "json": str(json_path), "html": str(html_path),
        })
        logger.info("报告已生成: %s", md_path)
        return md_path

    # ── 去重：同资产同漏洞类型合并 ─────────────────────────────────
    def _dedupe(self, findings: List[Finding]) -> List[Finding]:
        seen: Dict[str, Finding] = {}
        for f in findings:
            if f.status == VulnStatus.FALSE_POSITIVE:
                continue
            key = f"{f.asset.key if f.asset else 'none'}::{f.vuln_type}"
            if key in seen:
                # 保留置信度更高的
                if _confidence_rank(f.confidence) > _confidence_rank(seen[key].confidence):
                    seen[key] = f
                # 合并证据
                seen[key].evidence.extend(f.evidence)
            else:
                seen[key] = f
        return list(seen.values())

    def _sort(self, findings: List[Finding]) -> List[Finding]:
        return sorted(findings,
                      key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9),
                                     -f.cvss))

    # ── Markdown ───────────────────────────────────────────────────
    def _to_markdown(self, ctx: ScanContext, findings: List[Finding]) -> str:
        lines: List[str] = []
        lines.append(f"# 安全漏洞扫描报告")
        lines.append("")
        lines.append(f"- **目标**: `{ctx.target}`")
        lines.append(f"- **扫描时间**: {datetime.fromtimestamp(ctx.started_at)}")
        lines.append(f"- **资产数量**: {len(ctx.surface.assets) if ctx.surface else 0}")
        confirmed = [f for f in findings
                     if f.status in (VulnStatus.CONFIRMED, VulnStatus.EXPLOITED)]
        lines.append(f"- **确认漏洞**: {len(confirmed)} 个")
        lines.append(f"- **误报剔除**: "
                     f"{sum(1 for f in ctx.findings if f.status == VulnStatus.FALSE_POSITIVE)} 个")
        lines.append("")
        lines.append("## 风险概览")
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                    Severity.LOW, Severity.INFO):
            cnt = sum(1 for f in confirmed if f.severity == sev)
            if cnt:
                lines.append(f"- {_SEVERITY_LABEL[sev]}: {cnt}")
        lines.append("")

        if not confirmed:
            lines.append("## 结论")
            lines.append("本次扫描未发现可确认漏洞。")
            return "\n".join(lines)

        lines.append("## 漏洞详情")
        for i, f in enumerate(confirmed, 1):
            lines.append(f"### {i}. [{_SEVERITY_LABEL[f.severity]}] {f.title}")
            lines.append("")
            lines.append(f"- **类型**: `{f.vuln_type}`")
            if f.cve:
                lines.append(f"- **CVE**: {f.cve}")
            lines.append(f"- **CVSS**: {f.cvss}")
            lines.append(f"- **资产**: `{f.asset.value if f.asset else 'N/A'}`")
            lines.append(f"- **置信度**: {f.confidence.value}")
            lines.append(f"- **状态**: {f.status.value}")
            if f.payload:
                lines.append(f"- **Payload**: `{f.payload}`")
            if f.description:
                lines.append(f"- **描述**: {f.description}")
            if f.evidence:
                lines.append("- **证据**:")
                for ev in f.evidence[:5]:
                    lines.append(f"  - {ev}")
            if f.remediation:
                lines.append(f"- **修复建议**: {f.remediation}")
            lines.append("")
        lines.append("---")
        lines.append("*本报告由 AI 自动化漏洞挖掘系统生成，仅供授权测试使用。*")
        return "\n".join(lines)

    # ── JSON ───────────────────────────────────────────────────────
    def _to_json(self, ctx: ScanContext, findings: List[Finding]) -> str:
        return json.dumps({
            "target": ctx.target,
            "started_at": ctx.started_at,
            "finished_at": ctx.finished_at,
            "assets": [
                {
                    "value": a.value, "type": a.type,
                    "fingerprint": a.fingerprint, "port": a.port,
                } for a in (ctx.surface.assets if ctx.surface else [])
            ],
            "findings": [f.to_dict() for f in findings],
            "stats": {
                "total_candidates": len(ctx.findings),
                "confirmed": len([f for f in findings
                                  if f.status in (VulnStatus.CONFIRMED,
                                                  VulnStatus.EXPLOITED)]),
                "false_positives": len([f for f in ctx.findings
                                        if f.status == VulnStatus.FALSE_POSITIVE]),
            },
        }, ensure_ascii=False, indent=2)

    # ── HTML ───────────────────────────────────────────────────────
    def _to_html(self, ctx: ScanContext, findings: List[Finding]) -> str:
        confirmed = [f for f in findings
                     if f.status in (VulnStatus.CONFIRMED, VulnStatus.EXPLOITED)]
        rows = []
        for f in confirmed:
            rows.append(
                f"<tr>"
                f"<td>{html.escape(_SEVERITY_LABEL[f.severity])}</td>"
                f"<td>{html.escape(f.title)}</td>"
                f"<td><code>{html.escape(f.vuln_type)}</code></td>"
                f"<td>{html.escape(f.asset.value if f.asset else '')}</td>"
                f"<td>{f.cvss}</td>"
                f"<td>{html.escape(f.confidence.value)}</td>"
                f"<td>{html.escape(f.remediation[:80])}</td>"
                f"</tr>"
            )
        return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>漏洞扫描报告 - {html.escape(ctx.target)}</title>
<style>
body {{ font-family: -apple-system, "Segoe UI", sans-serif; margin: 40px; color: #1a1d29; }}
h1 {{ color: #6366f1; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
th, td {{ border: 1px solid #e5e7eb; padding: 8px 12px; text-align: left; font-size: 14px; }}
th {{ background: #f5f6fa; }}
.meta {{ color: #6b7280; margin: 8px 0; }}
</style></head><body>
<h1>安全漏洞扫描报告</h1>
<p class="meta">目标: <code>{html.escape(ctx.target)}</code></p>
<p class="meta">时间: {datetime.fromtimestamp(ctx.started_at)}</p>
<p class="meta">确认漏洞: <strong>{len(confirmed)}</strong> 个</p>
<table>
<tr><th>严重度</th><th>标题</th><th>类型</th><th>资产</th><th>CVSS</th><th>置信度</th><th>修复建议</th></tr>
{''.join(rows)}
</table>
<p class="meta">本报告由 AI 自动化漏洞挖掘系统生成，仅供授权测试使用。</p>
</body></html>"""


def _confidence_rank(c) -> int:
    return {"low": 0, "medium": 1, "high": 2, "verified": 3}.get(c.value, 0)
