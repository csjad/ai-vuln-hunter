"""核心数据模型：贯穿全流程的统一数据结构。"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0:
            return cls.LOW
        return cls.INFO


class Confidence(str, Enum):
    """检测置信度，用于误报过滤决策。"""

    LOW = "low"        # 仅单一信号
    MEDIUM = "medium"  # 多信号但未验证
    HIGH = "high"      # 已 PoC 复现
    VERIFIED = "verified"  # 已实际利用取证


class VulnStatus(str, Enum):
    CANDIDATE = "candidate"      # 扫描发现待验证
    FALSE_POSITIVE = "false_positive"
    CONFIRMED = "confirmed"      # 已验证可利用
    EXPLOITED = "exploited"      # 已取得利用证据
    FAILED = "failed"            # 验证失败/不可利用


@dataclass
class Asset:
    """识别到的单个资产。"""

    type: str  # domain / ip / url / service
    value: str
    port: Optional[int] = None
    service: Optional[str] = None  # http / ssh / mysql ...
    banner: Optional[str] = None
    fingerprint: Dict[str, str] = field(default_factory=dict)  # {component: version}
    tags: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.type}:{self.value}:{self.port or ''}"


@dataclass
class AttackSurface:
    """目标的攻击面汇总。"""

    target: str
    assets: List[Asset] = field(default_factory=list)
    # 按漏洞类别给出先验权重，例如 {"sqli": 0.7, "xss": 0.5}
    vector_priors: Dict[str, float] = field(default_factory=dict)

    def add(self, asset: Asset) -> None:
        # 去重合并
        existing = {a.key for a in self.assets}
        if asset.key not in existing:
            self.assets.append(asset)


@dataclass
class Finding:
    """单个漏洞发现（候选项）。"""

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    asset: Optional[Asset] = None
    vuln_type: str = ""           # sqli / xss / ssrf / cve-xxxx / ...
    title: str = ""
    severity: Severity = Severity.INFO
    cvss: float = 0.0
    confidence: Confidence = Confidence.LOW
    status: VulnStatus = VulnStatus.CANDIDATE
    evidence: List[str] = field(default_factory=list)  # 原始证据片段
    payload: Optional[str] = None
    request: Optional[str] = None
    response_snippet: Optional[str] = None
    oob_hit: bool = False         # 是否有带外回连命中
    cve: Optional[str] = None
    description: str = ""
    remediation: str = ""
    created_at: float = field(default_factory=time.time)
    verified_at: Optional[float] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    def add_evidence(self, label: str, content: str) -> None:
        self.evidence.append(f"[{label}] {content}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "asset": self.asset.key if self.asset else None,
            "vuln_type": self.vuln_type,
            "title": self.title,
            "severity": self.severity.value,
            "cvss": self.cvss,
            "confidence": self.confidence.value,
            "status": self.status.value,
            "evidence": self.evidence,
            "payload": self.payload,
            "cve": self.cve,
            "description": self.description,
            "remediation": self.remediation,
            "created_at": self.created_at,
            "verified_at": self.verified_at,
        }


@dataclass
class ScanContext:
    """单次扫描任务的上下文，贯穿编排全流程。"""

    target: str
    authorized_scope: List[str] = field(default_factory=list)
    surface: Optional[AttackSurface] = None
    findings: List[Finding] = field(default_factory=list)
    # 学习引擎产出的策略权重，供扫描器使用
    strategy_weights: Dict[str, float] = field(default_factory=dict)
    # 执行审计日志
    audit_log: List[Dict[str, Any]] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None

    def log(self, module: str, action: str, detail: Any = None) -> None:
        self.audit_log.append({
            "t": time.time(),
            "module": module,
            "action": action,
            "detail": detail,
        })

    @property
    def confirmed_findings(self) -> List[Finding]:
        return [f for f in self.findings
                if f.status in (VulnStatus.CONFIRMED, VulnStatus.EXPLOITED)]
