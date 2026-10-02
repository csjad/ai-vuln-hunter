"""漏洞知识库：统一检索 CVE、攻击模式、误报特征、历史发现。

持久化历史发现到磁盘，供学习引擎做跨任务学习。
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import settings
from .patterns import ATTACK_PATTERNS, CVE_DATABASE, FP_SIGNATURES


class KnowledgeBase:
    """聚合各类知识源的只读 + 历史写入接口。"""

    def __init__(self, history_path: Optional[Path] = None) -> None:
        self.history_path = history_path or (settings.kb_dir / "history.json")
        self._lock = threading.Lock()
        self._history: List[Dict[str, Any]] = []
        self._load_history()

    # ── 静态知识检索 ────────────────────────────────────────────────
    def get_pattern(self, vuln_type: str) -> Optional[Dict[str, Any]]:
        return ATTACK_PATTERNS.get(vuln_type)

    def all_patterns(self) -> Dict[str, Dict[str, Any]]:
        return ATTACK_PATTERNS

    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        for item in CVE_DATABASE:
            if item["cve"].upper() == cve_id.upper():
                return item
        return None

    def cve_by_fingerprint(self, component: str, version: str) -> List[Dict[str, Any]]:
        """按指纹匹配受影响的 CVE。"""
        hits: List[Dict[str, Any]] = []
        for cve in CVE_DATABASE:
            for fp in cve.get("fingerprints", []):
                if fp.get("component") != component:
                    continue
                vmax = fp.get("version_max")
                if vmax and _version_le(version, vmax):
                    hits.append(cve)
        return hits

    def fp_signatures(self, vuln_type: Optional[str] = None) -> List[Dict[str, Any]]:
        if vuln_type is None:
            return FP_SIGNATURES
        return [s for s in FP_SIGNATURES if s["vuln_type"] == vuln_type]

    # ── 历史发现（跨任务学习）──────────────────────────────────────
    def _load_history(self) -> None:
        if self.history_path.exists():
            try:
                with self.history_path.open("r", encoding="utf-8") as f:
                    self._history = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._history = []

    def record_finding(self, finding_dict: Dict[str, Any]) -> None:
        with self._lock:
            self._history.append(finding_dict)
            self.history_path.parent.mkdir(parents=True, exist_ok=True)
            with self.history_path.open("w", encoding="utf-8") as f:
                json.dump(self._history, f, ensure_ascii=False, indent=2)

    def history(self, vuln_type: Optional[str] = None) -> List[Dict[str, Any]]:
        if vuln_type is None:
            return list(self._history)
        return [h for h in self._history if h.get("vuln_type") == vuln_type]

    def stats(self) -> Dict[str, int]:
        """统计各漏洞类型历史确认数，供策略调权。"""
        counts: Dict[str, int] = {}
        for h in self._history:
            if h.get("status") in ("confirmed", "exploited"):
                vt = h.get("vuln_type", "unknown")
                counts[vt] = counts.get(vt, 0) + 1
        return counts


def _version_le(v: str, vmax: str) -> bool:
    """简化版本比较：按点分段数值比较。"""
    try:
        a = [int(x) for x in v.split(".")]
        b = [int(x) for x in vmax.split(".")]
    except ValueError:
        return False
    n = max(len(a), len(b))
    a += [0] * (n - len(a))
    b += [0] * (n - len(b))
    return a <= b
