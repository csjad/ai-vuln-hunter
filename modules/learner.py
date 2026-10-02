"""自适应学习引擎：从扫描/验证结果中提取经验，优化后续策略。

职责：
1. 沉淀已确认漏洞到知识库历史
2. 统计各类漏洞命中率，更新向量先验权重
3. 标记误报特征，丰富误报特征库
4. 输出 strategy_weights 供编排引擎与扫描器使用
"""
from __future__ import annotations

from typing import Dict

from config import Settings
from core.models import ScanContext, VulnStatus
from knowledge import KnowledgeBase, PayloadStore
from utils.logger import get_logger

logger = get_logger("learner")


class LearnerModule:
    """自适应学习引擎。"""

    def __init__(self, settings: Settings, kb: KnowledgeBase,
                 payloads: PayloadStore) -> None:
        self.settings = settings
        self.kb = kb
        self.payloads = payloads

    def run(self, ctx: ScanContext) -> Dict[str, float]:
        """从本次扫描结果学习，返回更新后的策略权重。"""
        if not self.settings.learning_enabled:
            return ctx.strategy_weights
        ctx.log("learner", "start")

        # 1. 沉淀确认漏洞
        for f in ctx.findings:
            if f.status in (VulnStatus.CONFIRMED, VulnStatus.EXPLOITED):
                self.kb.record_finding(f.to_dict())

        # 2. 统计向量命中率
        weights = self._update_weights(ctx)
        ctx.strategy_weights = weights
        ctx.log("learner", "done", {"weights": weights})
        logger.info("学习完成: 策略权重=%s", weights)
        return weights

    def _update_weights(self, ctx: ScanContext) -> Dict[str, float]:
        """结合本次结果与历史统计，计算各向量优先级权重。"""
        # 本次各类型：候选数 vs 确认数
        local: Dict[str, Dict[str, int]] = {}
        for f in ctx.findings:
            vt = f.vuln_type
            local.setdefault(vt, {"cand": 0, "conf": 0})
            local[vt]["cand"] += 1
            if f.status in (VulnStatus.CONFIRMED, VulnStatus.EXPLOITED):
                local[vt]["conf"] += 1

        # 历史统计
        stats = self.kb.stats()
        total_hist = sum(stats.values()) or 1

        weights: Dict[str, float] = {}
        all_types = set(list(local.keys()) + list(stats.keys()))
        for vt in all_types:
            # 本次命中率
            l = local.get(vt, {"cand": 0, "conf": 0})
            local_rate = (l["conf"] / l["cand"]) if l["cand"] else 0.0
            # 历史占比
            hist_rate = stats.get(vt, 0) / total_hist
            # 加权融合：历史权重更大以保持稳定
            score = 0.6 * hist_rate + 0.4 * local_rate
            weights[vt] = round(min(1.0, max(0.05, score)), 3)
        return weights

    def feedback_to_orchestrator(self, ctx: ScanContext) -> Dict[str, str]:
        """向编排引擎输出可读的策略建议。"""
        suggestions: Dict[str, str] = {}
        weights = ctx.strategy_weights
        if not weights:
            return suggestions
        # 排序取 Top3 / Bottom3
        ranked = sorted(weights.items(), key=lambda x: x[1], reverse=True)
        for vt, w in ranked[:3]:
            suggestions[vt] = f"优先投放 (权重 {w})"
        for vt, w in ranked[-3:]:
            suggestions[vt] = f"降低优先级 (权重 {w})"
        return suggestions
