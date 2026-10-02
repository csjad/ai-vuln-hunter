"""中央 AI 编排引擎：状态机驱动全流程，协调各模块，形成学习闭环。

状态机：
    INIT → RECON → SCAN → VERIFY → EXPLOIT(可选) → LEARN → REPORT → DONE

每个状态对应一个模块动作，编排引擎决定：
- 何时进入下一状态
- 何时回退（如扫描无候选则直接 LEARN）
- 异常处理与重试策略
"""
from __future__ import annotations

import time
from enum import Enum
from typing import Optional

from config import Settings
from core.models import ScanContext, VulnStatus
from knowledge import KnowledgeBase, PayloadStore
from modules import (
    LearnerModule, ReconnaissanceModule, ReporterModule,
    ScannerModule, VerifierModule,
)
from utils import CommandRunner, HTTPClient, OOBListener, SafetyGuard
from utils.logger import get_logger

logger = get_logger("orchestrator")


class State(str, Enum):
    INIT = "init"
    RECON = "recon"
    SCAN = "scan"
    VERIFY = "verify"
    EXPLOIT = "exploit"
    LEARN = "learn"
    REPORT = "report"
    DONE = "done"


class Orchestrator:
    """中央编排引擎：装配各模块并按状态机推进。"""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or Settings()
        self.settings.ensure_dirs()
        # 装配依赖
        self.guard = SafetyGuard(self.settings.safety)
        self.kb = KnowledgeBase()
        self.payloads = PayloadStore()
        self.runner = CommandRunner(self.settings.tool_paths)
        self.http = HTTPClient(
            qps=self.guard.rate_limit_qps,
            timeout=self.guard.poc_timeout,
        )
        self.oob: Optional[OOBListener] = None
        if self.settings.safety.require_oob_verification:
            self.oob = OOBListener()
        # 装配模块
        self.recon = ReconnaissanceModule(
            self.settings, self.kb, self.runner, self.http, self.guard)
        self.scanner = ScannerModule(
            self.settings, self.kb, self.payloads, self.http, self.guard)
        self.verifier = VerifierModule(
            self.settings, self.kb, self.http, self.guard, self.oob)
        self.learner = LearnerModule(
            self.settings, self.kb, self.payloads)
        self.reporter = ReporterModule(self.settings)

    # ── 主流程 ─────────────────────────────────────────────────────
    def run(self, target: str, authorized_scope: Optional[list] = None) -> ScanContext:
        ctx = ScanContext(
            target=target,
            authorized_scope=authorized_scope or self.settings.safety.authorized_scope,
        )
        logger.info("=== 编排启动 === 目标=%s 守卫=%s", target, self.guard.summary())
        state = State.INIT
        try:
            if self.oob:
                self.oob.start()
            while state != State.DONE:
                state = self._step(state, ctx)
        except Exception as e:
            logger.error("编排异常: %s", e, exc_info=True)
            ctx.log("orchestrator", "error", {"state": state.value, "err": str(e)})
        finally:
            if self.oob:
                self.oob.stop()
            ctx.finished_at = time.time()
        logger.info("=== 编排结束 === 确认漏洞=%d 误报=%d",
                    len(ctx.confirmed_findings),
                    sum(1 for f in ctx.findings
                        if f.status == VulnStatus.FALSE_POSITIVE))
        return ctx

    # ── 状态转移 ───────────────────────────────────────────────────
    def _step(self, state: State, ctx: ScanContext) -> State:
        if state == State.INIT:
            ctx.log("orchestrator", "state", {"state": "INIT"})
            return State.RECON

        if state == State.RECON:
            logger.info("[状态] 侦察")
            self.recon.run(ctx)
            return State.SCAN

        if state == State.SCAN:
            logger.info("[状态] 扫描")
            self.scanner.run(ctx)
            candidates = [f for f in ctx.findings
                          if f.status == VulnStatus.CANDIDATE]
            if not candidates:
                logger.info("无候选漏洞，跳过验证直接进入学习")
                return State.LEARN
            return State.VERIFY

        if state == State.VERIFY:
            logger.info("[状态] 验证")
            self.verifier.run(ctx)
            return State.EXPLOIT if self.settings.safety.allow_exploitation \
                else State.LEARN

        if state == State.EXPLOIT:
            logger.info("[状态] 利用取证（仅确认项）")
            for f in ctx.confirmed_findings:
                try:
                    self.verifier.attempt_exploit(f, ctx)
                except Exception as e:
                    logger.warning("利用尝试异常 %s: %s", f.id, e)
            return State.LEARN

        if state == State.LEARN:
            logger.info("[状态] 学习")
            self.learner.run(ctx)
            suggestions = self.learner.feedback_to_orchestrator(ctx)
            if suggestions:
                ctx.log("orchestrator", "feedback", suggestions)
                logger.info("策略反馈: %s", suggestions)
            return State.REPORT

        if state == State.REPORT:
            logger.info("[状态] 报告")
            self.reporter.run(ctx)
            return State.DONE

        return State.DONE

    # ── 状态机可视化（调试用）──────────────────────────────────────
    @staticmethod
    def state_graph() -> str:
        return (
            "INIT → RECON → SCAN "
            "→[有候选] VERIFY → EXPLOIT → LEARN → REPORT → DONE\n"
            "      ↘[无候选]────────────── LEARN → REPORT → DONE"
        )
