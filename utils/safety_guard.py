"""安全守卫：授权范围校验、破坏性操作拦截、速率与并发控制。

所有模块在执行可能触及目标的动作前必须经过 SafetyGuard 检查。
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from config import SafetyPolicy


class SafetyViolation(Exception):
    """安全策略违规，必须中止当前动作。"""


class SafetyGuard:
    """硬约束守卫，编排引擎与各模块共享同一实例。"""

    def __init__(self, policy: SafetyPolicy) -> None:
        self.policy = policy

    # ── 授权范围 ───────────────────────────────────────────────────
    def assert_authorized(self, target: str) -> None:
        """校验目标在授权白名单内。白名单为空时视为未配置，禁止执行。

        支持对 URL/IP/域名 形式的目标校验：
        - 先从 target 提取 host（去除 scheme、port、path）
        - host 与 scope 条目精确相等、或为 scope 域名的子域、
          或以 scope IP 前缀开头，则判为授权
        """
        scope: List[str] = self.policy.authorized_scope
        if not scope:
            raise SafetyViolation(
                "授权范围未配置：必须在 SafetyPolicy.authorized_scope 中"
                "显式声明授权目标，禁止扫描未授权对象。"
            )
        host = self._extract_host(target)
        for entry in scope:
            entry_lc = entry.lower().strip()
            if not entry_lc:
                continue
            # 精确匹配
            if host == entry_lc:
                return
            # 子域匹配：host == sub.example.com, entry == example.com
            if host.endswith("." + entry_lc):
                return
            # IP 前缀匹配（如 scope=192.168.1，host=192.168.1.10）
            if _is_ip_like(entry_lc) and _is_ip_like(host) \
               and host.startswith(entry_lc):
                return
        raise SafetyViolation(
            f"目标 {target} (host={host}) 不在授权范围 {scope} 内，已拦截。"
        )

    @staticmethod
    def _extract_host(target: str) -> str:
        """从 URL/IP/域名 中提取 host，去除 scheme、port、path。"""
        t = target.strip()
        if "://" in t:
            parsed = urlparse(t)
            return (parsed.hostname or "").lower()
        # 无 scheme：去除 path/port
        t = t.split("/")[0]
        t = t.split(":")[0]
        return t.lower()

    # ── 破坏性操作拦截 ─────────────────────────────────────────────
    def assert_payload_safe(self, payload: str) -> None:
        pl = payload.lower()
        for forbidden in self.policy.forbidden_actions:
            if forbidden in pl:
                raise SafetyViolation(
                    f"Payload 包含禁止的破坏性操作 '{forbidden}'，已拦截。"
                )

    def assert_action_allowed(self, action: str) -> None:
        """校验是否允许进入利用阶段。"""
        if action in ("exploit", "exfiltrate") and not self.policy.allow_exploitation:
            raise SafetyViolation(
                "当前策略禁止实际利用 (allow_exploitation=False)，仅允许检测。"
            )

    # ── 速率与并发 ─────────────────────────────────────────────────
    @property
    def max_concurrency(self) -> int:
        return self.policy.max_concurrency

    @property
    def rate_limit_qps(self) -> float:
        return self.policy.rate_limit_qps

    @property
    def poc_timeout(self) -> int:
        return self.policy.poc_timeout

    def summary(self) -> str:
        return (
            f"SafetyGuard(allow_exploit={self.policy.allow_exploitation}, "
            f"qps={self.policy.rate_limit_qps}, "
            f"scope={len(self.policy.authorized_scope)} entries)"
        )


def _is_ip_like(s: str) -> bool:
    """粗略判断是否为 IP 地址片段（含数字与点）。"""
    return bool(s) and all(c.isdigit() or c == "." for c in s) and "." in s
