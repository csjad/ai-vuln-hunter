"""全局配置：路径、速率、安全边界、工具开关。"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
REPORT_DIR = PROJECT_ROOT / "reports"
KB_DIR = PROJECT_ROOT / "knowledge" / "store"


@dataclass
class SafetyPolicy:
    """安全合规边界，硬约束，所有模块必须遵守。"""

    # 是否允许实际利用（True=可读取证据，False=仅检测不下探）
    allow_exploitation: bool = True
    # 禁止的破坏性操作关键词
    forbidden_actions: List[str] = field(
        default_factory=lambda: [
            "rm", "drop", "delete", "shutdown", "reboot",
            "format", "mkfs", "chmod 777", "wget+exec",
        ]
    )
    # 单目标最大并发请求数
    max_concurrency: int = 5
    # 每秒最大请求数（速率限制）
    rate_limit_qps: float = 8.0
    # 单次 PoC 超时秒
    poc_timeout: int = 15
    # 是否强制带外回连验证（降低误报）
    require_oob_verification: bool = True
    # 授权范围白名单（域名/IP前缀），空表示由调用方传入
    authorized_scope: List[str] = field(default_factory=list)


@dataclass
class Settings:
    """运行时配置。"""

    safety: SafetyPolicy = field(default_factory=SafetyPolicy)
    # 外部工具二进制路径，None 表示使用 PATH 查找
    tool_paths: dict = field(default_factory=lambda: {
        "nmap": None,
        "subfinder": None,
        "httpx": None,
        "nuclei": None,
        "sqlmap": None,
    })
    # LLM 配置（用于智能 payload 生成，留空则走规则引擎）
    llm_enabled: bool = False
    llm_api_base: str = os.getenv("LLM_API_BASE", "")
    llm_api_key: str = os.getenv("LLM_API_KEY", "")
    llm_model: str = os.getenv("LLM_MODEL", "gpt-4o-mini")
    # 数据目录
    data_dir: Path = DATA_DIR
    report_dir: Path = REPORT_DIR
    kb_dir: Path = KB_DIR
    # 扫描深度：quick / normal / deep
    scan_depth: str = "normal"
    # 学习引擎开关
    learning_enabled: bool = True

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.report_dir, self.kb_dir):
            d.mkdir(parents=True, exist_ok=True)


# 默认全局实例
settings = Settings()
settings.ensure_dirs()
