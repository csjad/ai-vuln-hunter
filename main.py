"""AI 自动化漏洞挖掘系统 - 命令行入口。

用法示例：
    python main.py scan example.com --scope example.com,www.example.com
    python main.py scan http://target.local --scope target.local --depth deep
    python main.py scan 192.168.1.10 --scope 192.168.1.0/24 --no-exploit

⚠️ 仅限对已获书面授权的目标使用。未授权扫描属违法行为。
"""
from __future__ import annotations

import argparse
import sys

from config import Settings, SafetyPolicy, settings as default_settings
from core.models import VulnStatus
from core.orchestrator import Orchestrator


def build_settings(args: argparse.Namespace) -> Settings:
    policy = SafetyPolicy(
        allow_exploitation=not args.no_exploit,
        authorized_scope=[s.strip() for s in args.scope.split(",") if s.strip()],
        max_concurrency=args.concurrency,
        rate_limit_qps=args.qps,
        require_oob_verification=not args.no_oob,
    )
    s = Settings(safety=policy, scan_depth=args.depth,
                 learning_enabled=not args.no_learn)
    return s


def cmd_scan(args: argparse.Namespace) -> int:
    settings = build_settings(args)
    orch = Orchestrator(settings)
    print(orch.state_graph())
    print(f"\n守卫策略: {orch.guard.summary()}\n")
    ctx = orch.run(args.target, authorized_scope=settings.safety.authorized_scope)
    # 摘要
    print("\n" + "=" * 60)
    print(f"目标: {ctx.target}")
    print(f"资产数: {len(ctx.surface.assets) if ctx.surface else 0}")
    print(f"候选漏洞: {len(ctx.findings)}")
    print(f"确认漏洞: {len(ctx.confirmed_findings)}")
    print(f"误报剔除: "
          f"{sum(1 for f in ctx.findings if f.status == VulnStatus.FALSE_POSITIVE)}")
    for f in ctx.confirmed_findings:
        print(f"  [{f.severity.value}] {f.title} @ {f.asset.value if f.asset else '?'}")
    print(f"\n报告已生成于: {settings.report_dir}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="ai_vuln_hunter",
        description="AI 自动化漏洞挖掘系统（仅限授权测试）",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="对授权目标执行全自动扫描")
    p_scan.add_argument("target", help="目标域名/IP/URL")
    p_scan.add_argument("--scope", required=True,
                        help="授权范围，逗号分隔（必填，硬约束）")
    p_scan.add_argument("--depth", choices=["quick", "normal", "deep"],
                        default="normal", help="扫描深度")
    p_scan.add_argument("--concurrency", type=int, default=5,
                        help="单目标最大并发")
    p_scan.add_argument("--qps", type=float, default=8.0,
                        help="每秒最大请求数")
    p_scan.add_argument("--no-exploit", action="store_true",
                        help="禁用实际利用，仅检测")
    p_scan.add_argument("--no-oob", action="store_true",
                        help="禁用带外验证")
    p_scan.add_argument("--no-learn", action="store_true",
                        help="禁用学习引擎")
    p_scan.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
