# ai-vuln-hunter · AI 自动化漏洞挖掘系统

面向**已获书面授权**目标的全链路漏洞挖掘引擎：侦察 → 扫描 → 验证 → 利用取证 → 学习 → 报告，由状态机编排引擎驱动，并内置硬约束安全策略层。

> ⚠️ 仅限对已获书面授权的目标使用。未授权扫描属违法行为。

## 架构

```
INIT → RECON → SCAN → VERIFY → EXPLOIT(可选) → LEARN → REPORT → DONE
```

| 模块 | 职责 |
|---|---|
| `modules/reconnaissance` | 子域名发现（subfinder，缺失时内置前缀补全）、技术栈指纹（httpx 或内置客户端 + 启发式）、端口扫描（nmap，缺失跳过），输出攻击面与漏洞向量先验权重 |
| `modules/scanner` | CVE 匹配 + 模式扫描 + 智能 Fuzz，只产出候选 Finding（`CANDIDATE`），判定权交给验证模块 |
| `modules/verifier` | 误报特征库过滤 → payload 二次复现 → OOB 带外回调验证（盲注 / SSRF / Log4Shell）→ 授权范围内最小证据取证；结果置 `CONFIRMED / EXPLOITED / FALSE_POSITIVE / FAILED` |
| `modules/learner` | 确认漏洞沉淀知识库、按命中率更新向量先验权重、扩充误报特征库、输出策略权重回灌编排引擎，形成学习闭环 |
| `modules/reporter` | 漏洞去重、按严重度排序、风险评分汇总、修复建议聚合；输出 Markdown / HTML / JSON |
| `core/orchestrator` | 中央状态机：决定状态推进与回退（如扫描无候选直接 LEARN）、异常处理与重试策略 |
| `knowledge` | 知识库 + 漏洞模式库 + Payload 库 |

## 安全策略层（硬约束）

`SafetyPolicy` 对全部模块生效，不可绕过：

- **授权域白名单**：所有外发流量必须命中 `authorized_scope`（域名 / IP 前缀）
- **破坏性操作拦截**：`rm / drop / delete / shutdown / reboot / format / mkfs / chmod 777 / wget+exec` 等关键词硬拦截
- **速率与并发上限**：单目标默认并发 5、QPS 8，PoC 单发超时 15s
- **OOB 验证开关**：默认强制带外回连验证以降误报

## 快速开始

```bash
pip install -r requirements.txt

# 基础扫描（仅检测不下探）
python main.py scan example.com --scope example.com,www.example.com --no-exploit

# 深度扫描（含利用取证）
python main.py scan http://target.local --scope target.local --depth deep
```

- 外部工具（nmap / subfinder / httpx / nuclei / sqlmap）可选：配置 `tool_paths` 指定二进制路径，缺失时自动降级到内置实现
- LLM 智能 payload 生成可选：设置 `LLM_API_BASE / LLM_API_KEY / LLM_MODEL`，未配置时走内置规则引擎，离线可运行
- 端到端演示：`python tests/demo_target.py`（本地模拟目标）

## 目录结构

```
main.py            CLI 入口
config.py          全局配置与 SafetyPolicy
core/              状态模型 + 编排引擎
modules/           recon / scan / verify / learn / report 五阶段
knowledge/         知识库、模式库、Payload 库
utils/             命令执行、HTTP 客户端、OOB 监听、安全守卫
tests/             演示目标与测试
```
