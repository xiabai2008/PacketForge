# PacketForge

> AI network analysis toolkit + MCP server for **authorized** penetration testing
> 面向**授权**渗透测试的 AI 网络分析工具库 + MCP Server

[![CI](https://github.com/xiabai2008/PacketForge/actions/workflows/ci.yml/badge.svg)](https://github.com/xiabai2008/PacketForge/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

**English** | [中文](#中文文档) · ⭐ [Star it](https://github.com/xiabai2008/PacketForge) if it helps! · 有帮助请点个 Star ⭐

---

## English

### Overview

PacketForge wraps Wireshark capture, cleartext-credential extraction,
threat-intelligence lookups, and Nmap scanning into standard MCP tools that any
AI client (Claude Desktop, Cursor, custom agents) can call.

Form factor: **library + thin MCP adapter**. The core is pure Python with zero
MCP dependency and can be used standalone; the MCP layer is deliberately thin.

### ⚠️ Authorized use only

This is a dual-use tool. Use it **only** against systems you own or are
explicitly authorized to test. Users are responsible for complying with all
applicable laws. See [SECURITY.md](SECURITY.md) for the responsible-use policy
and vulnerability reporting.

### Capabilities

| Module | What it does | Backed by |
|---|---|---|
| Capture & analysis | Live capture (BPF), PCAP/PCAPNG analysis, protocol stats, TCP/UDP stream reassembly, JSON/CSV export | tshark |
| Nmap scanning | SYN/connect/UDP, service/OS detection, NSE scripts (`nmap_nse_scan`), vulnerability scan, structured XML output | nmap |
| Threat intelligence | URLhaus + AbuseIPDB lookups with merged `verdict`, whole-capture IOC scan, pluggable `IntelSource` feeds (incl. optional poxiao IP enrichment) | abuse.ch / AbuseIPDB |
| Credential extraction | HTTP Basic/FTP/Telnet credentials (redacted for the LLM) and HTTP Digest/NTLM auth-scheme exposure | tshark |

Every tool call passes input validation (`core/security.py`) and is recorded in
a SHA-256 hash-chain audit log (`core/audit.py`) with a compliance report.

### Install

```bash
pip install -e ".[dev]"        # development install (pytest/ruff included)
python -m build                # or build sdist/wheel
```

Requirements: Python 3.11+, and external commands `tshark` (Wireshark) and
`nmap`. On Windows, Npcap is additionally required for live capture.

### Run as an MCP server

```bash
python -m mcp_server.server                 # stdio (Claude Desktop / Cursor)
python -m mcp_server.server --transport http --host 0.0.0.0 --port 8000
```

13 tools: `capture_live` (with `save_to`), `analyze_pcap_file`,
`get_protocol_statistics`, `follow_tcp_stream`, `export_packets_json`,
`nmap_port_scan`, `nmap_service_detection`, `nmap_vulnerability_scan`,
`nmap_nse_scan`, `extract_credentials`, `check_ip_threat_intel`,
`scan_capture_for_threats`, `save_audit_report`.

Resources: `network://help`, `audit://report` (live compliance report).
Prompts: `security_audit`, `incident_response`.

### Use as a library

```python
from packetforge.core.audit import AuditLog
from packetforge.core.security import RateLimiter
from packetforge.tools.capture import CaptureTools

audit = AuditLog()
tools = CaptureTools(audit=audit, limiter=RateLimiter())
result = tools.analyze_pcap_file("capture.pcap")
print(result)
```

All tools return a uniform envelope
`{"tool", "status", "data"|"error", "audit_id"}`; large payloads are
truncated for LLM context safety.

### Configuration

| Item | Notes |
|---|---|
| `ThreatIntelInterface(urlhaus_key=..., abuseipdb_key=..., extra_sources=[...])` | URLhaus and AbuseIPDB both need free API keys; missing sources are skipped or degraded, never blocking |
| `AuditLog(path="audit.jsonl")` | Persistent audit chain (JSONL); replay-verified on load, tampered files rejected |
| `RateLimiter(max_calls, window_seconds)` | Nmap throttle (default 10/hour), thread-safe |
| `TsharkInterface(binary=...)` / `NmapInterface(binary=...)` | Custom binary paths |

### Security design

- Input validation: IP/CIDR/FQDN, port ranges, BPF/display-filter hygiene,
  path sandbox (`core/security.py`)
- Command-injection protection: all subprocess calls use `shell=False` with
  list-built argv
- Rate limiting: Nmap scans are throttled per tool call
- Full audit: timestamp + tool + param hash + result summary in a SHA-256
  hash chain, exportable as a compliance report
- Credential redaction: plaintext passwords never reach the LLM
- Privilege checks without auto-elevation

### Testing

```bash
pytest                       # full suite + coverage (>=85% overall, security/audit >=90%)
ruff check packetforge mcp_server tests
ruff format --check packetforge mcp_server tests
```

Integration tests skip automatically when `tshark`/`nmap` are unavailable.
CI runs lint, format, coverage gate, and packaging on Python 3.11-3.13.

### Documentation

- [Design doc](docs/specs/2026-08-10-packetforge-design.md) (Chinese)
- [Implementation plan](docs/plans/2026-08-10-packetforge-implementation.md) (Chinese)
- [Roadmap](ROADMAP.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Code of Conduct](CODE_OF_CONDUCT.md)

### Support the project

If PacketForge helps your authorized testing workflow, please consider giving
it a ⭐ **star** — it helps others discover the project. Issues and PRs are
welcome.

### License

MIT — see [LICENSE](LICENSE).

---

## 中文文档

### 概述

PacketForge 把 Wireshark 抓包、明文凭据提取、威胁情报联动、Nmap 主动扫描封装成
标准化 MCP 工具，供任意 AI 客户端（Claude Desktop、Cursor、自研 Agent）调用。

形态：**工具库 + 薄 MCP 封装**。核心逻辑为纯 Python、零 MCP 依赖，可独立使用；
MCP 层刻意保持轻薄。

### ⚠️ 仅限授权使用

本项目是双用途工具，**只能**用于你拥有或获得明确授权的系统。使用者需自行遵守
适用法律法规。责任边界与漏洞报告流程见 [SECURITY.md](SECURITY.md)。

### 能力模块

| 模块 | 能力 | 底座 |
|---|---|---|
| 抓包与分析 | 实时抓包(BPF)、PCAP/PCAPNG 分析、协议统计、TCP/UDP 流重组、JSON/CSV 导出 | tshark |
| Nmap 主动扫描 | SYN/connect/UDP、服务/OS 指纹、NSE 脚本（`nmap_nse_scan`）、漏洞扫描、结构化 XML 输出 | nmap |
| 威胁情报联动 | URLhaus + AbuseIPDB 查询并合并 `verdict`、整包 IOC 扫描、可插拔 `IntelSource` 情报源（含可选 poxiao IP 富化） | abuse.ch / AbuseIPDB |
| 明文凭据提取 | HTTP Basic/FTP/Telnet 凭据（对 LLM 脱敏）、HTTP Digest/NTLM 认证方案暴露检测 | tshark |

所有工具调用强制经过输入校验（`core/security.py`），并写入 SHA-256 哈希链审计
日志（`core/audit.py`），可输出合规报告。

### 安装

```bash
pip install -e ".[dev]"        # 开发安装（含 pytest/ruff）
python -m build                # 或构建 sdist/wheel
```

依赖：Python 3.11+，外部命令 `tshark`（Wireshark）与 `nmap`；Windows 实时抓包另需
Npcap 驱动。

### 作为 MCP Server 运行

```bash
python -m mcp_server.server                 # stdio（Claude Desktop / Cursor）
python -m mcp_server.server --transport http --host 0.0.0.0 --port 8000
```

13 个工具：`capture_live`（支持 `save_to` 落盘）、`analyze_pcap_file`、
`get_protocol_statistics`、`follow_tcp_stream`、`export_packets_json`、
`nmap_port_scan`、`nmap_service_detection`、`nmap_vulnerability_scan`、
`nmap_nse_scan`、`extract_credentials`、`check_ip_threat_intel`、
`scan_capture_for_threats`、`save_audit_report`。

资源：`network://help`、`audit://report`（实时合规报告）。
提示词：`security_audit`、`incident_response`。

### 作为库直接调用

```python
from packetforge.core.audit import AuditLog
from packetforge.core.security import RateLimiter
from packetforge.tools.capture import CaptureTools

audit = AuditLog()
tools = CaptureTools(audit=audit, limiter=RateLimiter())
result = tools.analyze_pcap_file("capture.pcap")
print(result)
```

所有工具返回统一信封 `{"tool", "status", "data"|"error", "audit_id"}`；
超大输出自动截断以保护 LLM 上下文。

### 配置

| 项 | 说明 |
|---|---|
| `ThreatIntelInterface(urlhaus_key=..., abuseipdb_key=..., extra_sources=[...])` | URLhaus 与 AbuseIPDB 均需免费 API key；未配置的源自动跳过或降级，不阻断主流程 |
| `AuditLog(path="audit.jsonl")` | 审计链持久化（JSONL）；加载自动重放校验，篡改文件拒绝加载 |
| `RateLimiter(max_calls, window_seconds)` | Nmap 限速（默认 10 次/小时），线程安全 |
| `TsharkInterface(binary=...)` / `NmapInterface(binary=...)` | 自定义二进制路径 |

### 安全设计

- 输入校验：IP/CIDR/FQDN、端口范围、BPF/display filter 卫生化、路径沙箱（`core/security.py`）
- 命令注入防护：全部 subprocess 强制 `shell=False`、列表式构建 argv
- 限速：Nmap 每次工具调用强制冷却
- 全审计：时间戳 + 工具名 + 参数哈希 + 结果摘要，SHA-256 哈希链，可导出合规报告
- 凭据脱敏：明文密码不直接回传 LLM
- 检测权限需求但不自动提权

### 测试

```bash
pytest                       # 全量测试 + 覆盖率（整体 ≥85%，security/audit ≥90%）
ruff check packetforge mcp_server tests
ruff format --check packetforge mcp_server tests
```

集成测试在无 `tshark`/`nmap` 时自动跳过；CI（GitHub Actions）在 Python 3.11-3.13
上运行 lint、格式、覆盖率门槛与打包构建。

### 文档

- [设计文档](docs/specs/2026-08-10-packetforge-design.md)
- [实现计划](docs/plans/2026-08-10-packetforge-implementation.md)
- [路线图](ROADMAP.md) · [贡献指南](CONTRIBUTING.md) · [安全政策](SECURITY.md) · [行为准则](CODE_OF_CONDUCT.md)

### 支持项目

如果 PacketForge 对你的授权测试工作有帮助，欢迎点一个 ⭐ **Star**
支持一下，让更多人发现这个项目；也欢迎提 Issue 和 PR。

### 许可证

MIT — 见 [LICENSE](LICENSE)。
