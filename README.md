# PacketForge

> AI 网络分析工具库 + MCP Server，面向**授权**渗透测试
> AI network analysis tool library + MCP server for **authorized** penetration testing

[![CI](https://github.com/xiabai2008/PacketForge/actions/workflows/ci.yml/badge.svg)](https://github.com/xiabai2008/PacketForge/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

把 Wireshark 抓包、明文凭据提取、威胁情报联动、Nmap 主动扫描封装成标准化 MCP 工具，
供任意 AI 客户端调用，增强 Agent 的渗透测试能力。

Wraps Wireshark capture, cleartext-credential extraction, threat-intelligence
lookups, and Nmap scanning into standard MCP tools for AI agents.

形态：**工具库 + MCP 封装**。核心逻辑零 MCP 依赖，可独立迭代；MCP 层保持薄。
Form factor: **library + MCP adapter**. The core is pure Python with zero MCP
dependency; the MCP layer stays thin.

## ⚠️ 授权使用 / Authorized Use Only

本项目是双用途（dual-use）工具，**只能**用于你拥有或获得明确授权的系统。
本项目的使用由使用者自行遵守适用法律法规；开发者对滥用不承担任何责任。
See [SECURITY.md](SECURITY.md) for responsible-use policy.

## 能力模块 / Capabilities

| 模块 | 能力 | 底座 |
|---|---|---|
| 抓包与分析 Capture | 实时抓包(BPF)、PCAP/PCAPNG 分析、协议统计、TCP/UDP 流重组、JSON/CSV 导出 | tshark |
| Nmap 主动扫描 | SYN/connect/UDP、服务版本、OS 指纹、NSE 脚本 | nmap |
| 威胁情报联动 | URLhaus 查恶意 IP、整包威胁扫描（优雅降级） | URLhaus API |
| 明文凭据提取 | HTTP Basic Auth / FTP / Telnet 凭据（对 LLM 脱敏） | tshark |

## 安装 / Install

```
pip install -e ".[dev]"        # 开发安装（含 pytest/ruff）
python -m build                # 或构建 sdist/wheel
```

依赖：Python 3.11+，以及外部命令 `tshark`（Wireshark）与 `nmap`（Windows 下另需 Npcap 驱动）。

## 作为 MCP Server 运行 / Run as MCP Server

```
python -m mcp_server.server
# 在 Claude Desktop / Cursor 的 MCP 配置中指向该命令
```

注册的工具（10 个）：`capture_live`、`analyze_pcap_file`、`get_protocol_statistics`、
`follow_tcp_stream`、`export_packets_json`、`nmap_port_scan`、`nmap_service_detection`、
`extract_credentials`、`check_ip_threat_intel`、`scan_capture_for_threats`。
另有资源 `network://help` 与提示词 `security_audit` / `incident_response`。

## 作为库直接调用 / Use as a Library

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
审计链可用 `audit.report()` 输出合规报告（含篡改校验结果）。

## 配置 / Configuration

| 项 | 说明 |
|---|---|
| `ThreatIntelInterface(urlhaus_key=...)` | URLhaus API 现已强制 Auth-Key（免费申请：abuse.ch Authentication Portal）。未配置时查询自动降级为 `degraded`，不阻断主流程 |
| `RateLimiter(max_calls, window_seconds)` | Nmap 限速（默认 10 次/小时），可调 |
| `TsharkInterface(binary=...)` / `NmapInterface(binary=...)` | 自定义二进制路径 |

## 安全设计 / Security Design

- 输入校验：IP/CIDR/FQDN、端口范围、BPF/display filter 卫生化、路径沙箱（`core/security.py`）
- 命令注入防护：全部 subprocess 强制 `shell=False`、列表式构建
- 限速：Nmap 每工具调用强制冷却
- 全审计：每次操作记录时间戳 + 工具名 + 参数哈希 + 结果摘要，SHA-256 哈希链（`core/audit.py`），可输出合规报告
- 凭据脱敏：明文密码不直接回传 LLM，仅报告存在性与用户名
- 检测 root 需求但不自动提权，清晰报错

## 测试 / Testing

```
pytest                       # 全量测试 + 覆盖率（整体 ≥ 85%，security/audit ≥ 90%）
ruff check packetforge mcp_server tests
ruff format --check packetforge mcp_server tests
```

集成测试在无 `tshark`/`nmap` 时自动跳过；CI（GitHub Actions）在 Python 3.11/3.12/3.13
上运行 lint、格式、覆盖率门槛（85%）与打包构建。

## 文档 / Docs

- [设计文档 design](docs/specs/2026-08-10-packetforge-design.md)
- [实现计划 implementation](docs/plans/2026-08-10-packetforge-implementation.md)
- [贡献指南](CONTRIBUTING.md) · [安全政策](SECURITY.md) · [行为准则](CODE_OF_CONDUCT.md)

## 许可证 / License

MIT — see [LICENSE](LICENSE)。
