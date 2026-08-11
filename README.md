# PacketForge

> 面向授权渗透测试的 AI 网络分析工具库 + MCP Server

## 定位

把 Wireshark 抓包、明文凭据提取、威胁情报联动、Nmap 主动扫描封装成标准化 MCP 工具，供任意 AI 客户端调用，增强 Agent 的渗透测试能力。

形态：**工具库 + MCP 封装**。核心逻辑零 MCP 依赖，可独立迭代；MCP 层保持薄。

## 能力模块

- 抓包与分析：实时抓包(BPF)、PCAP/PCAPNG 分析、协议统计、TCP/UDP 流重组、JSON/CSV 导出
- Nmap 主动扫描：SYN/connect/UDP、服务版本、OS 指纹、NSE 漏洞脚本（复用 rayscan 底座）
- 威胁情报联动：URLhaus/AbuseIPDB 查恶意 IP、整包威胁扫描（复用 poxiao 情报库）
- 明文凭据提取：HTTP Basic Auth / FTP / Telnet 凭据

## 安全设计

强安全 + 全审计：输入校验、`shell=False` 防注入、Nmap 限速、路径沙箱、哈希链审计日志（对齐 08 可审计证据链）。

## 快速使用

### 安装

```
pip install -e ".[dev]"
```

### 作为 MCP Server 运行

```
python -m mcp_server.server
# 在 Claude Desktop / Cursor 的 MCP 配置中指向该命令
```

### 作为库直接调用

```python
from packetforge.tools.capture import CaptureTools
from packetforge.core.audit import AuditLog

tools = CaptureTools(audit=AuditLog())
result = tools.analyze_pcap_file("capture.pcap")
print(result)
```

## 安全须知

- 所有工具调用经过输入校验与审计哈希链记录。
- Nmap 扫描强制限速（默认每小时 10 次）。
- 凭据提取结果对 LLM 脱敏（仅报告存在性与用户，不泄露明文密码）。
- 仅限授权环境使用。

## 测试

```
pytest
# 集成测试在无 tshark/nmap 时自动跳过
```

## 文档

- [设计文档](docs/specs/2026-08-10-packetforge-design.md)
- [实现计划](docs/plans/2026-08-10-packetforge-implementation.md)

## 目录结构

```
packetforge/      # 核心工具库（纯 Python，零 MCP 依赖）
  core/           # security（校验/沙箱/限速）、audit（哈希链）、output_formatter
  interfaces/     # tshark / nmap / creds / threat_intel 封装
  tools/          # capture / streams / export / nmap_scan / creds / threat
mcp_server/       # MCP 适配层（FastMCP tools/resources/prompts）
tests/            # pytest + coverage
```

## 状态

核心库与 MCP 层全部实现完成，12 个 TDD 任务已全部落地。
