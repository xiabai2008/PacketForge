# PacketForge 设计文档

> 面向授权渗透测试的 AI 网络分析工具库 + MCP Server
> 设计日期：2026-08-10

## 1. 定位与目标

把 Wireshark 抓包、明文凭据提取、威胁情报联动、Nmap 主动扫描封装成标准化 MCP 工具，供任意 AI 客户端调用，增强 Agent 的渗透测试能力。在授权场景下最大化能力释放，同时内置强安全校验与全链路审计。

核心价值：**工具库 + MCP 封装**形态，核心逻辑零 MCP 依赖，方便长期迭代；复用自己的安全资产底座，补齐"抓包 → 凭据 → 情报 → 主动纵深"闭环。

## 2. 落地形态

**工具库 + MCP 封装**（推荐）。

- `packetforge` 核心工具库：纯 Python，零 MCP 依赖，可独立 `pip install` 使用。
- `mcp_server` 适配层：基于 FastMCP，暴露工具 / Resource / Prompt 给任何 AI 客户端。
- 主攻核心库迭代，MCP 层保持薄。

## 3. 架构分层

```
AI 客户端（Claude / Cursor / dawnforge-pentest 等）
        │ MCP(stdio)
        ▼
MCP Server 层（FastMCP）—— 工具注册 / Resource / Prompt / 限速 / 审计日志
        │
        ▼
PacketCore 核心工具库（纯 Python）
  ├── tshark 封装（抓包/分析/流重组）
  ├── 凭据提取
  ├── 威胁情报
  └── Nmap 扫描（复用 rayscan 底座）
        │
        ▼
core/security.py（输入校验/沙箱/限速）→ 审计记录（哈希链）
        │
        ├──► rayscan（Nmap 底座复用）
        ├──► poxiao（情报库复用）
        └──► LogicHunt（可承载多 agent）
```

## 4. 能力模块与吸收来源

| 模块 | 具体能力 | 吸收自 | 复用资产 |
|------|---------|--------|---------|
| 抓包与分析 | 实时抓包(BPF)、PCAP/PCAPNG 分析、协议统计、TCP/UDP 流重组、JSON/CSV 导出 | Wireshark-MCP 模块化 + WireMCP tshark 封装 | 全新 |
| Nmap 主动扫描 | SYN/connect/UDP、服务版本、OS 指纹、NSE 漏洞脚本、快速/全面扫描 | Wireshark-MCP | 全新实现（见下方更正） |
| 威胁情报联动 | URLhaus/AbuseIPDB 查恶意 IP、整包威胁扫描 | Wireshark-MCP + WireMCP | 全新实现（见下方更正） |
| 明文凭据提取 | HTTP Basic Auth / FTP / Telnet 凭据 | WireMCP（独有优势） | 全新 |

> **2026-08-11 更正**：原设计中"复用 rayscan（Nmap 底座）"与"复用 poxiao（情报库）"
> 的假设经代码勘察不成立——rayscan 实为 Web 应用漏洞扫描器（`wvs` 包，无 Nmap API），
> poxiao 实为 SRC 侦察工具链（`src` 包，无 URLhaus/AbuseIPDB API）。
> 因此 Nmap 与威胁情报模块为全新实现；两底座的可选集成（poxiao `IPCollector` IP 富化、
> rayscan `WAVScanner` Web 漏洞验证）列入 ROADMAP 后续评估。

## 5. 目录结构

```
packetforge/
├── packetforge/                 # 核心工具库（纯 Python，零 MCP 依赖）
│   ├── __init__.py
│   ├── core/
│   │   ├── security.py          # 输入校验 / 沙箱 / 限速
│   │   ├── audit.py             # 哈希链审计日志
│   │   └── output_formatter.py  # LLM 友好 JSON 格式化
│   ├── interfaces/
│   │   ├── tshark_interface.py  # tshark 封装（抓包/分析/流重组）
│   │   ├── nmap_interface.py    # Nmap 封装（复用 rayscan 底座）
│   │   ├── creds_interface.py   # 明文凭据提取
│   │   └── threat_intel.py      # URLhaus/AbuseIPDB 查询（复用 poxiao）
│   └── tools/
│       ├── capture.py           # 实时抓包 / PCAP 分析
│       ├── streams.py           # TCP/UDP 流重组
│       ├── export.py            # JSON/CSV 导出
│       ├── nmap_scan.py         # 主动扫描
│       ├── creds.py             # 凭据提取
│       └── threat.py            # 情报联动
├── mcp_server/                  # MCP 适配层（薄）
│   ├── server.py                # FastMCP 注册
│   ├── resources.py             # wireshark:// 资源
│   └── prompts.py               # 安全审计/应急响应工作流
├── tests/                       # pytest + coverage
├── pyproject.toml
└── README.md
```

设计要点：
- `core/security.py` 是所有工具调用的唯一入口前置，强制校验。
- `interfaces/` 与 `tools/` 分离，每个单元单一职责、可独立测试。
- 每个单元回答：做什么、怎么用、依赖什么。

## 6. 数据流（一次渗透分析会话）

1. AI 收到用户指令（如"分析 suspicious.pcap 并查恶意 IP"）。
2. MCP 层调用 `analyze_pcap_file` → `PacketCore.security` 校验路径 → `tshark_interface` 执行。
3. 结果经 `output_formatter` 转成 LLM 友好的 JSON。
4. AI 进一步要求 `scan_capture_for_threats` → 提取 IP → 复用 `poxiao` 情报库查询。
5. 发现开放端口后调用 `nmap_service_detection` → 复用 `rayscan` 底座。
6. 每一步都经 `audit.py` 写入哈希链日志，最终可输出合规审计报告。

## 7. 安全设计（强安全 + 全审计）

- **输入校验**：IP/CIDR/主机名、端口范围、BPF/display filter 卫生化、路径沙箱。
- **命令注入防护**：所有 subprocess 强制 `shell=False`，列表式构建命令。
- **限速**：Nmap 每工具调用强制冷却，可配置（如每小时 10 次）。
- **权限管理**：检测 root 需求，不自动提权，清晰报错。
- **全链路审计**：每次操作记录时间戳 + 工具名 + 参数哈希 + 结果摘要，串成哈希链（对齐 08 可审计证据链），输出合规审计报告。

## 8. 错误处理

- tshark/nmap 未安装 → 启动时检测并明确报错，提示安装命令。
- 权限不足（root 要求）→ 检测并提示，不自动提权。
- 非法输入（恶意路径/超限端口）→ `security.py` 拦截并记录审计。
- 外部情报 API 失败 → 降级为"本地分析 + 标记未查"，不阻断主流程。

## 9. 测试策略

- 单元测试：`core/security` 校验逻辑、`interfaces` 各封装（mock tshark/nmap 输出）。
- 集成测试：用本地靶场（DVWA/Metasploitable）生成真实 PCAP 跑通全流程。
- 安全回归：注入用例集（命令注入、路径穿越、超限扫描）确保被拦截。
- 覆盖率目标：核心 `security.py` 与审计链路 ≥ 90%。

## 10. 验收标准

- 核心库可独立 `pip install` 并运行全部工具。
- MCP Server 可被 Claude/Cursor 通过 stdio 调用全部工具。
- 覆盖抓包分析、凭据提取、威胁情报、Nmap 扫描四模块。
- 本地靶场端到端跑通"分析 → 情报 → 扫描"闭环。
- 安全回归用例全部拦截，审计哈希链可输出合规报告。