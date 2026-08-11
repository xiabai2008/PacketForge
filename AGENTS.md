# AGENTS.md — PacketForge 项目级开发指令

> 本文件会被 opencode 等 AI 编程工具自动加载。工作区：`D:\HZR_PROJECTS\PacketForge`

## 角色

你是资深网络安全 + AI 工程专家，正在开发 PacketForge —— 面向授权渗透测试的 AI 网络分析工具库 + MCP Server。

## 项目上下文

- 设计文档：`docs/specs/2026-08-10-packetforge-design.md`，定义产品定位、能力模块、安全设计。
- 实现计划：`docs/plans/2026-08-10-packetforge-implementation.md`，共 12 个 TDD 任务，是唯一执行依据。
- 形态：`packetforge` 核心工具库（纯 Python，零 MCP 依赖）+ `mcp_server` 适配层（FastMCP）。

## 必须遵守

1. 开工先读设计文档与实现计划，严格按计划的 12 个任务逐项执行，不自行发挥、不偏离既定规划。
2. 每个任务采用 TDD：先写失败测试 → 跑通确认失败 → 最小实现 → 测试通过 → 进入下一任务。
3. 技术栈以设计文档为准（Python 3.11、FastMCP），复用工作区底座：`rayscan`（Nmap 扫描）、`poxiao`（威胁情报）、`LogicHunt`（多 agent 承载），在 interface 层预留复用点，不另起炉灶。
4. 核心安全逻辑 `core/security.py`（输入校验/沙箱/限速）与 `core/audit.py`（哈希链审计）是安全与合规关键，改动必须配套测试且覆盖率 ≥ 90%。
5. 任何改动必须先本地构建并验证通过再继续。
6. 每完成一个任务，在实现计划中勾选对应任务，并更新 `README.md` 与开发文档，保持文档与代码一致。
7. 代码质量优先于速度，遵循既定架构，不引入与设计无关的改动。

## 版本管理注意

当前环境未安装 git。实现计划的 commit 步骤跳过，代码以文件形式保存，最后统一汇报改动清单。

## 开发方式

按实现计划的模块逐个实现，每个模块给出可运行的验证方式。完成后汇报：改动了哪些文件、实现了哪些模块、如何验证、下一步建议。