---
name: Feature request
about: Suggest an idea for PacketForge
title: "[feat] "
labels: enhancement
assignees: ""
---

**Problem to solve**

What authorized-pentest workflow is blocked or awkward today?

**Proposed solution**

The tool/behavior you would like. Note whether it fits the existing layers
(`interfaces/` wrapper vs `tools/` orchestration vs `mcp_server/` exposure).

**Security considerations**

New tools must pass through `core/security.py` validation and the audit
hash-chain, and must keep `shell=False`. Describe the input validation and
rate-limiting plan for your proposal.

**Alternatives considered**

Any workarounds you have tried.
