# Contributing to PacketForge

Thanks for your interest in contributing. PacketForge is a network-analysis
tool library + MCP server for **authorized** penetration testing. Before you
start, please read the design doc and implementation plan in `docs/`.

## Security notice

Only use this project against systems you are explicitly authorized to test.
Contributions that weaken the built-in safety controls (input validation,
rate limiting, audit hash-chain) will not be accepted. See `SECURITY.md`.

## Development setup

```bash
pip install -e ".[dev]"
pytest                  # full suite with coverage
ruff check packetforge mcp_server tests
ruff format --check packetforge mcp_server tests
```

Python 3.11+ is required. The integration test skips automatically when
`tshark`/`nmap` are not on `PATH`.

## Contribution workflow

1. Open an issue describing the problem/feature before writing code.
2. Fork the repository and create a branch from `main`.
3. Follow the existing TDD convention: add a failing test first, then the
   minimal implementation.
4. Core security modules (`core/security.py`, `core/audit.py`) must keep
   test coverage >= 90%. The global coverage gate is 85%.
5. Keep the code style consistent: run `ruff check` and `ruff format`
   locally; the CI job enforces both.
6. Open a pull request against `main`. CI must be green.

## Code conventions

- Core library (`packetforge/`) stays free of MCP imports; the MCP adapter
  lives in `mcp_server/` and stays thin.
- Every tool call passes through `core/security.py` validation and records an
  entry in the audit hash-chain.
- All subprocess calls use `shell=False` with list-built commands.
- Never commit secrets, API keys, or capture files.
