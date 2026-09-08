# Roadmap

PacketForge is an AI network-analysis tool library + MCP server for
**authorized** penetration testing. This roadmap reflects the current
priorities; the authoritative design doc lives in `docs/specs/`.

## v0.1.0 — shipped

- Core library: capture/analysis, stream reassembly, export, credential
  extraction (HTTP Basic/FTP/Telnet), threat intel (URLhaus + AbuseIPDB),
  Nmap scanning — all behind `core/security.py` validation with a
  SHA-256 audit hash-chain and compliance report.
- MCP adapter: 11 tools + resource + prompts, stdio / HTTP / SSE transports.
- Persistent audit log (JSONL) with tamper detection.
- Output truncation for LLM context safety; display-filter syntax pre-check.
- CI (Python 3.11-3.13, ruff, coverage gate 85%), packaging, governance files.

## Next (near-term)

- [x] Structured Nmap output (`-oX -` → parsed JSON) — shipped (all scan tools).
- [x] Pluggable intel verdict merging (`verdict` + `sources` in check_ip) — shipped.
- [x] IntelSource protocol for third-party feeds — shipped.
- [x] Audit report exposed via MCP resource `audit://report` + `save_audit_report` tool — shipped.
- [x] NSE script scanning (`nmap_nse_scan`) with script-spec validation — shipped.
- [x] Poxiao IP-enrichment adapter (`PoxiaoIPSource`, optional) — shipped.
- [ ] RayScan `WAVScanner` web-vuln follow-up after Nmap service discovery
      (optional import; see design-doc correction below).
- [ ] Local blocklist / file-based feed loader as a ready-made IntelSource.
- [ ] NSE script catalog helper (list available scripts from the local nmap install).

## Later

- [ ] NSE script catalog exposure (select scripts, not blanket `--script vuln`).
- [ ] Credentials: Kerberos/NTLM SSP parsing, HTTP digest detection.
- [ ] Session capture store: search past captures by IOC via MCP resource.
- [ ] Multi-language docs (English primary, Chinese retained).

## Non-goals

- Any capability that bypasses the built-in safety controls.
- Silent privilege escalation (root/UAC prompts are always explicit).
