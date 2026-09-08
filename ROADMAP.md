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

- [ ] **Poxiao / RayScan adapter review** — the original design assumed
      Nmap and URLhaus/AbuseIPDB APIs in those bases; investigation showed
      they are a web-vuln scanner (`wvs`) and an SRC recon pipeline (`src`)
      respectively. Evaluate integrating poxiao's `IPCollector` as an
      optional IP-enrichment source and RayScan's `WAVScanner` for web-vuln
      follow-up after Nmap service discovery (both optional imports).
- [ ] Pluggable intel sources: registry of feeds (URLhaus, AbuseIPDB,
      local blocklists) with unified verdict merging.
- [ ] Audit report export to file/JSON artifact via an MCP resource.
- [ ] Structured Nmap output (`-oX -` → parsed JSON) instead of raw text.

## Later

- [ ] NSE script catalog exposure (select scripts, not blanket `--script vuln`).
- [ ] Credentials: Kerberos/NTLM SSP parsing, HTTP digest detection.
- [ ] Session capture store: search past captures by IOC via MCP resource.
- [ ] Multi-language docs (English primary, Chinese retained).

## Non-goals

- Any capability that bypasses the built-in safety controls.
- Silent privilege escalation (root/UAC prompts are always explicit).
