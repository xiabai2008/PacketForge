"""MCP prompts for security workflows."""

from fastmcp import FastMCP


def register_prompts(mcp: FastMCP) -> None:
    @mcp.prompt()
    def security_audit() -> str:
        return (
            "Perform a security audit on a captured network file. Steps:\n"
            "1. Call get_protocol_statistics on the pcap.\n"
            "2. Call scan_capture_for_threats to check for malicious IPs.\n"
            "3. Call extract_credentials to detect cleartext credentials.\n"
            "4. Summarize findings into a report."
        )

    @mcp.prompt()
    def incident_response() -> str:
        return (
            "Investigate a security incident from a pcap. Steps:\n"
            "1. Call analyze_pcap_file with an http.request filter.\n"
            "2. Follow suspicious TCP streams.\n"
            "3. Report the timeline and indicators."
        )
