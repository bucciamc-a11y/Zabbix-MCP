"""Reusable prompts exposed to MCP clients."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP) -> None:
    @mcp.prompt(description="Triage current Zabbix problems and propose next steps")
    def triage_problems(min_severity: str = "average") -> str:
        return (
            f"Triage Zabbix problems of severity {min_severity} or higher. 1) get_active_problems. "
            "2) Group them by host and likely shared cause. 3) For the top items call get_host_details "
            "and query_metrics_history for the relevant metric. 4) Summarise: what is wrong, since "
            "when, probable cause, recommended action. Do not acknowledge or change anything "
            "without asking me first.")

    @mcp.prompt(description="Health check for one host")
    def host_health_check(host: str) -> str:
        return (
            f"Check the health of host '{host}': get_host_details, get_triggers, "
            "get_latest_values (CPU, memory, disk, network), and query_metrics_history for the last 24 "
            "hours of anything that looks abnormal. Report findings and risks.")
