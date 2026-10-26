from __future__ import annotations

import logging
import sys
from mcp.server.mcpserver import MCPServer
from . import data
from . import services

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    stream=sys.stderr,  # never stdout — that's the JSON-RPC channel
)

mcp = MCPServer("mitre-attack-mcp", version="0.1.0")


def _preStart():
    logging.info("downloading mitre knowledge data..")
    data.download_all()


@mcp.tool()
def get_data_stats(*, domain: str | None = None) -> dict | list[dict]:
    """Return counts of techniques, groups, software, and mitigations.

    domain: one of 'enterprise-attack', 'ics-attack', 'mobile-attack'.
        Omit to get a per-domain breakdown of all three.
    """

    return services.get_data_stats(domain=domain)


@mcp.tool()
def get_technique_by_id(
    attack_id: str,
    *,
    domain: str | None = None,
) -> dict:
    """Look up a MITRE ATT&CK technique by its ID (e.g. 'T1059' or 'T1059.001').

    Returns name, truncated description, tactics, and platforms, plus the
    domain the match came from.

    domain: one of 'enterprise-attack', 'ics-attack', 'mobile-attack'.
        Omit if you are not sure which domain the technique belongs to —
        all three will be searched and the result will say which domain
        matched. ATT&CK IDs are not globally unique across domains, so if
        the ID exists in more than one domain the result also lists
        `other_domains`.
    """
    return services.get_technique_by_id(attack_id, domain=domain)


@mcp.tool()
def search_techniques(
    keyword: str,
    *,
    domain: str | None = None,
    limit: int = 10,
) -> list[dict]:
    """Search techniques whose name or description contains the keyword.

    domain: restrict to one of 'enterprise-attack', 'ics-attack',
        'mobile-attack'. Omit to search all three domains.
    limit: maximum results across all searched domains (default 10).
    """
    return services.search_techniques(keyword, domain=domain, limit=limit)


@mcp.tool()
def get_group_by_name(
    name: str,
    *,
    domain: str | None = None,
) -> dict:
    """Look up a threat group by name or alias (e.g. 'APT29' or 'Cozy Bear').

    domain: one of 'enterprise-attack', 'ics-attack', 'mobile-attack'.
        Omit if you are not sure which domain the group belongs to —
        all three will be searched and the result will say which domain
        matched.
    """
    return services.get_group_by_name(name, domain=domain)


@mcp.tool()
def get_mitigations_for_technique(
    attack_id: str,
    *,
    domain: str | None = None,
) -> dict:
    """Return MITRE ATT&CK mitigations that apply to a specific technique.

    Use this tool whenever the user asks how to defend against, mitigate,
    or prevent a technique (e.g. "What mitigations exist for T1003?").
    Returns each mitigation's ATT&CK ID (M####), name, and description,
    sourced from the official ATT&CK dataset — do not answer from memory.

    domain: one of 'enterprise-attack', 'ics-attack', 'mobile-attack'.
        Omit to search all three.
    """
    return services.get_mitigations_for_technique(attack_id, domain=domain)


@mcp.tool()
def get_procedures_for_technique(
    attack_id: str,
    *,
    domain: str | None = None,
) -> dict:
    """Return procedure examples for a MITRE ATT&CK technique.

    Use this tool when the user asks how a technique has been used in the
    wild — which threat groups or malware employed it, and how. Returns
    each actor's name, ATT&CK ID (G#### or S####), kind (group/software),
    and the procedure description from the official ATT&CK dataset.
    Do not answer from memory.

    domain: one of 'enterprise-attack', 'ics-attack', 'mobile-attack'.
        Omit to search all three.
    """
    return services.get_procedures_for_technique(attack_id, domain=domain)


@mcp.tool()
def get_detections_for_technique(
    attack_id: str,
    *,
    domain: str | None = None,
) -> dict:
    """Return detection strategies and analytics for a MITRE ATT&CK technique.

    Use this tool when the user asks how to detect a technique (e.g.
    "How do I detect T1003?"). Returns each Detection Strategy (DET####)
    and its platform-specific Analytics (AN####) from the official
    ATT&CK v18 dataset. Do not answer from memory.

    domain: one of 'enterprise-attack', 'ics-attack', 'mobile-attack'.
        Omit to search all three.
    """
    return services.get_detections_for_technique(attack_id, domain=domain)


def main():
    _preStart()
    logging.info("mitre-attack-mcp server starting..")
    mcp.run()


if __name__ == "__main__":
    main()
