import pytest
import json
from pytest_mcp import assert_tool_call
from mitre_attack_mcp.server import mcp  # Import your MCPServer instance

# Tell pytest-mcptest which server to test
pytestmark = pytest.mark.mcp_server(mcp)


def _payload(result):
    """Extract the tool's return value from a CallToolResult."""
    if getattr(result, "structured_content", None):
        return result.structured_content
    # Fallback: the SDK wraps a bare dict return in {"result": ...}
    text = result.content[0].text
    return json.loads(text)


async def test_technique_lookup_without_domain(mcp_client):
    result = await assert_tool_call(
        mcp_client, "get_technique_by_id", {"attack_id": "T1059"}
    )
    data = _payload(result)
    if set(data.keys()) == {"result"}:
        data = data["result"]
    assert data["domain"] == "enterprise-attack"
    assert "Command and Scripting" in data["name"]


async def test_mitigations_for_technique(mcp_client):
    result = await assert_tool_call(
        mcp_client, "get_mitigations_for_technique", {"attack_id": "T1003"}
    )
    data = _payload(result)
    if set(data.keys()) == {"result"}:
        data = data["result"]
    ids = {m["id"] for m in data["mitigations"]}
    assert {"M1015", "M1043", "M1026"} <= ids


async def test_procedures_for_technique(mcp_client):
    result = await assert_tool_call(
        mcp_client, "get_procedures_for_technique", {"attack_id": "T1003"}
    )
    data = _payload(result)
    if set(data.keys()) == {"result"}:
        data = data["result"]
    names = {p["name"] for p in data["procedures"]}
    assert "APT28" in names
    assert all(p["procedure"] for p in data["procedures"])  # no empty procedures


async def test_techniques_by_tactic_name(mcp_client):
    """Tactic shortname returns techniques, including a known one."""
    result = await assert_tool_call(
        mcp_client, "get_techniques_by_tactic", {"tactic": "credential-access"}
    )
    data = _payload(result)
    if set(data.keys()) == {"result"}:
        data = data["result"]
    ids = {t["id"] for t in data["techniques"]}
    assert "T1003" in ids


async def test_techniques_by_tactic_id(mcp_client):
    """Tactic ID (TA0006) resolves to the same set as the shortname."""
    result = await assert_tool_call(
        mcp_client, "get_techniques_by_tactic", {"tactic": "TA0006"}
    )
    data = _payload(result)
    if set(data.keys()) == {"result"}:
        data = data["result"]
    ids = {t["id"] for t in data["techniques"]}
    assert "T1003" in ids


async def test_detections_for_technique(mcp_client):
    """T1003 returns detection strategies with at least one analytic."""
    result = await assert_tool_call(
        mcp_client, "get_detections_for_technique", {"attack_id": "T1003"}
    )
    data = _payload(result)
    if set(data.keys()) == {"result"}:
        data = data["result"]

    strategies = data["detection_strategies"]
    assert len(strategies) > 0, "T1003 should have at least one detection strategy"

    # Every strategy should have an ID starting with DET
    for s in strategies:
        assert s["id"].startswith("DET"), f"strategy ID {s['id']} not a DET####"

    # At least one strategy should carry analytics
    all_analytics = [a for s in strategies for a in s["analytics"]]
    assert len(all_analytics) > 0, "expected at least one analytic across strategies"
    for a in all_analytics:
        assert a["id"].startswith("AN"), f"analytic ID {a['id']} not an AN####"
        assert a["description"], "analytic should have a non-empty description"
