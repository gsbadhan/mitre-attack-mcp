import pytest
import json
from pytest_mcp import assert_tool_call, assert_tool_error
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
