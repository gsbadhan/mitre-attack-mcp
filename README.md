# mitre-attack-mcp
MITRE ATT&amp;CK MCP Server

# Description


# Project setup
- uv venv
- source .venv/bin/activate
- uv sync

# Data ingestion
### Download all three domains
- uv run python -m mitre_attack_mcp.data
### Download just one domain
- uv run python -m mitre_attack_mcp.data enterprise-attack
### Force re-download + show progress
- uv run python -m mitre_attack_mcp.data --force -v

# Run MCP server locally
- uv run python -m mitre_attack_mcp.server

# Unit tests
- uv run pytest tests/ -v

# Integration Anthropic claude
```
1. check mcps: claude mcp list

2. add below configs in macOS: ~/Library/Application Support/Claude/claude_desktop_config.json

{
  "mcpServers": {
    "mitre-attack": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/Users/john/git-projects/mitre-attack-mcp",
        "mitre-attack-mcp"
      ]
    }
  }
}

3. register mitre mcp: claude mcp add --scope user mitre-attack -- uv run --directory /Users/john/git-projects/mitre-attack-mcp mitre-attack-mcp

4. check mitre mcp: claude mcp list

5. check detail: claude mcp get mitre-attack

```
![Claude Settings](claude-settings.png)