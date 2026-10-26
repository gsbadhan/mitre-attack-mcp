# mitre-attack-mcp
MITRE ATT&amp;CK MCP Server

# Description
A Model Context Protocol server that exposes the MITRE ATT&CK knowledge base to AI agents such as Claude Desktop and Claude Code. PyPi - https://pypi.org/project/mitre-attack-mcp, githib- https://github.com/gsbadhan/mitre-attack-mcp .

## What it does
| Tool | Purpose | Input |
|------|---------|-------|
| `get_data_stats` | Counts of techniques, groups, software, mitigations | none |
| `search_techniques` | Find techniques by keyword | `keyword` |
| `get_technique_by_id` | Technique details by ID | `attack_id` |
| `get_mitigations_for_technique` | Mitigations for a technique | `attack_id` |
| `get_group_by_name` | Threat group details | `name` |

All tools also accept an optional `domain`: `enterprise-attack`, `ics-attack`, or `mobile-attack`.


# Project setup
- uv venv
- source .venv/bin/activate
- uv sync

# Data ingestion
- MITRE data auto downloaded while MCP server starts

# Run MCP server locally
- uv run python -m mitre_attack_mcp.server
#### Note: Dont run with Claude, its for local testing only

# Unit tests
- uv run pytest tests/ -v

# Integration With Anthropic Claude Code
```
1. Clone code repository locally

2. Check mcps: claude mcp list

3. Add below configs in macOS: ~/Library/Application Support/Claude/claude_desktop_config.json

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


4. Register mitre mcp: claude mcp add --scope user mitre-attack -- uv run --directory /Users/john/git-projects/mitre-attack-mcp mitre-attack-mcp

5. Check mitre-attack mcp: claude mcp list

6. Check detail: claude mcp get mitre-attack

```
# Integration with Anthropic Claude Desktop
```
1. Claude desktop -> Settings -> Developer -> Edit config

2. Add below configs if you using git repository code:

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

2. Add below configs if you using PyPi:

 "mcpServers": {
    "mitre-attack": {
      "command": "uvx",
      "args": ["mitre-attack-mcp@latest"]
    }
  }

3. Relaunch Claude

```
```
 
```
![Claude Settings](https://raw.githubusercontent.com/gsbadhan/mitre-attack-mcp/main/claude-settings.png)


# Claude Desktop Assistant With Mitre MCP
![Claude Desktop Chat](https://raw.githubusercontent.com/gsbadhan/mitre-attack-mcp/main/claude-desktop-chat.png)


# Common prompts
```
Search mitre-attack for techniques containing 'credential'.
Get the data stats from mitre-attack.
Look up the group APT29 in mitre-attack.
Use the mitre-attack server to look up technique T1059.
what is mitigations for T1003.
```


