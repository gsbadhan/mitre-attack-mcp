# mitre-attack-mcp
MITRE ATT&amp;CK MCP Server

# Description


# Project setup
- uv venv
- source .venv/bin/activate
- uv sync

# Run MCP server locally
- uv run python -m mitre_attack_mcp.server

# Data ingestion
## Download all three domains
- uv run python -m mitre_attack_mcp.data
## Download just one domain
- uv run python -m mitre_attack_mcp.data enterprise-attack
## Force re-download + show progress
- uv run python -m mitre_attack_mcp.data --force -v

# Run application


# Unit tests
- uv run pytest tests/ -v