# optimike-obsidian-tasks-mcp

A Model Context Protocol (MCP) server for extracting and querying Obsidian Tasks from markdown files. Designed to work with Claude via the MCP protocol to enable AI-assisted task management.

## Installation

You can install globally:

```bash
npm install -g optimike-obsidian-tasks-mcp
```

Or use with npx without installing:

```bash
npx optimike-obsidian-tasks-mcp /path/to/obsidian/vault
```

## Usage

### Running the Server

If installed globally:

```bash
optimike-obsidian-tasks-mcp /path/to/obsidian/vault
```

With npx (recommended):

```bash
npx optimike-obsidian-tasks-mcp /path/to/obsidian/vault
```

You can specify multiple directories:

```bash
npx optimike-obsidian-tasks-mcp /path/to/obsidian/vault /another/directory
```

## HTTP transport (optional)

```bash
MCP_TRANSPORT_TYPE=http MCP_HTTP_HOST=127.0.0.1 MCP_HTTP_PORT=3011 \
  npx optimike-obsidian-tasks-mcp /path/to/obsidian/vault
```

Session mode (default `stateful`):
- `MCP_HTTP_SESSION_MODE=stateful`
- `MCP_HTTP_SESSION_MODE=stateless`

## Performance & scope

Env vars (CSV) to limit scope:
- `MCP_TASKS_INCLUDE_PATHS`
- `MCP_TASKS_EXCLUDE_PATHS`
- `MCP_TASKS_MAX_FILES`
- `MCP_TASKS_CONCURRENCY`

## Inspection (MCP Inspector)

```bash
npm run inspect:stdio
npm run inspect:http
```

### Using with Claude

Add this configuration to your Claude client that supports MCP:

```json
{
  "mcpServers": {
    "optimike-obsidian-tasks": {
      "command": "npx",
      "args": [
        "optimike-obsidian-tasks-mcp",
        "/path/to/obsidian/vault"
      ]
    }
  }
}
```

## Features

This MCP server provides the following tools and capabilities:

- Status mapping driven by your Tasks plugin config (core + custom statuses)
- Presets + placeholders (`preset name`, `{{preset.xxx}}`, `{{query.file.*}}`)
- Relative date filters (EN/FR) and range comparisons
- Optional Dataview task format parsing
- Optional frontmatter meta dates with filesystem fallback

### list_all_tasks

Extracts all tasks from markdown files in a directory, recursively scanning through subfolders.

### query_tasks

Searches for tasks based on Obsidian Tasks query syntax. Applies multiple filters to find matching tasks.

Supported query syntax includes:
- Status filters: `done`, `not done`
- Date filters: `due today`, `scheduled tomorrow`, `start on or before today`, `due in next 7 days`
- Tag filters: `has tags`, `no tags`, `tag include #tag`
- Path and description filters
- Priority filters

For more details, see the full documentation at [GitHub Repository](https://github.com/mickahouan/optimike-obsidian-tasks-mcp).

## License

MIT
