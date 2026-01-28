# Optimike Obsidian Tasks MCP

[![npm version](https://badge.fury.io/js/optimike-obsidian-tasks-mcp.svg)](https://badge.fury.io/js/optimike-obsidian-tasks-mcp)

A Model Context Protocol (MCP) server for extracting and querying Obsidian Tasks from markdown files. Designed to work with Claude via the MCP protocol to enable AI-assisted task management.

French version: [README.fr.md](README.fr.md)

## Features

- Extract tasks from Obsidian markdown files with compatibility for Obsidian Tasks settings
- Status mapping driven by your Tasks plugin config (core + custom statuses)
- Supports Tasks global filter + presets (optional)
- Date filters with relative ranges (EN/FR) and comparisons
- Optional Dataview task format parsing (`[due:: 2024-01-01]`, etc.)
- Optional file metadata + frontmatter meta dates (with fallback to filesystem)
- Output as JSON or Markdown

## Tasks plugin config (source of truth)

This server reads your Tasks plugin settings (statuses, presets, global filter) from:

```
<vault>/.obsidian/plugins/obsidian-tasks/data.json
```

Make sure that file reflects your current Tasks configuration.

## Tools

This MCP server provides the following tools:

### list_all_tasks

Extracts all tasks from markdown files in a directory, recursively scanning through subfolders.

**Input Parameters:**
- `path` (string, optional): Directory to scan. Defaults to the vault root.
- `includePaths` (string[], optional): Only include paths containing any of these substrings.
- `excludePaths` (string[], optional): Exclude paths containing any of these substrings.
- `includeNonTasks` (boolean, optional): Include NON_TASK statuses.
- `includeFileMetadata` (boolean, optional): Include file created/modified dates.
- `includeMetaDates` (boolean, optional): Include frontmatter meta dates (e.g., création/modification).
- `metaFallbackToFile` (boolean, optional, default true): If meta dates are missing, fall back to file dates.
- `applyGlobalFilter` (boolean, optional): Apply Tasks `globalFilter`.
- `responseFormat` ("json" | "markdown", optional): Output format.
- `responseLimit` (number, optional): Limit number of tasks returned.
- `useCache` (boolean, optional, default true): Cache per-file parsing.

**Returns:**
A JSON array of task objects, each containing:
```json
{
  "id": "string",          // Unique identifier (filepath:linenumber)
  "description": "string", // Full text description of the task
  "status": "complete" | "incomplete" | "cancelled" | "in_progress" | "non_task",
  "statusName": "string", // Optional - status name from Tasks config
  "statusType": "string", // Optional - TODO | DONE | IN_PROGRESS | CANCELLED | NON_TASK
  "filePath": "string",    // Path to the file containing the task
  "lineNumber": "number",  // Line number in the file
  "tags": ["string"],      // Array of tags found in the task
  "dueDate": "string",     // Optional - YYYY-MM-DD format 
  "scheduledDate": "string", // Optional - YYYY-MM-DD format
  "startDate": "string",   // Optional - YYYY-MM-DD format
  "createdDate": "string", // Optional - YYYY-MM-DD format
  "doneDate": "string",    // Optional - YYYY-MM-DD format
  "cancelledDate": "string", // Optional - YYYY-MM-DD format
  "metaCreatedDate": "string", // Optional - from frontmatter
  "metaModifiedDate": "string", // Optional - from frontmatter
  "fileCreatedDate": "string", // Optional - filesystem
  "fileModifiedDate": "string", // Optional - filesystem
  "priority": "string",    // Optional - "high", "medium", or "low"
  "recurrence": "string"   // Optional - recurrence rule
}
```

### query_tasks

Searches for tasks based on Obsidian Tasks query syntax. Applies multiple filters to find matching tasks.

**Input Parameters:**
- `path` (string, optional): Directory to scan. Defaults to the vault root.
- `query` (string, required): Tasks query. Each line is treated as a filter.
- `queryFilePath` (string, optional): Used to resolve `{{query.file.*}}` placeholders.
- All other parameters from `list_all_tasks` (include/exclude, meta dates, global filter, etc.)

**Returns:**
A JSON array of task objects that match the query, with the same structure as `list_all_tasks`.

**Supported Query Syntax (subset + extras):**

- Status filters:
  - `done` / `not done` (aligned with Tasks semantics)
  - `status.type is TODO|DONE|IN_PROGRESS|CANCELLED|NON_TASK`
  - `status.name is "In Progress"`

- Date filters:
  - `due|scheduled|start|created on|before|after YYYY-MM-DD`
  - `due|scheduled|start|created on or before|on or after <date>`
  - Relative EN/FR: `today`, `tomorrow`, `yesterday`, `this week`, `next week`, `last week`, `aujourd'hui`, `demain`, `hier`, `cette semaine`, `semaine prochaine`
  - Ranges: `due in next 7 days`
  - Meta/file: `meta created before 2026-01-01`, `file modified after 2025-12-31`

- Tag filters:
  - `no tags`, `has tags`
  - `tag include #tag` / `tag do not include #tag`

- Path filters:
  - `path includes string`, `path does not include string`
  - `folder includes string`, `filename includes string`

- Description filters:
  - `description includes string` - Tasks with descriptions containing "string"
  - `description does not include string` - Tasks with descriptions not containing "string"

- Priority filters:
  - `priority is high` - Tasks with high priority
  - `priority is medium` - Tasks with medium priority
  - `priority is low` - Tasks with low priority
  - `priority is none` - Tasks with no priority

**Example Query:**
```
not done
due before 2025-05-01
tag include #work
```
This would return all incomplete tasks due before May 1, 2025, that have the #work tag.

## Usage

### Installation

From npm (recommended):

```bash
# Install globally
npm install -g optimike-obsidian-tasks-mcp

# Or use directly with npx without installing
npx optimike-obsidian-tasks-mcp /path/to/obsidian/vault
```

From source:

```bash
git clone https://github.com/mickahouan/optimike-obsidian-tasks-mcp.git
cd optimike-obsidian-tasks-mcp
npm install
npm run build
```

### Running the Server

Using npm package (recommended):

```bash
# If installed globally
optimike-obsidian-tasks-mcp /path/to/obsidian/vault

# Or with npx (no installation required)
npx optimike-obsidian-tasks-mcp /path/to/obsidian/vault
```

From source:

```bash
node dist/index.js /path/to/obsidian/vault
```

You can specify multiple directories:

```bash
npx optimike-obsidian-tasks-mcp /path/to/obsidian/vault /another/directory
```

### HTTP transport (optional)

The server also supports Streamable HTTP transport.

```bash
MCP_TRANSPORT_TYPE=http MCP_HTTP_HOST=127.0.0.1 MCP_HTTP_PORT=3011 \
  npx optimike-obsidian-tasks-mcp /path/to/obsidian/vault
```

Session mode (default `stateful`):

- `MCP_HTTP_SESSION_MODE=stateful` (auto sessionId)
- `MCP_HTTP_SESSION_MODE=stateless` (no session)

### Performance & scope

To avoid scanning too much, use `includePaths`/`excludePaths` in MCP calls,
or set defaults via env vars:

- `MCP_TASKS_INCLUDE_PATHS` (CSV): vault-relative paths, e.g. `Efforts/Projets,Calendrier/NOTES PÉRIODIQUES`
- `MCP_TASKS_EXCLUDE_PATHS` (CSV)
- `MCP_TASKS_MAX_FILES` (number)
- `MCP_TASKS_CONCURRENCY` (number, default 8)

### Testing

To run the test suite:

```bash
npm test
```

See [TESTING.md](TESTING.md) for detailed information about the test suite.

### Inspection (MCP Inspector)

```bash
npm run inspect:stdio
# or
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

If you installed from source:

```json
{
  "mcpServers": {
    "optimike-obsidian-tasks": {
      "command": "node",
      "args": [
        "/path/to/optimike-obsidian-tasks-mcp/dist/index.js",
        "/path/to/obsidian/vault"
      ]
    }
  }
}
```

### Docker

Build the Docker image:

```bash
docker build -t optimike-obsidian-tasks-mcp .
```

Run with Docker:

```bash
docker run -i --rm --mount type=bind,src=/path/to/obsidian/vault,dst=/projects/vault optimike-obsidian-tasks-mcp /projects
```

Claude Desktop configuration:

```json
{
  "mcpServers": {
    "optimike-obsidian-tasks": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--mount", "type=bind,src=/path/to/obsidian/vault,dst=/projects/vault",
        "optimike-obsidian-tasks-mcp",
        "/projects"
      ]
    }
  }
}
```

## Task Format

The server recognizes the following Obsidian Tasks format:

- Task syntax: `- [ ] Task description`
- Completed task: `- [x] Task description`
- Due date: 
  - `🗓️ YYYY-MM-DD`
  - `📅 YYYY-MM-DD`
- Scheduled date: `⏳ YYYY-MM-DD`
- Start date: `🛫 YYYY-MM-DD`
- Created date: `➕ YYYY-MM-DD`
- Priority: `⏫` (high), `🔼` (medium), `🔽` (low)
- Recurrence: `🔁 every day/week/month/etc.`
- Tags: `#tag1 #tag2`

Example task: `- [ ] Complete project report 🗓️ 2025-05-01 ⏳ 2025-04-25 #work #report ⏫`

## License

MIT License
