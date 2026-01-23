# Optimike Obsidian Tasks MCP

[![version npm](https://badge.fury.io/js/optimike-obsidian-tasks-mcp.svg)](https://badge.fury.io/js/optimike-obsidian-tasks-mcp)

Serveur Model Context Protocol (MCP) pour extraire et interroger les tâches Obsidian depuis des fichiers markdown. Conçu pour fonctionner avec Claude via MCP et permettre une gestion assistée par IA.

Version anglaise : [README.md](README.md)

## Fonctionnalités

- Extraction des tâches Obsidian avec compatibilité des paramètres du plugin Tasks
- Mapping des statuts via la config Tasks (core + custom)
- Support du filtre global Tasks + presets (optionnel)
- Filtres de dates avec plages relatives (EN/FR) et comparaisons
- Parsing Dataview optionnel (`[due:: 2024-01-01]`, etc.)
- Métadonnées de fichier optionnelles + dates frontmatter (avec fallback)
- Sortie JSON ou Markdown

## Outils

Ce serveur MCP expose les outils suivants :

### list_all_tasks

Extrait toutes les tâches d’un dossier en scannant récursivement les fichiers markdown.

**Paramètres d’entrée :**
- `path` (string, optionnel) : dossier à scanner. Par défaut la racine du vault.
- `includePaths` (string[], optionnel) : inclure uniquement les chemins contenant ces fragments.
- `excludePaths` (string[], optionnel) : exclure les chemins contenant ces fragments.
- `includeNonTasks` (boolean, optionnel) : inclure les statuts NON_TASK.
- `includeFileMetadata` (boolean, optionnel) : inclure dates de création/modif des fichiers.
- `includeMetaDates` (boolean, optionnel) : inclure dates frontmatter (ex. création/modification).
- `metaFallbackToFile` (boolean, optionnel, défaut true) : fallback sur dates de fichiers.
- `applyGlobalFilter` (boolean, optionnel) : appliquer le `globalFilter` Tasks.
- `responseFormat` ("json" | "markdown", optionnel) : format de sortie.
- `responseLimit` (number, optionnel) : limite de tâches retournées.
- `useCache` (boolean, optionnel, défaut true) : cache par fichier.

**Retour :**
Un tableau JSON d’objets tâches, par ex :
```json
{
  "id": "string",
  "description": "string",
  "status": "complete" | "incomplete" | "cancelled" | "in_progress" | "non_task",
  "statusName": "string",
  "statusType": "string",
  "filePath": "string",
  "lineNumber": "number",
  "tags": ["string"],
  "dueDate": "string",
  "scheduledDate": "string",
  "startDate": "string",
  "createdDate": "string",
  "doneDate": "string",
  "cancelledDate": "string",
  "metaCreatedDate": "string",
  "metaModifiedDate": "string",
  "fileCreatedDate": "string",
  "fileModifiedDate": "string",
  "priority": "string",
  "recurrence": "string"
}
```

### query_tasks

Recherche des tâches via la syntaxe Obsidian Tasks (filtres combinés).

**Paramètres d’entrée :**
- `path` (string, optionnel) : dossier à scanner. Par défaut la racine du vault.
- `query` (string, requis) : requête Tasks (1 filtre par ligne).
- `queryFilePath` (string, optionnel) : pour résoudre `{{query.file.*}}`.
- Tous les autres paramètres de `list_all_tasks`.

**Retour :**
Un tableau JSON de tâches correspondant à la requête.

**Syntaxe supportée (subset + extras) :**

- Statut :
  - `done` / `not done`
  - `status.type is TODO|DONE|IN_PROGRESS|CANCELLED|NON_TASK`
  - `status.name is "In Progress"`

- Dates :
  - `due|scheduled|start|created on|before|after YYYY-MM-DD`
  - `due|scheduled|start|created on or before|on or after <date>`
  - Relatif EN/FR : `today`, `tomorrow`, `yesterday`, `this week`, `next week`, `last week`, `aujourd'hui`, `demain`, `hier`, `cette semaine`, `semaine prochaine`
  - Plages : `due in next 7 days`
  - Meta/file : `meta created before 2026-01-01`, `file modified after 2025-12-31`

- Tags :
  - `no tags`, `has tags`
  - `tag include #tag` / `tag do not include #tag`

- Chemins :
  - `path includes string`, `path does not include string`
  - `folder includes string`, `filename includes string`

- Description :
  - `description includes string`
  - `description does not include string`

- Priorité :
  - `priority is high|medium|low|none`

**Exemple :**
```
not done
due before 2025-05-01
tag include #work
```

## Utilisation

### Installation

Depuis npm (recommandé) :

```bash
npm install -g optimike-obsidian-tasks-mcp
```

Ou avec npx :

```bash
npx optimike-obsidian-tasks-mcp /path/to/obsidian/vault
```

Depuis la source :

```bash
git clone https://github.com/mickahouan/optimike-obsidian-tasks-mcp.git
cd optimike-obsidian-tasks-mcp
npm install
npm run build
```

### Lancer le serveur

```bash
optimike-obsidian-tasks-mcp /path/to/obsidian/vault
```

### Transport HTTP (optionnel)

```bash
MCP_TRANSPORT_TYPE=http MCP_HTTP_HOST=127.0.0.1 MCP_HTTP_PORT=3011 \
  npx optimike-obsidian-tasks-mcp /path/to/obsidian/vault
```

Mode de session (défaut `stateful`) :
- `MCP_HTTP_SESSION_MODE=stateful`
- `MCP_HTTP_SESSION_MODE=stateless`

### Performance & scope

Variables d’env (CSV) pour limiter le scope :
- `MCP_TASKS_INCLUDE_PATHS`
- `MCP_TASKS_EXCLUDE_PATHS`
- `MCP_TASKS_MAX_FILES`
- `MCP_TASKS_CONCURRENCY`

### Tests

```bash
npm test
```

### Inspection (MCP Inspector)

```bash
npm run inspect:stdio
npm run inspect:http
```

### Configuration Claude Desktop (MCP)

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

## Format des tâches

- Tâche : `- [ ] Description`
- Terminée : `- [x] Description`
- Due : `🗓️ YYYY-MM-DD` ou `📅 YYYY-MM-DD`
- Scheduled : `⏳ YYYY-MM-DD`
- Start : `🛫 YYYY-MM-DD`
- Created : `➕ YYYY-MM-DD`
- Priorité : `⏫` (high), `🔼` (medium), `🔽` (low)
- Récurrence : `🔁 every day/week/month/etc.`
- Tags : `#tag1 #tag2`

Exemple : `- [ ] Complete project report 🗓️ 2025-05-01 ⏳ 2025-04-25 #work #report ⏫`

## Licence

MIT License
