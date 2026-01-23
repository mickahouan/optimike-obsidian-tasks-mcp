#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import fs from "fs/promises";
import { statSync } from "fs";
import http from "http";
import crypto from "crypto";
import path from "path";
import os from 'os';
import { z } from "zod";
import { glob } from 'glob';

// Command line argument parsing
const args = process.argv.slice(2);
if (args.length === 0 && process.env.NODE_ENV !== 'test') {
  console.error("Usage: optimike-obsidian-tasks-mcp <vault-directory>");
  process.exit(1);
}

// Normalize all paths consistently
export function normalizePath(p: string): string {
  return path.normalize(p);
}

export function expandHome(filepath: string): string {
  if (filepath.startsWith('~/') || filepath === '~') {
    return path.join(os.homedir(), filepath.slice(1));
  }
  return filepath;
}

// Set up a single vault directory
const vaultDirectory = args.length > 0 ? 
  normalizePath(path.resolve(expandHome(args[0]))) :
  // For tests, use current directory if no args provided
  normalizePath(path.resolve(process.cwd()));

const tasksPluginConfigPath = path.join(vaultDirectory, '.obsidian', 'plugins', 'obsidian-tasks-plugin', 'data.json');

function parseCsvEnv(name: string): string[] | undefined {
  const raw = process.env[name];
  if (!raw) return undefined;
  const values = raw.split(',').map((v) => v.trim()).filter(Boolean);
  return values.length ? values : undefined;
}

function parseIntEnv(name: string): number | undefined {
  const raw = process.env[name];
  if (!raw) return undefined;
  const value = Number(raw);
  return Number.isFinite(value) ? value : undefined;
}

const DEFAULT_INCLUDE_PATHS = parseCsvEnv('MCP_TASKS_INCLUDE_PATHS');
const DEFAULT_EXCLUDE_PATHS = parseCsvEnv('MCP_TASKS_EXCLUDE_PATHS');
const DEFAULT_MAX_FILES = parseIntEnv('MCP_TASKS_MAX_FILES');
const DEFAULT_CONCURRENCY = parseIntEnv('MCP_TASKS_CONCURRENCY') ?? 8;

// Validate that the vault directory exists and is accessible
if (process.env.NODE_ENV !== 'test') {
  try {
    const stats = await fs.stat(vaultDirectory);
    if (!stats.isDirectory()) {
      console.error(`Error: ${args[0]} is not a directory`);
      process.exit(1);
    }
  } catch (error) {
    console.error(`Error accessing directory ${args[0]}:`, error);
    process.exit(1);
  }
}

// Security utilities
function validateRelativePath(relativePath: string): void {
  // Check for directory traversal attempts
  if (relativePath.includes('..')) {
    throw new Error(`Access denied - directory traversal detected in path: ${relativePath}`);
  }
  
  // Additional path validation can be added here if needed
}

async function resolvePath(relativePath: string = ''): Promise<string> {
  // Validate the relative path doesn't contain directory traversal
  validateRelativePath(relativePath);
  
  // If relativePath is empty, use vault directory directly
  const absolute = relativePath === '' 
    ? vaultDirectory 
    : path.join(vaultDirectory, relativePath);
  
  // For testing environment, we'll simplify path resolution
  if (process.env.NODE_ENV === 'test') {
    // Just return the joined path for tests
    return absolute;
  }
  
  // In production mode, handle symlinks and additional security checks
  try {
    const realPath = await fs.realpath(absolute);
    // Ensure the resolved path is still within the vault directory
    if (!normalizePath(realPath).startsWith(vaultDirectory)) {
      throw new Error("Access denied - symlink target outside vault directory");
    }
    return realPath;
  } catch (error) {
    // For new files that don't exist yet, verify parent directory
    const parentDir = path.dirname(absolute);
    try {
      const realParentPath = await fs.realpath(parentDir);
      if (!normalizePath(realParentPath).startsWith(vaultDirectory)) {
        throw new Error("Access denied - parent directory outside vault directory");
      }
      return absolute;
    } catch {
      throw new Error(`Parent directory does not exist: ${parentDir}`);
    }
  }
}

// Schema definitions
export const ListAllTasksArgsSchema = z.object({
  path: z.string().optional(),
  includePaths: z.array(z.string()).optional(),
  excludePaths: z.array(z.string()).optional(),
  includeNonTasks: z.boolean().optional(),
  includeFileMetadata: z.boolean().optional(),
  includeMetaDates: z.boolean().optional(),
  metaFallbackToFile: z.boolean().optional(),
  applyGlobalFilter: z.boolean().optional(),
  responseFormat: z.enum(['json', 'markdown']).optional(),
  useCache: z.boolean().optional(),
  responseLimit: z.number().int().positive().optional(),
});

export const QueryTasksArgsSchema = z.object({
  path: z.string().optional(),
  query: z.string(),
  queryFilePath: z.string().optional(),
  includePaths: z.array(z.string()).optional(),
  excludePaths: z.array(z.string()).optional(),
  includeNonTasks: z.boolean().optional(),
  includeFileMetadata: z.boolean().optional(),
  includeMetaDates: z.boolean().optional(),
  metaFallbackToFile: z.boolean().optional(),
  applyGlobalFilter: z.boolean().optional(),
  responseFormat: z.enum(['json', 'markdown']).optional(),
  useCache: z.boolean().optional(),
  responseLimit: z.number().int().positive().optional(),
});

// MCP tool input schemas must be JSON Schema objects (type: "object").
// zod-to-json-schema doesn't reliably support Zod v4, so we define these explicitly.
const ListAllTasksInputSchema = {
  type: "object",
  properties: {
    path: { type: "string", description: "Vault-relative path to scan (defaults to vault root)." },
    includePaths: { type: "array", items: { type: "string" } },
    excludePaths: { type: "array", items: { type: "string" } },
    includeNonTasks: { type: "boolean" },
    includeFileMetadata: { type: "boolean" },
    includeMetaDates: { type: "boolean" },
    metaFallbackToFile: { type: "boolean" },
    applyGlobalFilter: { type: "boolean" },
    responseFormat: { type: "string", enum: ["json", "markdown"] },
    useCache: { type: "boolean" },
    responseLimit: { type: "integer", minimum: 1 },
  },
  additionalProperties: false,
} as const;

const QueryTasksInputSchema = {
  type: "object",
  properties: {
    path: { type: "string", description: "Vault-relative path to scan (defaults to vault root)." },
    query: { type: "string", description: "Obsidian Tasks query syntax (one filter per line)." },
    queryFilePath: { type: "string", description: "Optional file path used for {{query.file.*}} expansion." },
    includePaths: { type: "array", items: { type: "string" } },
    excludePaths: { type: "array", items: { type: "string" } },
    includeNonTasks: { type: "boolean" },
    includeFileMetadata: { type: "boolean" },
    includeMetaDates: { type: "boolean" },
    metaFallbackToFile: { type: "boolean" },
    applyGlobalFilter: { type: "boolean" },
    responseFormat: { type: "string", enum: ["json", "markdown"] },
    useCache: { type: "boolean" },
    responseLimit: { type: "integer", minimum: 1 },
  },
  required: ["query"],
  additionalProperties: false,
} as const;

// Server setup
const server = new Server(
  {
    name: "optimike-obsidian-tasks-mcp",
    version: "0.2.0",
  },
  {
    capabilities: {
      tools: {},
    },
  },
);

// Tool implementations

import { parseTasks, queryTasks as filterTasks, taskToString, Task } from './TaskParser.js';

type StatusMap = Record<string, Task['status']>;
type CacheEntry = { mtimeMs: number; size: number; tasks: Task[] };
const tasksCache = new Map<string, CacheEntry>();
type TasksPluginConfig = {
  statusMap: StatusMap;
  statusNameMap: Record<string, string>;
  statusTypeMap: Record<string, string>;
  globalFilter: string;
  removeGlobalFilter: boolean;
  presets: Record<string, string>;
  taskFormat: string;
};
let cachedTasksConfig: TasksPluginConfig | null = null;
let cachedConfigMtime = 0;

const ALWAYS_EXCLUDE_DIRS = new Set(['.obsidian', '.trash', '.git']);

function fileExists(p: string): boolean {
  try {
    statSync(p);
    return true;
  } catch {
    return false;
  }
}

function normalizeForMatch(p: string): string {
  return normalizePath(p).toLowerCase();
}

function shouldExcludePath(filePath: string, includePaths?: string[], excludePaths?: string[]): boolean {
  const normalized = normalizeForMatch(filePath);

  if (excludePaths && excludePaths.length > 0) {
    for (const ex of excludePaths) {
      if (normalized.includes(normalizeForMatch(ex))) {
        return true;
      }
    }
  }

  if (includePaths && includePaths.length > 0) {
    const match = includePaths.some(inc => normalized.includes(normalizeForMatch(inc)));
    return !match;
  }

  return false;
}

async function loadTasksPluginConfig(): Promise<TasksPluginConfig> {
  if (!fileExists(tasksPluginConfigPath)) {
    return { statusMap: {}, statusNameMap: {}, statusTypeMap: {}, globalFilter: '', removeGlobalFilter: false, presets: {}, taskFormat: '' };
  }

  const stats = statSync(tasksPluginConfigPath);
  if (cachedTasksConfig && cachedConfigMtime === stats.mtimeMs) {
    return cachedTasksConfig;
  }

  try {
    const raw = await fs.readFile(tasksPluginConfigPath, 'utf-8');
    const config = JSON.parse(raw);
    const statusSettings = config?.statusSettings;
    const combined = [
      ...(statusSettings?.coreStatuses || []),
      ...(statusSettings?.customStatuses || []),
    ];

    const map: StatusMap = {};
    const nameMap: Record<string, string> = {};
    const typeMap: Record<string, string> = {};
    for (const s of combined) {
      const symbol = s?.symbol;
      const type = s?.type;
      const name = s?.name;
      if (typeof symbol !== 'string' || !symbol) continue;
      if (typeof name === 'string' && name) {
        nameMap[symbol] = name;
      }
      if (typeof type === 'string' && type) {
        typeMap[symbol] = type;
      }
      switch (type) {
        case 'DONE':
          map[symbol] = 'complete';
          break;
        case 'CANCELLED':
          map[symbol] = 'cancelled';
          break;
        case 'IN_PROGRESS':
          map[symbol] = 'in_progress';
          break;
        case 'NON_TASK':
          map[symbol] = 'non_task';
          break;
        case 'TODO':
        default:
          map[symbol] = 'incomplete';
          break;
      }
    }

    const globalFilter = typeof config?.globalFilter === 'string' ? config.globalFilter : '';
    const removeGlobalFilter = config?.removeGlobalFilter === true;
    const presets = typeof config?.presets === 'object' && config?.presets ? config.presets : {};
    const taskFormat = typeof config?.taskFormat === 'string' ? config.taskFormat : '';

    cachedTasksConfig = { statusMap: map, statusNameMap: nameMap, statusTypeMap: typeMap, globalFilter, removeGlobalFilter, presets, taskFormat };
    cachedConfigMtime = stats.mtimeMs;
    return cachedTasksConfig;
  } catch {
    return { statusMap: {}, statusNameMap: {}, statusTypeMap: {}, globalFilter: '', removeGlobalFilter: false, presets: {}, taskFormat: '' };
  }
}

function resolveIncludePath(startPath: string, includePath: string): string {
  if (includePath.includes('..')) {
    throw new Error(`Access denied - directory traversal detected in include path: ${includePath}`);
  }
  const expanded = expandHome(includePath);
  const absolute = path.isAbsolute(expanded)
    ? normalizePath(path.resolve(expanded))
    : normalizePath(path.resolve(startPath, expanded));
  if (!normalizePath(absolute).startsWith(normalizePath(startPath))) {
    throw new Error(`Include path outside vault is not allowed: ${includePath}`);
  }
  return absolute;
}

export async function findAllMarkdownFiles(startPath: string, includePaths?: string[]): Promise<string[]> {
  const patterns = (includePaths && includePaths.length > 0)
    ? includePaths.map((p) => path.join(resolveIncludePath(startPath, p), '**/*.md'))
    : [path.join(startPath, '**/*.md')];

  return glob(patterns, {
    dot: false,
    ignore: ['**/.obsidian/**', '**/.trash/**', '**/.git/**'],
  });
}

type MetaDates = { metaCreated?: string; metaModified?: string };

function pickBestCreatedMs(stats: { birthtimeMs: number; ctimeMs: number; mtimeMs: number }): number {
  // On some filesystems (notably WSL mounts), birthtimeMs can be 0 (Unix epoch).
  // Prefer a plausible timestamp, falling back to ctimeMs, then mtimeMs.
  const minPlausible = Date.UTC(2000, 0, 1); // 2000-01-01
  const isPlausible = (ms: number) => Number.isFinite(ms) && ms >= minPlausible;
  if (isPlausible(stats.birthtimeMs)) return stats.birthtimeMs;
  if (isPlausible(stats.ctimeMs)) return stats.ctimeMs;
  return stats.mtimeMs;
}

function extractFrontmatterMetaDates(content: string): MetaDates {
  const match = content.match(/^---\s*\n([\s\S]*?)\n---\s*/);
  if (!match) return {};
  const frontmatter = match[1];
  const lines = frontmatter.split(/\r?\n/);
  const map = new Map<string, string>();
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    let value = line.slice(idx + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1).trim();
    }
    if (!value) continue;
    map.set(key, value);
  }

  const createdKeys = ['création', 'creation', 'created', 'date_creation', 'date-created', 'created_at'];
  const modifiedKeys = ['modification', 'modified', 'updated', 'date_modification', 'date-modified', 'updated_at', 'modified_at'];
  let metaCreated: string | undefined;
  let metaModified: string | undefined;

  for (const key of createdKeys) {
    const value = map.get(key);
    if (value) { metaCreated = value; break; }
  }
  for (const key of modifiedKeys) {
    const value = map.get(key);
    if (value) { metaModified = value; break; }
  }

  return { metaCreated, metaModified };
}

function normalizeDateValue(value?: string): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  return trimmed;
}

export async function extractTasksFromFile(
  filePath: string,
  statusMap: StatusMap,
  statusNameMap: Record<string, string>,
  statusTypeMap: Record<string, string>,
  taskFormat: string,
  includeFileMetadata: boolean,
  includeMetaDates: boolean,
  metaFallbackToFile: boolean,
  useCache: boolean
): Promise<Task[]> {
  try {
    let fileStats: { mtimeMs: number; size: number; birthtimeMs: number; ctimeMs: number } | null = null;
    const cacheKey = `${filePath}::file=${includeFileMetadata}::meta=${includeMetaDates}::fallback=${metaFallbackToFile}`;

    if (useCache) {
      try {
        const stats = await fs.stat(filePath);
        fileStats = { mtimeMs: stats.mtimeMs, size: stats.size, birthtimeMs: stats.birthtimeMs, ctimeMs: stats.ctimeMs };
        const cached = tasksCache.get(cacheKey);
        if (cached && cached.mtimeMs === stats.mtimeMs && cached.size === stats.size) {
          return cached.tasks;
        }
      } catch {
        // fallthrough to read
      }
    }

    const content = await fs.readFile(filePath, 'utf-8');

    const tasks = parseTasks(content, filePath, {
      statusMap,
      statusNameMap,
      statusTypeMap,
      taskFormat,
      ignoreCodeBlocks: true,
      ignoreFrontmatter: true,
    });

    let fileCreated: string | undefined;
    let fileModified: string | undefined;
    if (includeFileMetadata || (includeMetaDates && metaFallbackToFile)) {
      if (!fileStats) {
        const stats = await fs.stat(filePath);
        fileStats = { mtimeMs: stats.mtimeMs, size: stats.size, birthtimeMs: stats.birthtimeMs, ctimeMs: stats.ctimeMs };
      }
      fileCreated = new Date(pickBestCreatedMs(fileStats)).toISOString();
      fileModified = new Date(fileStats.mtimeMs).toISOString();
    }

    if (includeFileMetadata) {
      for (const t of tasks) {
        t.fileCreatedDate = fileCreated;
        t.fileModifiedDate = fileModified;
      }
    }

    if (includeMetaDates) {
      const meta = extractFrontmatterMetaDates(content);
      const metaCreated = normalizeDateValue(meta.metaCreated) ?? (metaFallbackToFile ? fileCreated : undefined);
      const metaModified = normalizeDateValue(meta.metaModified) ?? (metaFallbackToFile ? fileModified : undefined);
      for (const t of tasks) {
        t.metaCreatedDate = metaCreated;
        t.metaModifiedDate = metaModified;
      }
    }

    if (useCache && fileStats) {
      tasksCache.set(cacheKey, { mtimeMs: fileStats.mtimeMs, size: fileStats.size, tasks });
    }

    return tasks;
  } catch (error) {
    console.error(`Error processing file ${filePath}:`, error);
    return [];
  }
}

export async function findAllTasks(
  directoryPath: string,
  statusMap: StatusMap,
  statusNameMap: Record<string, string>,
  statusTypeMap: Record<string, string>,
  taskFormat: string,
  includePaths?: string[],
  excludePaths?: string[],
  includeNonTasks?: boolean,
  includeFileMetadata: boolean = false,
  includeMetaDates: boolean = false,
  metaFallbackToFile: boolean = true,
  useCache: boolean = true,
  maxTasks?: number,
  maxFiles?: number,
  concurrency: number = DEFAULT_CONCURRENCY
): Promise<Task[]> {
  const markdownFiles = await findAllMarkdownFiles(directoryPath, includePaths);
  const fileLimit = typeof maxFiles === 'number' && maxFiles > 0
    ? Math.min(maxFiles, markdownFiles.length)
    : markdownFiles.length;
  const filesToProcess = markdownFiles.slice(0, fileLimit);
  const allTasks: Task[] = [];

  const processFile = async (filePath: string): Promise<void> => {
    try {
      // Skip excluded directories by name (safety net)
      const parts = normalizePath(filePath).split(path.sep);
      if (parts.some(p => ALWAYS_EXCLUDE_DIRS.has(p))) {
        return;
      }

      if (shouldExcludePath(filePath, includePaths, excludePaths)) {
        return;
      }

      const tasks = await extractTasksFromFile(
        filePath,
        statusMap,
        statusNameMap,
        statusTypeMap,
        taskFormat,
        includeFileMetadata,
        includeMetaDates,
        metaFallbackToFile,
        useCache
      );
      for (const t of tasks) {
        if (!includeNonTasks && t.status === 'non_task') {
          continue;
        }
        allTasks.push(t);
      }
    } catch (error) {
      console.error(`Error processing file ${filePath}:`, error);
    }
  };

  const shouldShortCircuit = typeof maxTasks === 'number' && maxTasks > 0;
  if (shouldShortCircuit) {
    for (const filePath of filesToProcess) {
      if (allTasks.length >= (maxTasks as number)) break;
      await processFile(filePath);
    }
    return allTasks.slice(0, maxTasks);
  }

  const poolSize = Math.max(1, Math.min(concurrency, filesToProcess.length));
  let nextIndex = 0;
  const workers = Array.from({ length: poolSize }, async () => {
    while (nextIndex < filesToProcess.length) {
      const i = nextIndex++;
      await processFile(filesToProcess[i]);
    }
  });
  await Promise.all(workers);
  
  return allTasks;
}

// Apply a query to a list of tasks
export function queryTasks(tasks: Task[], queryText: string): Task[] {
  try {
    return filterTasks(tasks, queryText);
  } catch (error) {
    console.error(`Error querying tasks: ${error}`);
    // If the query fails, return an empty list
    return [];
  }
}

// Helper function to serialize tasks to JSON
export function serializeTasksToJson(tasks: Task[]): string {
  return JSON.stringify(tasks, null, 2);
}

export function serializeTasksToMarkdown(tasks: Task[]): string {
  return tasks.map(taskToString).join('\n');
}

function needsFileMetadata(queryText: string): boolean {
  return /file\s+(created|modified)\s+(before|after|on)\s+\d{4}-\d{2}-\d{2}/i.test(queryText);
}

function needsMetaDates(queryText: string): boolean {
  return /meta\s+(created|modified)\s+(before|after|on)\s+\d{4}-\d{2}-\d{2}/i.test(queryText);
}

function mergeGlobalFilter(queryText: string, globalFilter: string): string {
  const trimmedGlobal = globalFilter.trim();
  if (!trimmedGlobal) return queryText;
  const trimmedQuery = queryText.trim();
  if (!trimmedQuery) return trimmedGlobal;
  return `${trimmedGlobal}\n${trimmedQuery}`;
}

function expandPresets(queryText: string, presets: Record<string, string>): string {
  let expanded = queryText;
  expanded = expanded.replace(/\{\{\s*preset\.([^}]+)\s*\}\}/gi, (m, name) => {
    const key = String(name || '').trim();
    return presets[key] ?? m;
  });

  const lines = expanded.split('\n');
  const out: string[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    const presetMatch = trimmed.match(/^preset\s+(.+)$/i);
    if (presetMatch) {
      const key = presetMatch[1].trim();
      const preset = presets[key];
      if (preset) {
        out.push(...preset.split('\n'));
        continue;
      }
    }
    out.push(line);
  }
  return out.join('\n');
}

function applyQueryFilePlaceholders(queryText: string, queryFilePath?: string): string {
  if (!queryFilePath) return queryText;
  const absolute = path.isAbsolute(queryFilePath)
    ? normalizePath(queryFilePath)
    : normalizePath(path.join(vaultDirectory, queryFilePath));
  let relative = absolute;
  if (normalizePath(absolute).startsWith(vaultDirectory)) {
    relative = normalizePath(path.relative(vaultDirectory, absolute));
  }

  const folder = path.dirname(relative).replace(/\\/g, '/');
  const root = folder.split('/').filter(Boolean)[0] || '';
  return queryText
    .replace(/\{\{\s*query\.file\.path\s*\}\}/gi, relative.replace(/\\/g, '/'))
    .replace(/\{\{\s*query\.file\.folder\s*\}\}/gi, folder === '.' ? '' : folder)
    .replace(/\{\{\s*query\.file\.root\s*\}\}/gi, root);
}


// Tool handlers
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "list_all_tasks",
        description:
          "Extract all tasks from markdown files in a directory. " +
          "Recursively scans all markdown files and extracts tasks based on the Obsidian Tasks format. " +
          "Returns structured data about each task including status, dates, and tags. " +
          "Supports include/exclude path filters, optional non-task inclusion, optional file metadata (created/modified), optional meta dates (frontmatter), and optional global filter application. " +
          "The path parameter is optional; if not specified, it defaults to the vault root directory. " +
          "The path must be relative to the vault directory and cannot contain directory traversal components (..).",
        inputSchema: ListAllTasksInputSchema,
      },
      {
        name: "query_tasks",
        description:
          "Search for tasks based on Obsidian Tasks query syntax. " +
          "Allows filtering tasks by status, dates (including relative, EN/FR), description, tags, priority, and path. " +
          "Each line in the query is treated as a filter with AND logic between lines. " +
          "Returns only tasks that match all query conditions. " +
          "Examples of task filters are `done`, `not done`, `tag include #foo/bar`, `tag do not include #potato`, `description includes keyword`. " +
          "Supports include/exclude path filters, optional non-task inclusion, optional file metadata (created/modified), optional meta dates (frontmatter), and optional global filter application. " +
          "The path parameter is optional; if not specified, it defaults to the vault root directory. " +
          "The path must be relative to the vault directory and cannot contain directory traversal components (..).",
        inputSchema: QueryTasksInputSchema,
      }
    ],
  };
});


// Exported handlers for testing
export async function handleListAllTasksRequest(args: any) {
  try {
    const parsed = ListAllTasksArgsSchema.safeParse(args);
    if (!parsed.success) {
      throw new Error(`Invalid arguments for list_all_tasks: ${parsed.error}`);
    }
    
    // Use specified path or default to vault root directory
    const relativePath = parsed.data.path || '';
    
    // Validate and resolve the path (even in test mode)
    const validPath = await resolvePath(relativePath);
    
    const pluginConfig = await loadTasksPluginConfig();
    const applyGlobalFilter = parsed.data.applyGlobalFilter ?? false;
    const expandedGlobalFilter = expandPresets(pluginConfig.globalFilter || '', pluginConfig.presets || {});
    const effectiveGlobalFilter = (applyGlobalFilter && !pluginConfig.removeGlobalFilter)
      ? expandedGlobalFilter
      : '';
    const includeMetaDates = parsed.data.includeMetaDates ?? needsMetaDates(effectiveGlobalFilter);
    const metaFallbackToFile = parsed.data.metaFallbackToFile ?? true;
    const includeFileMetadata = parsed.data.includeFileMetadata ?? (needsFileMetadata(effectiveGlobalFilter) || (includeMetaDates && metaFallbackToFile));
    const includePaths = parsed.data.includePaths ?? DEFAULT_INCLUDE_PATHS;
    const excludePaths = [
      ...(DEFAULT_EXCLUDE_PATHS ?? []),
      ...(parsed.data.excludePaths ?? []),
    ];
    const limit = parsed.data.responseLimit;
    const maxTasks = (limit && limit > 0 && !effectiveGlobalFilter) ? limit : undefined;
    const tasks = await findAllTasks(
      validPath,
      pluginConfig.statusMap,
      pluginConfig.statusNameMap,
      pluginConfig.statusTypeMap,
      pluginConfig.taskFormat,
      includePaths,
      excludePaths,
      parsed.data.includeNonTasks,
      includeFileMetadata,
      includeMetaDates,
      metaFallbackToFile,
      parsed.data.useCache ?? true,
      maxTasks,
      DEFAULT_MAX_FILES,
      DEFAULT_CONCURRENCY,
    );

    const filteredTasks = effectiveGlobalFilter
      ? queryTasks(tasks, effectiveGlobalFilter)
      : tasks;

    const responseFormat = parsed.data.responseFormat ?? 'json';
    const finalTasks = (limit && limit > 0) ? filteredTasks.slice(0, limit) : filteredTasks;
    const text = responseFormat === 'markdown'
      ? serializeTasksToMarkdown(finalTasks)
      : serializeTasksToJson(finalTasks);
    return {
      content: [{ type: "text", text }],
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [{ type: "text", text: `Error: ${errorMessage}` }],
      isError: true,
    };
  }
}

export async function handleQueryTasksRequest(args: any) {
  try {
    const parsed = QueryTasksArgsSchema.safeParse(args);
    if (!parsed.success) {
      throw new Error(`Invalid arguments for query_tasks: ${parsed.error}`);
    }
    
    // Use specified path or default to vault root directory
    const relativePath = parsed.data.path || '';
    
    // Validate and resolve the path (even in test mode)
    const validPath = await resolvePath(relativePath);
    
    // Get all tasks from the directory
    const pluginConfig = await loadTasksPluginConfig();
    const applyGlobalFilter = parsed.data.applyGlobalFilter ?? true;
    const queryWithPresets = expandPresets(parsed.data.query, pluginConfig.presets || {});
    const queryWithFile = applyQueryFilePlaceholders(queryWithPresets, parsed.data.queryFilePath);
    const mergedQuery = (applyGlobalFilter && !pluginConfig.removeGlobalFilter)
      ? mergeGlobalFilter(queryWithFile, pluginConfig.globalFilter)
      : queryWithFile;
    const includeMetaDates = parsed.data.includeMetaDates ?? needsMetaDates(mergedQuery);
    const metaFallbackToFile = parsed.data.metaFallbackToFile ?? true;
    const includeFileMetadata = parsed.data.includeFileMetadata ?? (needsFileMetadata(mergedQuery) || (includeMetaDates && metaFallbackToFile));
    const includePaths = parsed.data.includePaths ?? DEFAULT_INCLUDE_PATHS;
    const excludePaths = [
      ...(DEFAULT_EXCLUDE_PATHS ?? []),
      ...(parsed.data.excludePaths ?? []),
    ];
    const allTasks = await findAllTasks(
      validPath,
      pluginConfig.statusMap,
      pluginConfig.statusNameMap,
      pluginConfig.statusTypeMap,
      pluginConfig.taskFormat,
      includePaths,
      excludePaths,
      parsed.data.includeNonTasks,
      includeFileMetadata,
      includeMetaDates,
      metaFallbackToFile,
      parsed.data.useCache ?? true,
      undefined,
      DEFAULT_MAX_FILES,
      DEFAULT_CONCURRENCY,
    );
    
    // Apply the query to filter tasks
    const filteredTasks = queryTasks(allTasks, mergedQuery);
    
    const responseFormat = parsed.data.responseFormat ?? 'json';
    const limit = parsed.data.responseLimit;
    const finalTasks = (limit && limit > 0) ? filteredTasks.slice(0, limit) : filteredTasks;
    const text = responseFormat === 'markdown'
      ? serializeTasksToMarkdown(finalTasks)
      : serializeTasksToJson(finalTasks);
    return {
      content: [{ type: "text", text }],
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [{ type: "text", text: `Error: ${errorMessage}` }],
      isError: true,
    };
  }
}

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  try {
    const { name, arguments: args } = request.params;

    if (name === "list_all_tasks") {
      return await handleListAllTasksRequest(args);
    }
    
    if (name === "query_tasks") {
      return await handleQueryTasksRequest(args);
    }
    
    throw new Error(`Unknown tool: ${name}`);
    
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [{ type: "text", text: `Error: ${errorMessage}` }],
      isError: true,
    };
  }
});

// Start server
async function runServer() {
  const transportType = (process.env.MCP_TRANSPORT_TYPE || 'stdio').toLowerCase();

  if (transportType === 'stdio') {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("Optimike Obsidian Tasks MCP running on stdio");
    console.error("Vault directory:", vaultDirectory);
    return;
  }

  if (transportType === 'http') {
    const host = process.env.MCP_HTTP_HOST || '127.0.0.1';
    const port = Number(process.env.MCP_HTTP_PORT || '3011');
    const sessionMode = (process.env.MCP_HTTP_SESSION_MODE || 'stateful').toLowerCase();
    const sessionIdGenerator = sessionMode === 'stateless' ? undefined : () => crypto.randomUUID();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator });
    await server.connect(transport);

    const httpServer = http.createServer(async (req, res) => {
      await transport.handleRequest(req, res);
    });

    await new Promise<void>((resolve) => {
      httpServer.listen(port, host, () => resolve());
    });

    console.error(`Optimike Obsidian Tasks MCP running on http at http://${host}:${port}`);
    console.error("Vault directory:", vaultDirectory);
    console.error(`Session mode: ${sessionMode}`);
    return;
  }

  throw new Error(`Unsupported MCP_TRANSPORT_TYPE: ${transportType}`);
}

// Don't run the server in test mode
if (process.env.NODE_ENV !== 'test' && process.env.DISABLE_SERVER !== 'true') {
  runServer().catch((error) => {
    console.error("Fatal error running server:", error);
    process.exit(1);
  });
}
