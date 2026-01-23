/**
 * TaskParser - Inspired by Obsidian Tasks but simplified for MCP
 * 
 * This file contains a simplified implementation inspired by Obsidian Tasks
 * but without the dependency complexity.
 */

import moment from 'moment';
import path from 'path';
import * as chrono from 'chrono-node';

// Interface for our task object
export interface Task {
  id: string;
  description: string;
  status: 'complete' | 'incomplete' | 'cancelled' | 'in_progress' | 'non_task';
  statusSymbol: string;
  statusName?: string;
  statusType?: string;
  filePath: string;
  lineNumber: number;
  tags: string[];
  dueDate?: string;
  scheduledDate?: string;
  createdDate?: string;
  doneDate?: string;
  cancelledDate?: string;
  startDate?: string;
  priority?: string;
  recurrence?: string;
  metaCreatedDate?: string;
  metaModifiedDate?: string;
  fileCreatedDate?: string;
  fileModifiedDate?: string;
  originalMarkdown: string;
}

export interface ParseOptions {
  statusMap?: Record<string, Task['status']>;
  statusNameMap?: Record<string, string>;
  statusTypeMap?: Record<string, string>;
  taskFormat?: string;
  ignoreCodeBlocks?: boolean;
  ignoreFrontmatter?: boolean;
}

// Regular expressions based on Obsidian Tasks conventions
export class TaskRegex {
  // Matches indentation before a list marker (including > for potentially nested blockquotes or Obsidian callouts)
  static readonly indentationRegex = /^([\s\t>]*)/;

  // Matches - * and + list markers, or numbered list markers, for example 1. and 1)
  static readonly listMarkerRegex = /([-*+]|[0-9]+[.)])/;

  // Matches a checkbox and saves the status character inside
  static readonly checkboxRegex = /\[(.)\]/u;

  // Matches the rest of the task after the checkbox.
  static readonly afterCheckboxRegex = / *(.*)/u;

  // Main regex for parsing a line. It matches the following:
  // - Indentation
  // - List marker
  // - Status character
  // - Rest of task after checkbox markdown
  static readonly taskRegex = new RegExp(
    TaskRegex.indentationRegex.source +
    TaskRegex.listMarkerRegex.source +
    ' +' +
    TaskRegex.checkboxRegex.source +
    TaskRegex.afterCheckboxRegex.source,
    'u',
  );
  
  // Matches hashtags in task descriptions
  static readonly hashTags = /(^|\s)#[^ !@#$%^&*(),.?":{}|<>]+/g;
  
  // Date related regular expressions - matches emoji followed by date
  static readonly dueDateRegex = /[📅🗓️]\s?(\d{4}-\d{2}-\d{2})/;
  static readonly scheduledDateRegex = /⏳\s?(\d{4}-\d{2}-\d{2})/;
  static readonly startDateRegex = /🛫\s?(\d{4}-\d{2}-\d{2})/;
  static readonly createdDateRegex = /➕\s?(\d{4}-\d{2}-\d{2})/;
  
  // Priority emoji - order is important! Longest pattern first
  static readonly priorityRegex = /(⏫⏫|⏫|🔼|🔽|⏬)/g;
  
  // Recurrence
  static readonly recurrenceRegex = /🔁\s?(.*?)(?=(\s|$))/;

  // Completion date
  static readonly doneDateRegex = /✅\s?(\d{4}-\d{2}-\d{2})/;

  // Cancelled date
  static readonly cancelledDateRegex = /❌\s?(\d{4}-\d{2}-\d{2})/;

  // Dataview inline fields e.g. [due:: 2024-01-01]
  static readonly dataviewFieldRegex = /\[(due|scheduled|start|created|done|cancelled)::\s*([^\]]+)\]/gi;
}

/**
 * Parse a string containing text that may have tasks and extract Task objects.
 * 
 * @param text The text to parse for tasks
 * @param filePath Optional file path for the task location
 * @returns Array of Task objects
 */
export function parseTasks(text: string, filePath: string = '', options: ParseOptions = {}): Task[] {
  const lines = text.split('\n');
  const tasks: Task[] = [];
  let inCodeBlock = false;
  let inFrontmatter = false;
  const ignoreCodeBlocks = options.ignoreCodeBlocks !== false;
  const ignoreFrontmatter = options.ignoreFrontmatter !== false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (ignoreFrontmatter) {
      const trimmed = line.trim();
      if (i === 0 && trimmed === '---') {
        inFrontmatter = true;
        continue;
      }
      if (inFrontmatter) {
        if (trimmed === '---') {
          inFrontmatter = false;
        }
        continue;
      }
    }

    if (ignoreCodeBlocks) {
      const trimmed = line.trim();
      if (trimmed.startsWith('```') || trimmed.startsWith('~~~')) {
        inCodeBlock = !inCodeBlock;
        continue;
      }
      if (inCodeBlock) {
        continue;
      }
    }

    const task = parseTaskLine(line, filePath, i, options);
    if (task) {
      tasks.push(task);
    }
  }

  return tasks;
}

/**
 * Parse a task from a line of text
 */
export function parseTaskLine(line: string, filePath: string = '', lineNumber: number = 0, options: ParseOptions = {}): Task | null {
  const match = line.match(TaskRegex.taskRegex);
  if (!match) {
    return null;
  }
  
  const statusChar = match[3];
  let description = match[4].trim();
  const taskFormat = (options.taskFormat || '').toLowerCase();
  const allowDataview = taskFormat.includes('dataview');
  
  // Extract tags
  const tags = (description.match(TaskRegex.hashTags) || [])
    .map(tag => tag.trim())
    .filter(tag => tag.length > 0);
  
  // Check for dates
  const dueMatch = description.match(TaskRegex.dueDateRegex);
  const scheduledMatch = description.match(TaskRegex.scheduledDateRegex);
  const startMatch = description.match(TaskRegex.startDateRegex);
  const createdMatch = description.match(TaskRegex.createdDateRegex);
  const recurrenceMatch = description.match(TaskRegex.recurrenceRegex);
  const doneMatch = description.match(TaskRegex.doneDateRegex);
  const cancelledMatch = description.match(TaskRegex.cancelledDateRegex);

  // Parse dataview inline fields if enabled
  let dvDue: string | undefined;
  let dvScheduled: string | undefined;
  let dvStart: string | undefined;
  let dvCreated: string | undefined;
  let dvDone: string | undefined;
  let dvCancelled: string | undefined;
  if (allowDataview) {
    const dvMatches = Array.from(description.matchAll(TaskRegex.dataviewFieldRegex));
    if (dvMatches.length > 0) {
      for (const m of dvMatches) {
        const key = m[1].toLowerCase();
        const raw = m[2].trim();
        const parsed = parseDateExpression(raw);
        if (!parsed) continue;
        if (key === 'due') dvDue = parsed;
        if (key === 'scheduled') dvScheduled = parsed;
        if (key === 'start') dvStart = parsed;
        if (key === 'created') dvCreated = parsed;
        if (key === 'done') dvDone = parsed;
        if (key === 'cancelled') dvCancelled = parsed;
      }
      description = description.replace(TaskRegex.dataviewFieldRegex, '').replace(/\s{2,}/g, ' ').trim();
    }
  }
  
  // Determine priority - check for highest priority first
  let priority = undefined;
  
  // Use regex to find all priority markers in order of appearance
  const priorityMatches = description.match(/⏫⏫|⏫|🔼|🔽|⏬/g);
  
  if (priorityMatches && priorityMatches.length > 0) {
    // Use the first priority marker found
    const firstPriority = priorityMatches[0];
    
    if (firstPriority === '⏫⏫') priority = 'highest';
    else if (firstPriority === '⏫') priority = 'high';
    else if (firstPriority === '🔼') priority = 'medium';
    else if (firstPriority === '🔽') priority = 'low';
    else if (firstPriority === '⏬') priority = 'lowest';
  }
  
  // Create a unique ID
  const id = `${filePath}:${lineNumber}`;
  
  // Determine task status from the statusChar
  let status: Task['status'] = 'incomplete';
  if (options.statusMap && statusChar in options.statusMap) {
    status = options.statusMap[statusChar];
  } else if (['x', 'X'].includes(statusChar)) {
    status = 'complete';
  } else if (['-'].includes(statusChar)) {
    status = 'cancelled';
  } else if (['/'].includes(statusChar)) {
    status = 'in_progress';
  } else if ([' ', '>', '<'].includes(statusChar)) {
    status = 'incomplete';
  } else {
    // Any other character is treated as a non-task
    status = 'non_task';
  }
  
  const task: Task = {
    id,
    description,
    status,
    statusSymbol: statusChar,
    statusName: options.statusNameMap ? options.statusNameMap[statusChar] : undefined,
    statusType: options.statusTypeMap ? options.statusTypeMap[statusChar] : undefined,
    filePath,
    lineNumber,
    tags,
    dueDate: (dueMatch ? dueMatch[1] : undefined) ?? dvDue,
    scheduledDate: (scheduledMatch ? scheduledMatch[1] : undefined) ?? dvScheduled,
    startDate: (startMatch ? startMatch[1] : undefined) ?? dvStart,
    createdDate: (createdMatch ? createdMatch[1] : undefined) ?? dvCreated,
    doneDate: (doneMatch ? doneMatch[1] : undefined) ?? dvDone,
    cancelledDate: (cancelledMatch ? cancelledMatch[1] : undefined) ?? dvCancelled,
    priority,
    recurrence: recurrenceMatch ? recurrenceMatch[1] : undefined,
    originalMarkdown: line
  };
  
  return task;
}

/**
 * Apply a filter function to a task
 */
export function applyFilter(task: Task, filter: string): boolean {
  filter = filter.toLowerCase().trim();
  
  // Boolean combinations with AND, OR, NOT
  if (filter.includes(' AND ')) {
    const parts = filter.split(' AND ');
    return parts.every(part => applyFilter(task, part.trim()));
  }
  
  if (filter.includes(' OR ')) {
    const parts = filter.split(' OR ');
    return parts.some(part => applyFilter(task, part.trim()));
  }
  
  // Case insensitive versions
  if (filter.includes(' and ')) {
    const parts = filter.split(' and ');
    return parts.every(part => applyFilter(task, part.trim()));
  }
  
  if (filter.includes(' or ')) {
    const parts = filter.split(' or ');
    return parts.some(part => applyFilter(task, part.trim()));
  }
  
  if (filter.startsWith('not ')) {
    const subFilter = filter.substring(4);
    return !applyFilter(task, subFilter);
  }
  
  const statusType = (task.statusType || '').toUpperCase();

  // Status-based filters (align with Tasks semantics)
  if (filter === 'done') {
    if (statusType) {
      return statusType === 'DONE' || statusType === 'CANCELLED' || statusType === 'NON_TASK';
    }
    return task.status === 'complete' || task.status === 'cancelled' || task.status === 'non_task';
  }
  if (filter === 'not done') {
    if (statusType) {
      return statusType === 'TODO' || statusType === 'IN_PROGRESS';
    }
    return task.status === 'incomplete' || task.status === 'in_progress';
  }
  if (filter === 'cancelled') {
    return statusType ? statusType === 'CANCELLED' : task.status === 'cancelled';
  }
  if (filter === 'in progress') {
    return statusType ? statusType === 'IN_PROGRESS' : task.status === 'in_progress';
  }
  if (filter === 'todo') {
    return statusType ? statusType === 'TODO' : task.status === 'incomplete';
  }
  if (filter === 'not cancelled') {
    return statusType ? statusType !== 'CANCELLED' : task.status !== 'cancelled';
  }

  if (filter === 'non task' || filter === 'non-task') {
    return task.status === 'non_task';
  }

  if (filter === 'task' || filter === 'is task') {
    return task.status !== 'non_task';
  }

  const statusTypeMatch = filter.match(/^status[ .]?type\s+is\s+(.+)$/);
  if (statusTypeMatch) {
    const wanted = normalizeStatusType(statusTypeMatch[1]);
    if (!wanted) return false;
    return statusType === wanted;
  }

  const statusTypeNotMatch = filter.match(/^status[ .]?type\s+is\s+not\s+(.+)$/);
  if (statusTypeNotMatch) {
    const unwanted = normalizeStatusType(statusTypeNotMatch[1]);
    if (!unwanted) return true;
    return statusType !== unwanted;
  }

  const statusNameMatch = filter.match(/^status[ .]?name\s+is\s+(.+)$/);
  if (statusNameMatch) {
    const wanted = statusNameMatch[1].trim().replace(/^["']|["']$/g, '').toLowerCase();
    return (task.statusName || '').toLowerCase() === wanted;
  }

  const statusNameNotMatch = filter.match(/^status[ .]?name\s+is\s+not\s+(.+)$/);
  if (statusNameNotMatch) {
    const unwanted = statusNameNotMatch[1].trim().replace(/^["']|["']$/g, '').toLowerCase();
    return (task.statusName || '').toLowerCase() !== unwanted;
  }

  if (filter === 'has done date') {
    return task.doneDate !== undefined;
  }
  if (filter === 'no done date') {
    return task.doneDate === undefined;
  }
  if (filter.startsWith('done ')) {
    return matchDateFilter(filter, 'done', task.doneDate);
  }

  if (filter === 'has cancelled date') {
    return task.cancelledDate !== undefined;
  }
  if (filter === 'no cancelled date') {
    return task.cancelledDate === undefined;
  }
  if (filter.startsWith('cancelled ')) {
    return matchDateFilter(filter, 'cancelled', task.cancelledDate);
  }
  
  // Due date filters
  if (filter.startsWith('due') || filter === 'has due date' || filter === 'no due date') {
    if (filter === 'no due date') {
      return task.dueDate === undefined;
    }
    if (filter === 'has due date') {
      return task.dueDate !== undefined;
    }
    return matchDateFilter(filter, 'due', task.dueDate);
  }

  if (filter.startsWith('scheduled') || filter === 'has scheduled date' || filter === 'no scheduled date') {
    if (filter === 'no scheduled date') {
      return task.scheduledDate === undefined;
    }
    if (filter === 'has scheduled date') {
      return task.scheduledDate !== undefined;
    }
    return matchDateFilter(filter, 'scheduled', task.scheduledDate);
  }

  if (filter.startsWith('start') || filter === 'has start date' || filter === 'no start date') {
    if (filter === 'no start date') {
      return task.startDate === undefined;
    }
    if (filter === 'has start date') {
      return task.startDate !== undefined;
    }
    return matchDateFilter(filter, 'start', task.startDate);
  }

  if (filter.startsWith('created') || filter === 'has created date' || filter === 'no created date') {
    if (filter === 'no created date') {
      return task.createdDate === undefined;
    }
    if (filter === 'has created date') {
      return task.createdDate !== undefined;
    }
    return matchDateFilter(filter, 'created', task.createdDate);
  }
  
  // Tag filters
  if (filter === 'no tags') {
    return !task.tags || task.tags.length === 0;
  }
  
  if (filter === 'has tags') {
    return task.tags && task.tags.length > 0;
  }
  
  if (filter.startsWith('tag includes ') || filter.startsWith('tag include ')) {
    const raw = filter.startsWith('tag includes ')
      ? filter.split('tag includes ')[1]
      : filter.split('tag include ')[1];
    const tagToFind = (raw || '').trim().replace(/^#/, '');
    if (!tagToFind) return false;
    return task.tags && task.tags.some(tag => tag.replace(/^#/, '').includes(tagToFind));
  }
  
  if (filter.startsWith('has tag ')) {
    const tagToFind = filter.substring(8).trim().replace(/^#/, '');
    return task.tags && task.tags.some(tag => {
      // Remove # prefix for comparison
      const normalizedTag = tag.replace(/^#/, '');
      // For exact matching, check if the tag equals the search term
      return normalizedTag === tagToFind;
    });
  }

  if (filter.startsWith('tag do not include') || filter.startsWith('tag does not include')) {
    const tagToExclude = filter.split('does not include')[1].trim().replace(/^#/, '');
    if (!tagToExclude) return true;
    return !task.tags || !task.tags.some(tag => tag.replace(/^#/, '').includes(tagToExclude));
  }
  
  // Path/filename filters
  if (filter.startsWith('path includes')) {
    const pathToFind = filter.split('includes')[1].trim();
    return task.filePath.toLowerCase().includes(pathToFind.toLowerCase());
  }
  
  if (filter.startsWith('path does not include')) {
    const pathToExclude = filter.split('does not include')[1].trim();
    return !task.filePath.toLowerCase().includes(pathToExclude.toLowerCase());
  }

  if (filter.startsWith('folder includes')) {
    const folderToFind = filter.split('includes')[1].trim().toLowerCase();
    const folder = path.dirname(task.filePath).toLowerCase();
    return folder.includes(folderToFind);
  }

  if (filter.startsWith('folder does not include')) {
    const folderToExclude = filter.split('does not include')[1].trim().toLowerCase();
    const folder = path.dirname(task.filePath).toLowerCase();
    return !folder.includes(folderToExclude);
  }

  if (filter.startsWith('filename includes')) {
    const nameToFind = filter.split('includes')[1].trim().toLowerCase();
    const name = path.basename(task.filePath).toLowerCase();
    return name.includes(nameToFind);
  }

  if (filter.startsWith('filename does not include')) {
    const nameToExclude = filter.split('does not include')[1].trim().toLowerCase();
    const name = path.basename(task.filePath).toLowerCase();
    return !name.includes(nameToExclude);
  }
  
  // Description filters
  if (filter.startsWith('description includes')) {
    const textToFind = filter.split('includes')[1].trim();
    return task.description.toLowerCase().includes(textToFind.toLowerCase());
  }
  
  if (filter.startsWith('description does not include')) {
    const textToExclude = filter.split('does not include')[1].trim();
    return !task.description.toLowerCase().includes(textToExclude.toLowerCase());
  }

  // File metadata date filters
  if (filter.startsWith('file created')) {
    return matchDateFilter(filter, 'file created', task.fileCreatedDate);
  }
  if (filter.startsWith('file modified')) {
    return matchDateFilter(filter, 'file modified', task.fileModifiedDate);
  }
  if (filter.startsWith('meta created')) {
    return matchDateFilter(filter, 'meta created', task.metaCreatedDate);
  }
  if (filter.startsWith('meta modified')) {
    return matchDateFilter(filter, 'meta modified', task.metaModifiedDate);
  }
  
  // Priority filters
  if (filter.startsWith('priority is')) {
    const priority = filter.split('priority is')[1].trim();
    if (priority === 'highest') {
      return task.priority === 'highest';
    }
    if (priority === 'high') {
      return task.priority === 'high';
    }
    if (priority === 'medium') {
      return task.priority === 'medium';
    }
    if (priority === 'low') {
      return task.priority === 'low';
    }
    if (priority === 'lowest') {
      return task.priority === 'lowest';
    }
    if (priority === 'none') {
      return task.priority === undefined;
    }
  }
  
  // If no filter match, check if description contains the filter text
  return task.description.toLowerCase().includes(filter);
}

/**
 * Parse a query string into a set of filter lines
 */
export function parseQuery(queryText: string): string[] {
  // Split into lines and remove empty ones and comments
  return queryText.split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#'));
}

/**
 * Apply a query to a list of tasks
 */
export function queryTasks(tasks: Task[], queryText: string): Task[] {
  const filters = parseQuery(queryText);
  
  // Apply all filters in sequence (AND logic between lines)
  return tasks.filter(task => {
    for (const filter of filters) {
      if (!applyFilter(task, filter)) {
        return false;
      }
    }
    return true;
  });
}

/**
 * Convert a Task object back to its string representation
 * 
 * @param task Task object to convert
 * @returns String representation of the task
 */
export function taskToString(task: Task): string {
  return task.originalMarkdown;
}

function normalizeStatusType(input: string): string | null {
  const cleaned = input.trim().toLowerCase();
  const map: Record<string, string> = {
    'done': 'DONE',
    'complete': 'DONE',
    'completed': 'DONE',
    'cancelled': 'CANCELLED',
    'canceled': 'CANCELLED',
    'in progress': 'IN_PROGRESS',
    'in_progress': 'IN_PROGRESS',
    'in-progress': 'IN_PROGRESS',
    'todo': 'TODO',
    'to do': 'TODO',
    'incomplete': 'TODO',
    'non task': 'NON_TASK',
    'non_task': 'NON_TASK',
    'non-task': 'NON_TASK',
    'nontask': 'NON_TASK',
  };
  if (cleaned in map) return map[cleaned];
  const upper = cleaned.toUpperCase().replace(/\s+/g, '_');
  return ['DONE', 'CANCELLED', 'IN_PROGRESS', 'TODO', 'NON_TASK'].includes(upper) ? upper : null;
}

function parseDateExpression(expr: string, reference: Date = new Date()): string | undefined {
  const trimmed = expr.trim();
  if (!trimmed) return undefined;
  const isoMatch = trimmed.match(/^(\d{4}-\d{2}-\d{2})$/);
  if (isoMatch) return isoMatch[1];

  const parsedFr = chrono.fr.parseDate(trimmed, reference);
  if (parsedFr) return moment(parsedFr).format('YYYY-MM-DD');

  const parsedEn = chrono.en.parseDate(trimmed, reference);
  if (parsedEn) return moment(parsedEn).format('YYYY-MM-DD');

  return undefined;
}

function getRangeForKeyword(keyword: string, reference: Date = new Date()): { start: string; end: string } | undefined {
  const k = keyword.toLowerCase().trim();
  const now = moment(reference);
  const isoWeekStart = (d: moment.Moment) => d.clone().startOf('isoWeek');
  const isoWeekEnd = (d: moment.Moment) => d.clone().endOf('isoWeek');

  if (k === 'today' || k === "aujourd'hui") {
    const day = now.format('YYYY-MM-DD');
    return { start: day, end: day };
  }
  if (k === 'tomorrow' || k === 'demain') {
    const day = now.clone().add(1, 'day').format('YYYY-MM-DD');
    return { start: day, end: day };
  }
  if (k === 'yesterday' || k === 'hier') {
    const day = now.clone().subtract(1, 'day').format('YYYY-MM-DD');
    return { start: day, end: day };
  }

  if (k === 'this week' || k === 'cette semaine') {
    return { start: isoWeekStart(now).format('YYYY-MM-DD'), end: isoWeekEnd(now).format('YYYY-MM-DD') };
  }
  if (k === 'next week' || k === 'semaine prochaine') {
    const d = now.clone().add(1, 'week');
    return { start: isoWeekStart(d).format('YYYY-MM-DD'), end: isoWeekEnd(d).format('YYYY-MM-DD') };
  }
  if (k === 'last week' || k === 'semaine dernière' || k === 'semaine derniere') {
    const d = now.clone().subtract(1, 'week');
    return { start: isoWeekStart(d).format('YYYY-MM-DD'), end: isoWeekEnd(d).format('YYYY-MM-DD') };
  }

  if (k === 'this month' || k === 'ce mois' || k === 'ce mois-ci') {
    return { start: now.clone().startOf('month').format('YYYY-MM-DD'), end: now.clone().endOf('month').format('YYYY-MM-DD') };
  }
  if (k === 'next month' || k === 'mois prochain') {
    const d = now.clone().add(1, 'month');
    return { start: d.startOf('month').format('YYYY-MM-DD'), end: d.endOf('month').format('YYYY-MM-DD') };
  }
  if (k === 'last month' || k === 'mois dernier') {
    const d = now.clone().subtract(1, 'month');
    return { start: d.startOf('month').format('YYYY-MM-DD'), end: d.endOf('month').format('YYYY-MM-DD') };
  }

  if (k === 'this year' || k === "cette année" || k === 'cette annee') {
    return { start: now.clone().startOf('year').format('YYYY-MM-DD'), end: now.clone().endOf('year').format('YYYY-MM-DD') };
  }
  if (k === 'next year' || k === "année prochaine" || k === 'annee prochaine') {
    const d = now.clone().add(1, 'year');
    return { start: d.startOf('year').format('YYYY-MM-DD'), end: d.endOf('year').format('YYYY-MM-DD') };
  }
  if (k === 'last year' || k === "année dernière" || k === 'annee derniere') {
    const d = now.clone().subtract(1, 'year');
    return { start: d.startOf('year').format('YYYY-MM-DD'), end: d.endOf('year').format('YYYY-MM-DD') };
  }

  return undefined;
}

function parseRangeExpression(expr: string, reference: Date = new Date()): { start: string; end: string } | undefined {
  const keywordRange = getRangeForKeyword(expr, reference);
  if (keywordRange) return keywordRange;

  const normalized = expr.toLowerCase().trim();
  const nextMatch = normalized.match(/^(?:the\s+)?next\s+(\d+)\s+(day|days|week|weeks|month|months|year|years)$/);
  if (nextMatch) {
    const count = Number(nextMatch[1]);
    const unit = nextMatch[2].replace(/s$/, '') as moment.unitOfTime.DurationConstructor;
    const start = moment(reference).format('YYYY-MM-DD');
    const end = moment(reference).add(count, unit).format('YYYY-MM-DD');
    return { start, end };
  }

  const inMatch = normalized.match(/^in\s+(\d+)\s+(day|days|week|weeks|month|months|year|years)$/);
  if (inMatch) {
    const count = Number(inMatch[1]);
    const unit = inMatch[2].replace(/s$/, '') as moment.unitOfTime.DurationConstructor;
    const start = moment(reference).format('YYYY-MM-DD');
    const end = moment(reference).add(count, unit).format('YYYY-MM-DD');
    return { start, end };
  }

  return undefined;
}

function compareDate(value: string | undefined, op: string, target: string): boolean {
  if (!value) return false;
  const v = value.substring(0, 10);
  if (op === 'before') return v < target;
  if (op === 'after') return v > target;
  if (op === 'on') return v === target;
  if (op === 'on or before') return v <= target;
  if (op === 'on or after') return v >= target;
  return false;
}

function matchDateFilter(filter: string, prefix: string, value?: string): boolean {
  const remainder = filter.slice(prefix.length).trim();
  const rangeMatch = remainder.match(/^in\s+(.+)$/);
  if (rangeMatch) {
    const range = parseRangeExpression(rangeMatch[1]);
    if (!range || !value) return false;
    const v = value.substring(0, 10);
    return v >= range.start && v <= range.end;
  }

  const opMatch = remainder.match(/^(on or before|on or after|before|after|on)\s+(.+)$/);
  if (!opMatch) return false;
  const op = opMatch[1];
  const dateExpr = opMatch[2];
  const range = getRangeForKeyword(dateExpr);
  if (range) {
    const v = value ? value.substring(0, 10) : undefined;
    if (!v) return false;
    if (op === 'on') return v >= range.start && v <= range.end;
    if (op === 'before') return v < range.start;
    if (op === 'after') return v > range.end;
    if (op === 'on or before') return v <= range.end;
    if (op === 'on or after') return v >= range.start;
    return false;
  }

  const parsed = parseDateExpression(dateExpr);
  if (!parsed) return false;
  return compareDate(value, op, parsed);
}
