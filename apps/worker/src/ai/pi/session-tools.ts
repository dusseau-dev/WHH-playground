import { defineTool, type ToolDefinition } from '@earendil-works/pi-coding-agent';
import { Type } from 'typebox';
import { fs, glob, path } from 'zx';

const GLOB_STAT_BATCH_SIZE = 32;

export interface TodoItem {
  content: string;
  status: 'pending' | 'in_progress' | 'completed';
  activeForm: string;
}

export interface TodoAuditLogger {
  logNote?(category: string, message: string): Promise<void>;
  logToolEnd?(result: unknown): Promise<void>;
}

export function renderTodos(todos: readonly TodoItem[]): string {
  const mark = (status: TodoItem['status']): string =>
    status === 'completed' ? 'x' : status === 'in_progress' ? '~' : ' ';
  return todos.map((todo) => `[${mark(todo.status)}] ${todo.content}`).join('  ');
}

export function createTodoWriteTool(auditLogger: TodoAuditLogger): ToolDefinition {
  let current: TodoItem[] = [];
  return defineTool({
    name: 'todo_write',
    label: 'Todo Write',
    description: 'Replace the current session todo list with the complete list supplied in this call.',
    promptSnippet: 'todo_write: create and manage a structured task list',
    parameters: Type.Object({
      todos: Type.Array(
        Type.Object({
          content: Type.String({ description: 'Imperative task description.' }),
          status: Type.Union([Type.Literal('pending'), Type.Literal('in_progress'), Type.Literal('completed')]),
          activeForm: Type.String({ description: 'Present-continuous task description.' }),
        }),
      ),
    }),
    async execute(_toolCallId, params) {
      current = params.todos as TodoItem[];
      await auditLogger.logNote?.('todo', renderTodos(current));
      const completed = current.filter((todo) => todo.status === 'completed').length;
      return {
        content: [{ type: 'text' as const, text: `Todos updated (${current.length} items, ${completed} completed).` }],
        details: undefined,
      };
    },
  });
}

export function createGlobTool(cwd: string): ToolDefinition {
  return defineTool({
    name: 'glob',
    label: 'Glob',
    description: 'Match file paths with glob patterns and return most recently modified files first.',
    promptSnippet: 'glob: find files by name pattern',
    parameters: Type.Object({
      pattern: Type.String({ description: 'Glob pattern to match.' }),
      path: Type.Optional(Type.String({ description: 'Directory to search, relative to the working directory.' })),
    }),
    async execute(_toolCallId, params) {
      const searchRoot = params.path ? path.resolve(cwd, params.path) : cwd;
      const matches = await glob.globby(params.pattern, {
        cwd: searchRoot,
        absolute: true,
        dot: true,
        onlyFiles: true,
        followSymbolicLinks: false,
      });
      if (matches.length === 0) {
        return { content: [{ type: 'text' as const, text: 'No files found' }], details: undefined };
      }
      const withMtime: Array<{ file: string; mtime: number }> = [];
      for (let offset = 0; offset < matches.length; offset += GLOB_STAT_BATCH_SIZE) {
        const batch = matches.slice(offset, offset + GLOB_STAT_BATCH_SIZE);
        withMtime.push(
          ...(await Promise.all(
            batch.map(async (file) => {
              try {
                return { file, mtime: (await fs.stat(file)).mtimeMs };
              } catch {
                return { file, mtime: 0 };
              }
            }),
          )),
        );
      }
      withMtime.sort((a, b) => b.mtime - a.mtime || a.file.localeCompare(b.file));
      return {
        content: [{ type: 'text' as const, text: withMtime.map(({ file }) => file).join('\n') }],
        details: undefined,
      };
    },
  });
}
