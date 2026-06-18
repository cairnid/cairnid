import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

type ContractRoute = {
  method: string;
  path: string;
};

type WebRouteCall = {
  helper: ApiHelper;
  method: string;
  path: string;
  sourcePath: string;
  line: number;
  expression: string;
};

type ApiHelper = 'api' | 'apiList' | 'apiText' | 'fetch';

type UnsupportedCall = {
  helper: string;
  sourcePath: string;
  line: number;
  reason: string;
  expression: string;
};

type PathResolution =
  | { kind: 'paths'; paths: string[] }
  | { kind: 'unsupported'; reason: string };

const routeRoot = 'apps/web/src/routes';
const apiHelperPath = 'apps/web/src/lib/api.ts';
const contractSchemaVersion = 'cairnid.api_contract.v1';

const contractRoutes = loadApiContractRoutes();
const scanned = scanWebRouteCalls();
const unsupportedCalls = scanned.unsupported;
const unknownCalls = scanned.calls.filter(
  (call) => !contractRoutes.some((route) => routeMatches(route, call)),
);

if (unsupportedCalls.length > 0 || unknownCalls.length > 0) {
  console.error('Web/API contract check failed.');
  console.error('');

  if (unknownCalls.length > 0) {
    console.error('Unknown web API routes:');
    for (const call of unknownCalls) {
      console.error(`- ${call.method} ${call.path} at ${call.sourcePath}:${call.line}`);
      console.error(`  ${call.helper} path: ${call.expression}`);
    }
    console.error('');
  }

  if (unsupportedCalls.length > 0) {
    console.error('Unsupported dynamic web API route shapes:');
    for (const call of unsupportedCalls) {
      console.error(`- ${call.sourcePath}:${call.line}: ${call.reason}`);
      console.error(`  ${call.helper} path: ${call.expression}`);
    }
    console.error('');
  }

  console.error(
    'Add the missing browser/admin route to cairn-api api-contract, or make the web call path a checked literal/template route shape.',
  );
  process.exit(1);
}

console.log(
  `Web/API contract check passed. Checked ${scanned.calls.length} web API calls against ${contractRoutes.length} exported contract routes.`,
);

function loadApiContractRoutes(): ContractRoute[] {
  const command = apiContractCommand();
  const result = spawnSync(command[0], command.slice(1), {
    encoding: 'utf8',
    env: apiContractEnvironment(),
    shell: false,
  });

  if (result.status !== 0) {
    console.error('Unable to export the machine-readable API contract.');
    console.error(`Command: ${command.join(' ')}`);
    if (result.error) {
      console.error(result.error.message);
    }
    if (result.stderr?.trim()) {
      console.error(result.stderr.trim());
    }
    if (result.stdout?.trim()) {
      console.error(result.stdout.trim());
    }
    process.exit(2);
  }

  let report: unknown;
  try {
    report = JSON.parse(result.stdout);
  } catch (error) {
    console.error('cairn-api api-contract did not return valid JSON.');
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(2);
  }

  if (!isApiContractReport(report)) {
    console.error(`cairn-api api-contract did not return ${contractSchemaVersion}.`);
    process.exit(2);
  }

  return report.routes.map((route) => ({
    method: route.method.toUpperCase(),
    path: normalizeApiPath(route.path),
  }));
}

function apiContractCommand(): string[] {
  if (process.platform === 'win32') {
    return [
      'cargo',
      '+stable-x86_64-pc-windows-gnu',
      'run',
      '-p',
      'cairn-api',
      '--locked',
      '--',
      'api-contract',
    ];
  }

  return ['cargo', 'run', '-p', 'cairn-api', '--locked', '--', 'api-contract'];
}

function apiContractEnvironment(): Record<string, string | undefined> {
  const env = { ...process.env };
  if (process.platform === 'win32') {
    const msys2Mingw = 'C:\\msys64\\mingw64';
    const pkgConfig = `${msys2Mingw}\\bin\\pkg-config.exe`;
    const opensslInclude = `${msys2Mingw}\\include\\openssl`;
    if (existsSync(pkgConfig) && existsSync(opensslInclude)) {
      env.OPENSSL_DIR ??= msys2Mingw;
      const pathKey = env.Path === undefined ? 'PATH' : 'Path';
      env[pathKey] = `${msys2Mingw}\\bin;${env[pathKey] ?? ''}`;
    }
  }

  return Object.fromEntries(
    Object.entries(env).filter((entry): entry is [string, string] => entry[1] !== undefined),
  );
}

function isApiContractReport(value: unknown): value is {
  schema_version: string;
  routes: Array<{ method: string; path: string }>;
} {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const report = value as {
    schema_version?: unknown;
    routes?: unknown;
  };

  return (
    report.schema_version === contractSchemaVersion
    && Array.isArray(report.routes)
    && report.routes.every(
      (route) =>
        route
        && typeof route === 'object'
        && typeof (route as { method?: unknown }).method === 'string'
        && typeof (route as { path?: unknown }).path === 'string',
    )
  );
}

function scanWebRouteCalls(): { calls: WebRouteCall[]; unsupported: UnsupportedCall[] } {
  const calls: WebRouteCall[] = [];
  const unsupported: UnsupportedCall[] = [];

  for (const sourcePath of collectWebApiSourceFiles()) {
    const source = readFileSync(sourcePath, 'utf8');
    const relativePath = normalizePath(relative(process.cwd(), sourcePath));
    const functionPaths = collectPathFunctions(source);
    const includeHelperCalls = normalizePath(sourcePath) !== normalizePath(apiHelperPath);

    for (const call of findWebApiCalls(source, includeHelperCalls)) {
      const args = splitTopLevelArgs(call.argumentsSource);
      const methodResolution = resolveMethod(call.helper, args);
      const pathExpression = args[0]?.trim() ?? '';
      const pathResolution = resolvePathExpression(pathExpression, functionPaths);
      const line = lineNumber(source, call.startIndex);

      if (methodResolution.kind === 'unsupported') {
        unsupported.push({
          helper: call.helper,
          sourcePath: relativePath,
          line,
          reason: methodResolution.reason,
          expression: pathExpression || '(missing first argument)',
        });
        continue;
      }

      if (pathResolution.kind === 'unsupported') {
        unsupported.push({
          helper: call.helper,
          sourcePath: relativePath,
          line,
          reason: pathResolution.reason,
          expression: pathExpression || '(missing first argument)',
        });
        continue;
      }

      for (const path of pathResolution.paths) {
        if (!path.startsWith('/api/v1/')) {
          continue;
        }

        calls.push({
          helper: call.helper,
          method: methodResolution.method,
          path,
          sourcePath: relativePath,
          line,
          expression: pathExpression,
        });
      }
    }
  }

  return { calls, unsupported };
}

function collectWebApiSourceFiles(): string[] {
  const sourceFiles = collectSvelteRouteFiles(routeRoot);
  if (existsSync(apiHelperPath)) {
    sourceFiles.push(apiHelperPath);
  }
  return sourceFiles.sort();
}

function collectSvelteRouteFiles(root: string): string[] {
  if (!existsSync(root)) {
    return [];
  }

  const files: string[] = [];
  for (const entry of readdirSync(root)) {
    const path = join(root, entry);
    const stats = statSync(path);
    if (stats.isDirectory()) {
      files.push(...collectSvelteRouteFiles(path));
    } else if (path.endsWith('.svelte')) {
      files.push(path);
    }
  }
  return files.sort();
}

function collectPathFunctions(source: string): Map<string, string[]> {
  const functions = new Map<string, string[]>();
  const functionPattern = /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/g;
  let match: RegExpExecArray | null;

  while ((match = functionPattern.exec(source)) !== null) {
    const name = match[1];
    const openBrace = findNextChar(source, '{', functionPattern.lastIndex);
    if (openBrace === -1) {
      continue;
    }
    const closeBrace = findMatchingBrace(source, openBrace);
    if (closeBrace === -1) {
      continue;
    }

    const signature = source.slice(match.index, openBrace);
    const body = source.slice(openBrace + 1, closeBrace);
    const paths = [
      ...extractApiPathLiterals(signature),
      ...extractApiPathLiterals(body),
    ];
    if (paths.length > 0) {
      functions.set(name, [...new Set(paths)].sort());
    }
    functionPattern.lastIndex = closeBrace + 1;
  }

  return functions;
}

function extractApiPathLiterals(source: string): string[] {
  const paths: string[] = [];
  const literalPattern = /(['"`])\/api\/v1[\s\S]*?/g;
  let match: RegExpExecArray | null;

  while ((match = literalPattern.exec(source)) !== null) {
    const quote = match[1];
    const start = match.index;
    const literal = readQuotedExpression(source, start, quote);
    if (!literal) {
      continue;
    }

    const resolution = resolvePathExpression(literal, new Map());
    if (resolution.kind === 'paths') {
      paths.push(...resolution.paths);
    }
    literalPattern.lastIndex = start + literal.length;
  }

  return paths;
}

function findWebApiCalls(source: string, includeHelperCalls: boolean): Array<{
  helper: ApiHelper;
  startIndex: number;
  argumentsSource: string;
}> {
  const calls: Array<{
    helper: ApiHelper;
    startIndex: number;
    argumentsSource: string;
  }> = [];
  const callPattern = includeHelperCalls
    ? /\b(api|apiList|apiText|fetch)\s*\(/g
    : /\b(fetch)\s*\(/g;
  let match: RegExpExecArray | null;

  while ((match = callPattern.exec(source)) !== null) {
    const helper = match[1] as ApiHelper;
    const openParen = source.indexOf('(', match.index + helper.length);
    const closeParen = findMatchingParen(source, openParen);
    if (closeParen === -1) {
      calls.push({
        helper,
        startIndex: match.index,
        argumentsSource: '',
      });
      continue;
    }

    const argumentsSource = source.slice(openParen + 1, closeParen);
    if (helper === 'fetch' && !splitTopLevelArgs(argumentsSource)[0]?.includes('/api/v1')) {
      callPattern.lastIndex = closeParen + 1;
      continue;
    }

    calls.push({
      helper,
      startIndex: match.index,
      argumentsSource,
    });
    callPattern.lastIndex = closeParen + 1;
  }

  return calls;
}

function resolveMethod(
  helper: ApiHelper,
  args: string[],
): { kind: 'method'; method: string } | { kind: 'unsupported'; reason: string } {
  if (helper === 'apiList') {
    return { kind: 'method', method: 'GET' };
  }

  const initArg = helper === 'apiText' || helper === 'fetch' ? args[1] : args[2];
  if (!initArg || !initArg.trim()) {
    return { kind: 'method', method: 'GET' };
  }

  const method = /\bmethod\s*:\s*(['"`])([A-Za-z]+)\1/.exec(initArg);
  if (method) {
    return { kind: 'method', method: method[2].toUpperCase() };
  }
  if (/\bmethod\s*:/.test(initArg)) {
    return { kind: 'unsupported', reason: 'method must be a literal string' };
  }

  return { kind: 'method', method: 'GET' };
}

function resolvePathExpression(
  expression: string,
  functionPaths: Map<string, string[]>,
): PathResolution {
  const trimmed = expression.trim();
  if (!trimmed) {
    return { kind: 'unsupported', reason: 'missing path argument' };
  }

  if (trimmed.startsWith("'") || trimmed.startsWith('"')) {
    return { kind: 'paths', paths: [normalizeApiPath(readPlainString(trimmed))] };
  }

  if (trimmed.startsWith('`')) {
    const template = readTemplatePath(trimmed);
    if (template.kind === 'unsupported') {
      return template;
    }
    return { kind: 'paths', paths: [normalizeApiPath(template.path)] };
  }

  const call = /^([A-Za-z_$][\w$]*)\s*\(([\s\S]*)\)$/.exec(trimmed);
  if (call) {
    const nestedArgs = splitTopLevelArgs(call[2]);
    if (nestedArgs[0]) {
      const firstArg = resolvePathExpression(nestedArgs[0], functionPaths);
      if (firstArg.kind === 'paths' && firstArg.paths.some((path) => path.startsWith('/api/v1/'))) {
        return firstArg;
      }
    }

    const paths = functionPaths.get(call[1]);
    if (paths) {
      return { kind: 'paths', paths };
    }

    return { kind: 'unsupported', reason: `unresolved path helper ${call[1]}()` };
  }

  return { kind: 'unsupported', reason: 'path must be a literal string, route template, or checked path helper' };
}

function readTemplatePath(expression: string): PathResolution | { kind: 'path'; path: string } {
  let index = 1;
  let path = '';

  while (index < expression.length) {
    const character = expression[index];
    if (character === '`') {
      return { kind: 'path', path };
    }
    if (character === '\\') {
      path += expression[index + 1] ?? '';
      index += 2;
      continue;
    }
    if (character === '$' && expression[index + 1] === '{') {
      const interpolationEnd = findTemplateInterpolationEnd(expression, index + 2);
      if (interpolationEnd === -1) {
        return { kind: 'unsupported', reason: 'unterminated template interpolation' };
      }

      const next = expression[interpolationEnd + 1];
      const interpolation = expression.slice(index + 2, interpolationEnd).trim();
      if (path === '' && interpolation === 'apiOrigin' && next === '/') {
        index = interpolationEnd + 1;
        continue;
      }

      if (!path.endsWith('/') || (next && next !== '/' && next !== '?' && next !== '`')) {
        return {
          kind: 'unsupported',
          reason: 'template interpolation must represent a complete path segment',
        };
      }

      path += '{param}';
      index = interpolationEnd + 1;
      continue;
    }

    path += character;
    index += 1;
  }

  return { kind: 'unsupported', reason: 'unterminated template literal' };
}

function routeMatches(contractRoute: ContractRoute, call: WebRouteCall): boolean {
  if (contractRoute.method !== call.method) {
    return false;
  }

  const contractParts = contractRoute.path.split('/');
  const callParts = call.path.split('/');
  if (contractParts.length !== callParts.length) {
    return false;
  }

  return contractParts.every((part, index) => {
    if (part.startsWith('{') && part.endsWith('}')) {
      return callParts[index].startsWith('{') && callParts[index].endsWith('}');
    }
    return part === callParts[index];
  });
}

function splitTopLevelArgs(source: string): string[] {
  const args: string[] = [];
  let start = 0;
  let parenDepth = 0;
  let braceDepth = 0;
  let bracketDepth = 0;
  let index = 0;

  while (index < source.length) {
    const character = source[index];
    if (character === "'" || character === '"') {
      index = skipQuoted(source, index, character);
      continue;
    }
    if (character === '`') {
      index = skipTemplate(source, index);
      continue;
    }
    if (character === '(') {
      parenDepth += 1;
    } else if (character === ')') {
      parenDepth -= 1;
    } else if (character === '{') {
      braceDepth += 1;
    } else if (character === '}') {
      braceDepth -= 1;
    } else if (character === '[') {
      bracketDepth += 1;
    } else if (character === ']') {
      bracketDepth -= 1;
    } else if (
      character === ','
      && parenDepth === 0
      && braceDepth === 0
      && bracketDepth === 0
    ) {
      args.push(source.slice(start, index).trim());
      start = index + 1;
    }
    index += 1;
  }

  const tail = source.slice(start).trim();
  if (tail) {
    args.push(tail);
  }

  return args;
}

function findMatchingParen(source: string, openParen: number): number {
  return findMatchingPair(source, openParen, '(', ')');
}

function findMatchingBrace(source: string, openBrace: number): number {
  return findMatchingPair(source, openBrace, '{', '}');
}

function findMatchingPair(source: string, openIndex: number, open: string, close: string): number {
  let depth = 0;
  let index = openIndex;

  while (index < source.length) {
    const character = source[index];
    if (character === "'" || character === '"') {
      index = skipQuoted(source, index, character);
      continue;
    }
    if (character === '`') {
      index = skipTemplate(source, index);
      continue;
    }
    if (character === open) {
      depth += 1;
    } else if (character === close) {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
    index += 1;
  }

  return -1;
}

function findTemplateInterpolationEnd(source: string, start: number): number {
  let depth = 1;
  let index = start;
  while (index < source.length) {
    const character = source[index];
    if (character === "'" || character === '"') {
      index = skipQuoted(source, index, character);
      continue;
    }
    if (character === '`') {
      index = skipTemplate(source, index);
      continue;
    }
    if (character === '{') {
      depth += 1;
    } else if (character === '}') {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
    index += 1;
  }
  return -1;
}

function skipQuoted(source: string, start: number, quote: string): number {
  let index = start + 1;
  while (index < source.length) {
    if (source[index] === '\\') {
      index += 2;
      continue;
    }
    if (source[index] === quote) {
      return index + 1;
    }
    index += 1;
  }
  return source.length;
}

function skipTemplate(source: string, start: number): number {
  let index = start + 1;
  while (index < source.length) {
    if (source[index] === '\\') {
      index += 2;
      continue;
    }
    if (source[index] === '`') {
      return index + 1;
    }
    index += 1;
  }
  return source.length;
}

function readQuotedExpression(source: string, start: number, quote: string): string | null {
  const end = skipQuoted(source, start, quote);
  if (end > source.length) {
    return null;
  }
  return source.slice(start, end);
}

function readPlainString(expression: string): string {
  const quote = expression[0];
  let index = 1;
  let value = '';
  while (index < expression.length) {
    const character = expression[index];
    if (character === quote) {
      return value;
    }
    if (character === '\\') {
      value += expression[index + 1] ?? '';
      index += 2;
      continue;
    }
    value += character;
    index += 1;
  }
  return value;
}

function normalizeApiPath(path: string): string {
  const withoutQuery = path.split('?')[0];
  return withoutQuery.endsWith('/') && withoutQuery !== '/' ? withoutQuery.slice(0, -1) : withoutQuery;
}

function findNextChar(source: string, character: string, start: number): number {
  for (let index = start; index < source.length; index += 1) {
    if (source[index] === character) {
      return index;
    }
  }
  return -1;
}

function lineNumber(source: string, index: number): number {
  let line = 1;
  for (let cursor = 0; cursor < index; cursor += 1) {
    if (source[cursor] === '\n') {
      line += 1;
    }
  }
  return line;
}

function normalizePath(path: string): string {
  return path.replaceAll('\\', '/');
}
