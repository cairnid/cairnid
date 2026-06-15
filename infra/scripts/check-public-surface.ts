import { readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, extname, join, relative } from 'node:path';

type Rule = {
  name: string;
  pattern: RegExp;
};

const skippedDirectories = new Set([
  '.git',
  '.svelte-kit',
  'build',
  'coverage',
  'node_modules',
  'playwright-report',
  'target',
  'test-results',
]);

const textExtensions = new Set([
  '.css',
  '.html',
  '.json',
  '.md',
  '.rs',
  '.sql',
  '.svelte',
  '.toml',
  '.ts',
  '.yml',
  '.yaml',
]);

const exactTextFiles = new Set([
  'Dockerfile',
  '.dockerignore',
  '.env.example',
  '.gitattributes',
  '.gitignore',
]);

const joinText = (...parts: string[]) => parts.join('');
const oldName = joinText('T', 'B', 'N');
const oldNameLower = oldName.toLowerCase();
const generated = joinText('a', 'i');
const internalTrackFile = joinText('MODERN', 'ISATION', '_', 'TRACK', 'ER');
const restrictedTier = joinText('enter', 'prise');
const restrictedTierSnake = joinText('enter', 'prise');
const licence = joinText('lic', 'ense');
const licenceUpper = licence.toUpperCase();
const chars = (...codes: number[]) => String.fromCodePoint(...codes);
const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const mojibakeMarkers = [
  chars(0xfffd),
  chars(0x00c3, 0x00a2, 0x00e2, 0x201a, 0x00ac, 0x00e2, 0x201e, 0x00a2),
  chars(0x00c3, 0x00a2, 0x00e2, 0x201a, 0x00ac, 0x00c5, 0x201c),
  chars(0x00c3, 0x00a2, 0x00e2, 0x201a, 0x00ac),
  chars(0x00c3, 0x0192),
  chars(0x00c3, 0x201a),
];

const forbiddenPaths = [
  new RegExp(`^${internalTrackFile}\\.md$`),
  new RegExp(`^docs/${restrictedTier}-${licence}ing\\.md$`),
  new RegExp(`^crates/${restrictedTier}/`),
  new RegExp(`^apps/api/src/${licence}_operations(?:\\.rs|/)`),
  new RegExp(`^apps/api/src/http/${restrictedTier}_${licence}(?:\\.rs|/)`),
  new RegExp(`^crates/database/src/${restrictedTier}_${licence}\\.rs$`),
  new RegExp(`^crates/database/src/rows/${restrictedTier}\\.rs$`),
  new RegExp(`^crates/domain/src/${licence}\\.rs$`),
];

const rules: Rule[] = [
  {
    name: 'stale project name',
    pattern: new RegExp(
      `\\b${oldName}\\b|\\b${oldNameLower}\\b|@${oldNameLower}\\b|X-${oldName}|x-${oldNameLower}|urn:${oldNameLower}`,
      'i',
    ),
  },
  {
    name: 'workspace planning artifact',
    pattern: new RegExp(
      [
        internalTrackFile,
        joinText('modern', 'isation', ' ', 'track', 'er'),
        joinText('modern', 'ization', ' ', 'track', 'er'),
      ].join('|'),
      'i',
    ),
  },
  {
    name: 'restricted module surface',
    pattern: new RegExp(
      [
        `cairn-${restrictedTier}`,
        `crates/${restrictedTier}`,
        `crates\\\\${restrictedTier}`,
        `${restrictedTier} ${licence}`,
        `${restrictedTierSnake}_module`,
        joinText('paid', '_features'),
        `/api/v1/${licence}`,
        `CAIRN_${licenceUpper}`,
        `${licence} import`,
        `${restrictedTierSnake}_${licence}s`,
      ].join('|'),
      'i',
    ),
  },
  {
    name: 'unsupported production claim',
    pattern: new RegExp(
      [
        joinText('production', '-', 'shaped'),
        joinText('production', '-', 'grade'),
        joinText('production', ' ', 'grade'),
      ].join('|'),
      'i',
    ),
  },
  {
    name: 'forbidden attribution wording',
    pattern: new RegExp(
      [
        `${generated}[- ]?generated`,
        `made by ${generated}`,
        joinText('chat', 'gpt'),
        joinText('open', 'a', 'i'),
        joinText('co', 'dex'),
      ].join('|'),
      'i',
    ),
  },
  {
    name: 'mojibake marker',
    pattern: new RegExp(mojibakeMarkers.map(escapeRegExp).join('|')),
  },
];

const failures: string[] = [];

for (const file of collectTextFiles('.')) {
  const relativePath = relative('.', file).replaceAll('\\', '/');

  if (forbiddenPaths.some((pattern) => pattern.test(relativePath))) {
    failures.push(`${relativePath}:1: forbidden public path`);
    continue;
  }

  const content = readFileSync(file, 'utf8');
  const lines = content.split(/\r?\n/);

  lines.forEach((line, index) => {
    for (const rule of rules) {
      if (rule.pattern.test(line)) {
        failures.push(`${relative('.', file)}:${index + 1}: ${rule.name}`);
      }
    }
  });
}

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(failure);
  }
  process.exit(1);
}

console.log('Public repository surface is clean.');

function collectTextFiles(root: string): string[] {
  const files: string[] = [];

  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      if (!skippedDirectories.has(entry.name)) {
        files.push(...collectTextFiles(path));
      }
      continue;
    }

    if (!entry.isFile() || !isTextFile(path)) {
      continue;
    }

    if (statSync(path).size > 2_000_000) {
      continue;
    }

    files.push(path);
  }

  return files.sort();
}

function isTextFile(path: string): boolean {
  return exactTextFiles.has(basename(path)) || textExtensions.has(extname(path));
}
