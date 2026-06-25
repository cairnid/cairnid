import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { basename, extname } from 'node:path';

type Finding = {
  path: string;
  rule: string;
  line?: number;
  snippet?: string;
};

type PathRule = {
  name: string;
  pattern: RegExp;
  allowedPaths?: RegExp[];
};

type ContentRule = {
  name: string;
  pattern: RegExp;
  allowedPaths?: RegExp[];
  allowedLines?: RegExp[];
};

const skippedDirectories = new Set([
  '.git',
  '.svelte-kit',
  'build',
  'coverage',
  'dist',
  'node_modules',
  'playwright-report',
  'target',
  'test-results',
]);

const textExtensions = new Set([
  '.css',
  '.csv',
  '.html',
  '.js',
  '.json',
  '.md',
  '.mjs',
  '.rs',
  '.sql',
  '.svelte',
  '.toml',
  '.ts',
  '.txt',
  '.yml',
  '.yaml',
]);

const exactTextFiles = new Set([
  '.dockerignore',
  '.editorconfig',
  '.env.example',
  '.gitattributes',
  '.gitignore',
  'Cargo.lock',
  'Dockerfile',
  'LICENSE',
  'NOTICE',
  'README',
  'bun.lock',
]);

const joinText = (...parts: string[]) => parts.join('');
const chars = (...codes: number[]) => String.fromCodePoint(...codes);
const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const repositoryName = 'cairnid';
const oldProjectName = joinText('T', 'B', 'N');
const oldProjectNameLower = oldProjectName.toLowerCase();
const modelLower = chars(0x61, 0x69);
const modelInitialism = joinText('A', 'I');
const oldOwner = joinText('ib', 'uuv', modelLower);
const staleSlug = joinText('cairn', '-', 'id');
const siteDriftName = joinText(repositoryName, '-', 'site');
const cloudDriftName = joinText(repositoryName, '-', 'cloud');
const restrictedTier = joinText('enter', 'prise');
const restrictedTierSnake = joinText('enter', 'prise');
const restrictedTierRepo = joinText(repositoryName, '-', restrictedTier);
const privateTerm = joinText('pri', 'vate');
const licence = joinText('lic', 'ense');
const licenceAlt = joinText('lic', 'ence');
const licenceUpper = licence.toUpperCase();
const railHost = joinText('rail', 'way');
const madeWord = joinText('gener', 'ated');
const codedMood = joinText('vi', 'be');
const trackerNameUk = joinText('MODERN', 'ISATION', '_', 'TRACK', 'ER');
const trackerNameUs = joinText('MODERN', 'IZATION', '_', 'TRACK', 'ER');
const trackerSuffixPattern = joinText('[^/]*', '_', 'TRACK', 'ER');
const trackerPhraseUk = joinText('modern', 'isation', ' ', 'track', 'er');
const trackerPhraseUs = joinText('modern', 'ization', ' ', 'track', 'er');
const chatTool = joinText('chat', 'gpt');
const modelVendor = joinText('open', modelLower);
const localTool = joinText('co', 'dex');
const otherAssistant = joinText('clau', 'de');
const localTodoFile = joinText('TODO', '_', 'LOCAL');
const checkerPathPattern = /^infra\/scripts\/check-public-surface\.ts$/;
const cargoLockPathPattern = /^Cargo\.lock$/;
const licensePathPattern = /^LICENSE$/;
const mojibakeMarkers = [
  chars(0xfffd),
  chars(0x00c3, 0x00a2, 0x00e2, 0x201a, 0x00ac, 0x00e2, 0x201e, 0x00a2),
  chars(0x00c3, 0x00a2, 0x00e2, 0x201a, 0x00ac, 0x00c5, 0x201c),
  chars(0x00c3, 0x00a2, 0x00e2, 0x201a, 0x00ac),
  chars(0x00c3, 0x0192),
  chars(0x00c3, 0x201a),
];

const pathRules: PathRule[] = [
  {
    name: 'workspace planning file',
    pattern: new RegExp(`(^|/)(?:${trackerNameUk}|${trackerNameUs}|${trackerSuffixPattern})\\.md$`, 'i'),
  },
  {
    name: 'local note artifact',
    pattern: new RegExp(`(^|/)(?:NOTES|SCRATCH|${localTodoFile}|.*_NOTES|.*\\.local)\\.(?:md|txt)$`, 'i'),
  },
  {
    name: 'local note directory',
    pattern: /(^|\/)(?:notes\.local|scratch|tmp|local-notes)\//i,
  },
  {
    name: 'secret or env artifact',
    pattern: /(^|\/)(?:\.env(?:\.|$)|.*\.(?:key|p12|pfx)|id_rsa(?:\.pub)?$|.*secret.*\.(?:json|toml|ya?ml|env)|.*secrets.*\.(?:json|toml|ya?ml|env))/i,
    allowedPaths: [/^\.env\.example$/],
  },
  {
    name: 'private key artifact',
    pattern: /(^|\/).*\.pem$/i,
    allowedPaths: [/\.example\.pem$/i, /^\.dev\.example\.pem$/],
  },
  {
    name: 'generated or build artifact',
    pattern: /(^|\/)(?:\.svelte-kit|build|coverage|dist|node_modules|playwright-report|target|test-results)\/|(?:^|\/).*\.(?:lcov|map|sqlite|sqlite3|tsbuildinfo)$/i,
  },
  {
    name: 'host-platform residue',
    pattern: new RegExp(`(^|/)(?:\\.${railHost}/|${railHost}\\.json$|${railHost}\\.toml$)`, 'i'),
  },
  {
    name: 'stale slug in path',
    pattern: new RegExp(`(^|/)${escapeRegExp(staleSlug)}(?:[./_-]|$)`, 'i'),
  },
  {
    name: 'repository-name drift in path',
    pattern: new RegExp(`(^|/)(?:${siteDriftName}|${cloudDriftName}|${restrictedTierRepo})(?:[./_-]|$)`, 'i'),
  },
  {
    name: 'non-public module path',
    pattern: new RegExp(
      [
        `^crates/${restrictedTier}(?:/|$)`,
        `^docs/${restrictedTier}-${licenceAlt}ing\\.md$`,
        `^docs/${restrictedTier}-${licence}ing\\.md$`,
        `^apps/api/src/${licence}_operations(?:\\.rs|/)`,
        `^apps/api/src/http/${restrictedTier}_${licence}(?:\\.rs|/)`,
        `^crates/database/src/${restrictedTier}_${licence}\\.rs$`,
        `^crates/database/src/rows/${restrictedTier}\\.rs$`,
        `^crates/domain/src/${licence}\\.rs$`,
      ].join('|'),
      'i',
    ),
  },
];

const contentRules: ContentRule[] = [
  {
    name: 'old repository owner',
    pattern: new RegExp(
      [
        `github\\.com/${oldOwner}/${repositoryName}`,
        `${oldOwner}/${repositoryName}`,
      ].join('|'),
      'i',
    ),
  },
  {
    name: 'stale project name',
    pattern: new RegExp(
      `\\b${oldProjectName}\\b|\\b${oldProjectNameLower}\\b|@${oldProjectNameLower}\\b|X-${oldProjectName}|x-${oldProjectNameLower}|urn:${oldProjectNameLower}`,
      'i',
    ),
  },
  {
    name: 'stale slug',
    pattern: new RegExp(`(^|[^a-z0-9])${escapeRegExp(staleSlug)}([^a-z0-9]|$)`, 'i'),
  },
  {
    name: 'repository-name drift',
    pattern: new RegExp(
      [
        siteDriftName,
        cloudDriftName,
        restrictedTierRepo,
      ].map(escapeRegExp).join('|'),
      'i',
    ),
  },
  {
    name: 'workspace planning wording',
    pattern: new RegExp(
      [
        trackerNameUk,
        trackerNameUs,
        trackerPhraseUk,
        trackerPhraseUs,
      ].map(escapeRegExp).join('|'),
      'i',
    ),
    allowedPaths: [/^\.gitignore$/],
  },
  {
    name: 'non-public implementation wording',
    pattern: new RegExp(
      [
        `cairn[-_ ]${restrictedTier}`,
        `\\b${restrictedTier}[-_ ](?:module|crate|${licence}|${licenceAlt}|${licence}ing|${licenceAlt}ing|edition|feature|features|repo|repository|tier)\\b`,
        `\\b${privateTerm}[-_ ](?:module|crate|implementation|edition|feature|features|repo|repository|tier)\\b`,
        `\\bpaid[-_ ]features?\\b`,
        `\\b${licence}[-_ ]server\\b`,
        `\\b${licenceAlt}[-_ ]server\\b`,
        `${restrictedTierSnake}_${licence}s?`,
        `${restrictedTierSnake}_${licenceAlt}s?`,
        `${restrictedTierSnake}_module`,
        `/api/v1/${licence}`,
        `/api/v1/${licenceAlt}`,
        `${joinText('CA', 'IRN')}_${licenceUpper}`,
        `${licence}_operations`,
      ].join('|'),
      'i',
    ),
  },
  {
    name: 'host-platform wording',
    pattern: new RegExp(
      [
        `\\b${railHost}\\b`,
        `${railHost}\\.app`,
        `${railHost}\\.json`,
        `${railHost.toUpperCase()}_`,
      ].join('|'),
      'i',
    ),
    allowedPaths: [/^\.gitignore$/],
  },
  {
    name: 'model-attribution wording',
    pattern: new RegExp(
      [
        `\\b${modelInitialism}\\b`,
        `${modelInitialism}[-_ ]?${madeWord}`,
        `${madeWord}\\s+by`,
        `\\b${chatTool}\\b`,
        `\\b${modelVendor}\\b`,
        `\\b${localTool}\\b`,
        `\\b${otherAssistant}\\b`,
        `\\b${codedMood}(?:[-_ ]?cod(?:e|ed|ing))?\\b`,
      ].join('|'),
      'i',
    ),
    allowedPaths: [cargoLockPathPattern, licensePathPattern],
  },
  {
    name: 'local-only note wording',
    pattern: /(^|[^a-z0-9])(?:scratchpad|personal notes?|local-only notes?|do not publish|for vai)([^a-z0-9]|$)/i,
    allowedPaths: [/^\.gitignore$/, checkerPathPattern],
  },
  {
    name: 'generated file marker',
    pattern: new RegExp(`@${madeWord}|auto[-_ ]${madeWord}|do not edit this file`, 'i'),
    allowedPaths: [cargoLockPathPattern, checkerPathPattern],
    allowedLines: [/^.*generated file marker.*$/i],
  },
  {
    name: 'private key material',
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  },
  {
    name: 'mojibake marker',
    pattern: new RegExp(mojibakeMarkers.map(escapeRegExp).join('|')),
  },
];

const findings = checkPublicSurface();

if (findings.length > 0) {
  console.error('Public repository surface check failed.');
  console.error('');

  for (const finding of findings) {
    const location = finding.line === undefined ? finding.path : `${finding.path}:${finding.line}`;
    console.error(`- ${location}: ${finding.rule}`);
    if (finding.snippet) {
      console.error(`  ${finding.snippet}`);
    }
  }

  console.error('');
  console.error(`${findings.length} violation${findings.length === 1 ? '' : 's'} found.`);
  process.exit(1);
}

console.log('Public repository surface is clean.');

function checkPublicSurface(): Finding[] {
  const failures: Finding[] = [];

  for (const relativePath of collectPublicFiles()) {
    const path = normalizePath(relativePath);

    for (const rule of pathRules) {
      if (rule.pattern.test(path) && !isAllowedPath(path, rule.allowedPaths)) {
        failures.push({ path, rule: rule.name });
      }
    }

    if (!existsSync(relativePath) || !isTextFile(path) || statSync(relativePath).size > 2_000_000) {
      continue;
    }

    const content = readFileSync(relativePath, 'utf8');
    const lines = content.split(/\r?\n/);

    lines.forEach((line, index) => {
      for (const rule of contentRules) {
        if (
          rule.pattern.test(line)
          && !isAllowedPath(path, rule.allowedPaths)
          && !isAllowedLine(line, rule.allowedLines)
        ) {
          failures.push({
            path,
            line: index + 1,
            rule: rule.name,
            snippet: line.trim().slice(0, 180),
          });
        }
      }
    });
  }

  return failures;
}

function collectPublicFiles(): string[] {
  const result = spawnSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'], {
    encoding: 'utf8',
  });

  if (result.status !== 0) {
    console.error('Unable to list repository files for public-surface check.');
    if (result.stderr) {
      console.error(result.stderr.trim());
    }
    process.exit(2);
  }

  return [...new Set(result.stdout.split(/\r?\n/).filter(Boolean))]
    .map(normalizePath)
    .filter((path) => !isSkippedPath(path))
    .sort();
}

function isSkippedPath(path: string): boolean {
  return path.split('/').some((part) => skippedDirectories.has(part));
}

function isTextFile(path: string): boolean {
  return exactTextFiles.has(basename(path)) || textExtensions.has(extname(path));
}

function normalizePath(path: string): string {
  return path.replaceAll('\\', '/');
}

function isAllowedPath(path: string, allowedPaths: RegExp[] | undefined): boolean {
  return allowedPaths?.some((pattern) => pattern.test(path)) ?? false;
}

function isAllowedLine(line: string, allowedLines: RegExp[] | undefined): boolean {
  return allowedLines?.some((pattern) => pattern.test(line)) ?? false;
}
