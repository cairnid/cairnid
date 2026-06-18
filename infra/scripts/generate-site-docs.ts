import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, normalize, relative, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';

type SiteDocsConfig = {
  basePath: string;
  assets: AssetConfig[];
  documents: DocumentConfig[];
};

type AssetConfig = {
  source: string;
  output: string;
};

type DocumentConfig = {
  slug: string;
  title: string;
  section: string;
  source: string;
  description: string;
};

type ManifestDocument = DocumentConfig & {
  href: string;
  output: string;
};

type Manifest = {
  generatedAt: string;
  sourceCommit: string | null;
  basePath: string;
  documents: ManifestDocument[];
  assets: AssetConfig[];
};

const repoRoot = process.cwd();
const args = parseArgs(process.argv.slice(2));
const configPath = resolveRepoPath(args.config ?? 'docs/site-docs.json');
const outputRoot = resolveRepoPath(args.out ?? 'dist/site-docs');
const config = readConfig(configPath);

validateConfig(config);

const sourcePathToDocument = new Map(
  config.documents.map((document) => [normalizePath(document.source), document]),
);
const sourcePathToAsset = new Map(
  config.assets.map((asset) => [normalizePath(asset.source), asset]),
);

const manifestDocuments: ManifestDocument[] = [];

for (const document of config.documents) {
  const sourcePath = normalize(join(repoRoot, document.source));
  const output = `${document.slug}.md`;
  const outputPath = join(outputRoot, output);
  const markdown = readFileSync(sourcePath, 'utf8');
  const renderedMarkdown = [
    '---',
    `title: ${JSON.stringify(document.title)}`,
    `description: ${JSON.stringify(document.description)}`,
    `section: ${JSON.stringify(document.section)}`,
    `source: ${JSON.stringify(normalizePath(document.source))}`,
    '---',
    '',
    rewriteMarkdownLinks(markdown, document, config.basePath, sourcePathToDocument, sourcePathToAsset),
  ].join('\n');

  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, renderedMarkdown);

  manifestDocuments.push({
    ...document,
    href: documentHref(config.basePath, document),
    output,
  });
}

for (const asset of config.assets) {
  const sourcePath = normalize(join(repoRoot, asset.source));
  const outputPath = normalize(join(outputRoot, asset.output));
  mkdirSync(dirname(outputPath), { recursive: true });
  copyFileSync(sourcePath, outputPath);
}

const manifest: Manifest = {
  generatedAt: new Date().toISOString(),
  sourceCommit: currentCommit(),
  basePath: config.basePath,
  documents: manifestDocuments,
  assets: config.assets,
};

writeFileSync(join(outputRoot, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);

console.log(`Exported ${manifestDocuments.length} docs and ${config.assets.length} assets to ${relative(repoRoot, outputRoot)}.`);

function parseArgs(argv: string[]): { config?: string; out?: string } {
  const parsed: { config?: string; out?: string } = {};

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const next = argv[index + 1];

    if (arg === '--config' && next) {
      parsed.config = next;
      index += 1;
      continue;
    }

    if (arg === '--out' && next) {
      parsed.out = next;
      index += 1;
      continue;
    }

    throw new Error(`Unsupported argument: ${arg}`);
  }

  return parsed;
}

function readConfig(path: string): SiteDocsConfig {
  return JSON.parse(readFileSync(path, 'utf8')) as SiteDocsConfig;
}

function validateConfig(config: SiteDocsConfig): void {
  const slugs = new Set<string>();
  const outputs = new Set<string>();

  if (!config.basePath.startsWith('/')) {
    throw new Error('docs site basePath must start with /');
  }

  for (const document of config.documents) {
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(document.slug)) {
      throw new Error(`invalid docs slug: ${document.slug}`);
    }

    if (slugs.has(document.slug)) {
      throw new Error(`duplicate docs slug: ${document.slug}`);
    }
    slugs.add(document.slug);

    const output = `${document.slug}.md`;
    if (outputs.has(output)) {
      throw new Error(`duplicate docs output: ${output}`);
    }
    outputs.add(output);

    if (!existsSync(join(repoRoot, document.source))) {
      throw new Error(`docs source does not exist: ${document.source}`);
    }
  }

  for (const asset of config.assets) {
    if (!existsSync(join(repoRoot, asset.source))) {
      throw new Error(`docs asset does not exist: ${asset.source}`);
    }
  }
}

function rewriteMarkdownLinks(
  markdown: string,
  currentDocument: DocumentConfig,
  basePath: string,
  sourcePathToDocument: Map<string, DocumentConfig>,
  sourcePathToAsset: Map<string, AssetConfig>,
): string {
  return markdown.replace(/\]\(([^)]*)\)/g, (match, rawTarget: string) => {
    const parsedTarget = parseMarkdownLinkTarget(rawTarget);
    if (!parsedTarget || shouldKeepLinkTarget(parsedTarget.destination)) {
      return match;
    }

    const { targetPath, suffix } = splitLocalLinkTarget(parsedTarget.destination);
    if (targetPath === '') {
      return match;
    }

    const normalizedTarget = normalizeLinkTarget(currentDocument.source, targetPath);
    const targetDocument = sourcePathToDocument.get(normalizedTarget);

    if (targetDocument) {
      return `](${formatMarkdownLinkTarget(parsedTarget, `${documentHref(basePath, targetDocument)}${suffix}`)})`;
    }

    const targetAsset = sourcePathToAsset.get(normalizedTarget);
    if (targetAsset) {
      return `](${formatMarkdownLinkTarget(parsedTarget, `${assetHref(basePath, targetAsset)}${suffix}`)})`;
    }

    const targetState = existsSync(join(repoRoot, normalizedTarget))
      ? 'target exists but is not configured for export'
      : 'target does not exist';
    throw new Error(
      `unresolved local Markdown link in ${normalizePath(currentDocument.source)}: ${parsedTarget.destination} (${normalizedTarget}; ${targetState})`,
    );
  });
}

type MarkdownLinkTarget = {
  leadingWhitespace: string;
  destination: string;
  suffix: string;
  enclosedInAngles: boolean;
};

function parseMarkdownLinkTarget(rawTarget: string): MarkdownLinkTarget | null {
  const leadingWhitespace = rawTarget.match(/^\s*/)?.[0] ?? '';
  const linkBody = rawTarget.slice(leadingWhitespace.length);

  if (linkBody === '') {
    return null;
  }

  if (linkBody.startsWith('<')) {
    const closingIndex = linkBody.indexOf('>');
    if (closingIndex === -1) {
      return null;
    }

    return {
      leadingWhitespace,
      destination: linkBody.slice(1, closingIndex),
      suffix: linkBody.slice(closingIndex + 1),
      enclosedInAngles: true,
    };
  }

  const destinationMatch = /^(\S+)([\s\S]*)$/.exec(linkBody);
  if (!destinationMatch) {
    return null;
  }

  return {
    leadingWhitespace,
    destination: destinationMatch[1],
    suffix: destinationMatch[2],
    enclosedInAngles: false,
  };
}

function shouldKeepLinkTarget(target: string): boolean {
  return target.startsWith('#') || target.startsWith('//') || /^[a-z][a-z0-9+.-]*:/i.test(target);
}

function splitLocalLinkTarget(target: string): { targetPath: string; suffix: string } {
  const fragmentIndex = target.indexOf('#');
  const targetBeforeFragment = fragmentIndex === -1 ? target : target.slice(0, fragmentIndex);
  const fragment = fragmentIndex === -1 ? '' : target.slice(fragmentIndex);
  const queryIndex = targetBeforeFragment.indexOf('?');

  if (queryIndex === -1) {
    return { targetPath: targetBeforeFragment, suffix: fragment };
  }

  return {
    targetPath: targetBeforeFragment.slice(0, queryIndex),
    suffix: `${targetBeforeFragment.slice(queryIndex)}${fragment}`,
  };
}

function formatMarkdownLinkTarget(parsedTarget: MarkdownLinkTarget, destination: string): string {
  const formattedDestination = parsedTarget.enclosedInAngles ? `<${destination}>` : destination;
  return `${parsedTarget.leadingWhitespace}${formattedDestination}${parsedTarget.suffix}`;
}

function normalizeLinkTarget(source: string, target: string): string {
  let decodedTarget: string;
  try {
    decodedTarget = decodeURIComponent(target);
  } catch {
    throw new Error(`invalid encoded local Markdown link in ${normalizePath(source)}: ${target}`);
  }

  if (target.startsWith('/')) {
    return normalizePath(decodedTarget.slice(1));
  }

  return normalizePath(join(dirname(source), decodedTarget));
}

function documentHref(basePath: string, document: DocumentConfig): string {
  return `${basePath}/${document.slug === 'index' ? '' : document.slug}`.replace(/\/$/, '');
}

function assetHref(basePath: string, asset: AssetConfig): string {
  return `${basePath.replace(/\/$/, '')}/${normalizePath(asset.output).replace(/^\/+/, '')}`;
}

function normalizePath(path: string): string {
  return normalize(path).replaceAll('\\', '/');
}

function resolveRepoPath(path: string): string {
  return normalize(resolve(repoRoot, path));
}

function currentCommit(): string | null {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repoRoot, encoding: 'utf8' }).trim();
  } catch {
    return null;
  }
}
