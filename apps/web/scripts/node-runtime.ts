import { spawnSync } from 'node:child_process';

export function resolveNodeRuntime(toolName: string): string {
  const node = nodeCandidates().find(canRunNode);
  if (!node) {
    console.error(
      `${toolName} requires a Node-compatible runtime. Set CAIRN_NODE_PATH to a Node 20+ executable and rerun the Bun script.`,
    );
    process.exit(1);
  }

  return node;
}

function nodeCandidates(): string[] {
  const candidates = [
    process.env.CAIRN_NODE_PATH,
    process.env.NODE,
    ...pathLookupNodeCandidates(),
    'node',
  ];

  return [...new Set(candidates.filter((candidate): candidate is string => Boolean(candidate)))];
}

function pathLookupNodeCandidates(): string[] {
  if (process.platform !== 'win32') {
    return [];
  }

  const result = spawnSync('where.exe', ['node'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  });

  if (result.status !== 0 || !result.stdout) {
    return [];
  }

  return result.stdout
    .split(/\r?\n/)
    .map((candidate) => candidate.trim())
    .filter((candidate) => candidate.length > 0);
}

function canRunNode(candidate: string): boolean {
  const result = spawnSync(candidate, ['--version'], {
    encoding: 'utf8',
    stdio: 'ignore',
  });

  return result.status === 0;
}
