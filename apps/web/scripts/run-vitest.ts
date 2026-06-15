import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { resolveNodeRuntime } from './node-runtime';

const node = resolveNodeRuntime('Vitest');
const vitestCli = resolve(process.cwd(), 'node_modules/vitest/vitest.mjs');
const args = process.argv.length > 2 ? process.argv.slice(2) : ['run'];

const result = spawnSync(node, [vitestCli, ...args], {
  env: process.env,
  stdio: 'inherit',
});

process.exit(result.status ?? 1);
