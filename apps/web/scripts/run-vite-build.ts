import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { resolveNodeRuntime } from './node-runtime';

const node = resolveNodeRuntime('Vite build');
const viteCli = resolve(process.cwd(), 'node_modules/vite/bin/vite.js');
const args = process.argv.length > 2 ? process.argv.slice(2) : ['build'];

const result = spawnSync(node, [viteCli, ...args], {
  env: {
    ...process.env,
    RAYON_NUM_THREADS: process.env.RAYON_NUM_THREADS ?? '2',
  },
  stdio: 'inherit',
});

process.exit(result.status ?? 1);
