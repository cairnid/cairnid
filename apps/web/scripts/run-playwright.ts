import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { resolveNodeRuntime } from './node-runtime';

const playwrightCli = resolve(process.cwd(), 'node_modules/@playwright/test/cli.js');
const viteCli = resolve(process.cwd(), 'node_modules/vite/bin/vite.js');
const extraArgs = process.argv.slice(2);
const node = resolveNodeRuntime('Playwright');

const build = spawnSync(node, [viteCli, 'build'], {
  env: {
    ...process.env,
    RAYON_NUM_THREADS: process.env.RAYON_NUM_THREADS ?? '2',
  },
  stdio: 'inherit',
});

if (build.status !== 0) {
  process.exit(build.status ?? 1);
}

const result = spawnSync(node, [playwrightCli, 'test', ...extraArgs], {
  env: process.env,
  stdio: 'inherit',
});

process.exit(result.status ?? 1);
