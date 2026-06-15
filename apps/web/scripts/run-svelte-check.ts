import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { resolveNodeRuntime } from './node-runtime';

const node = resolveNodeRuntime('Svelte diagnostics');
const svelteKitCli = resolve(process.cwd(), 'node_modules/@sveltejs/kit/svelte-kit.js');
const svelteCheckCli = resolve(process.cwd(), 'node_modules/svelte-check/bin/svelte-check');
const svelteCheckArgs =
  process.argv.length > 2 ? process.argv.slice(2) : ['--tsconfig', './tsconfig.json'];

run([svelteKitCli, 'sync']);
run([svelteCheckCli, ...svelteCheckArgs], {
  NODE_OPTIONS: withNodeOption(process.env.NODE_OPTIONS, '--max-old-space-size=4096'),
});

function run(args: string[], envOverrides: Record<string, string> = {}): void {
  const result = spawnSync(node, args, {
    env: {
      ...process.env,
      ...envOverrides,
    },
    stdio: 'inherit',
  });

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function withNodeOption(current: string | undefined, option: string): string {
  if (!current || current.trim().length === 0) {
    return option;
  }
  if (current.includes(option)) {
    return current;
  }
  return `${current} ${option}`;
}
