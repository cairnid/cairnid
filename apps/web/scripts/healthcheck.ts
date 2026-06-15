const port = process.env.PORT ?? '3000';
const controller = new AbortController();
const timeout = setTimeout(() => controller.abort(), 2_000);

try {
  const response = await fetch(`http://127.0.0.1:${port}/healthz`, {
    signal: controller.signal
  });

  if (response.status !== 200) {
    process.exit(1);
  }

  const body = await response.json().catch(() => null);
  process.exit(body?.status === 'ok' ? 0 : 1);
} catch {
  process.exit(1);
} finally {
  clearTimeout(timeout);
}
