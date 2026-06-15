const LOCAL_REDIRECT_ORIGIN = 'http://cairn.local';

export function localRedirectPath(
  value: string | null | undefined,
  fallback = '/admin'
): string {
  const candidate = value?.trim();

  if (
    !candidate ||
    !candidate.startsWith('/') ||
    candidate.startsWith('//') ||
    candidate.includes('\\')
  ) {
    return fallback;
  }

  let url: URL;
  try {
    url = new URL(candidate, LOCAL_REDIRECT_ORIGIN);
  } catch {
    return fallback;
  }

  return url.origin === LOCAL_REDIRECT_ORIGIN
    ? `${url.pathname}${url.search}${url.hash}`
    : fallback;
}
