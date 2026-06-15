import type { Handle } from '@sveltejs/kit';
import { applyWebSecurityHeaders, isSecureRequest } from '$lib/server/security-headers';

export const handle: Handle = async ({ event, resolve }) => {
  const response = await resolve(event);

  return applyWebSecurityHeaders(response, isSecureRequest(event.request, event.url));
};
