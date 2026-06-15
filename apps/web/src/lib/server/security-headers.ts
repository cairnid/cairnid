const HSTS_VALUE = 'max-age=63072000; includeSubDomains';

export function webSecurityHeaders(secureTransport: boolean): Record<string, string> {
  const headers: Record<string, string> = {
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Permissions-Policy':
      'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY'
  };

  if (secureTransport) {
    headers['Strict-Transport-Security'] = HSTS_VALUE;
  }

  return headers;
}

export function applyWebSecurityHeaders(response: Response, secureTransport: boolean): Response {
  const securedResponse = new Response(response.body, response);
  const headers = webSecurityHeaders(secureTransport);

  for (const [name, value] of Object.entries(headers)) {
    securedResponse.headers.set(name, value);
  }

  return securedResponse;
}

export function isSecureRequest(request: Request, url: URL): boolean {
  const forwardedProtocol = request.headers
    .get('x-forwarded-proto')
    ?.split(',')[0]
    ?.trim()
    .toLowerCase();

  return forwardedProtocol === 'https' || url.protocol === 'https:';
}
