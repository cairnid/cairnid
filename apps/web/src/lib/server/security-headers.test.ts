import { describe, expect, it } from 'vitest';
import { applyWebSecurityHeaders, isSecureRequest, webSecurityHeaders } from './security-headers';

describe('web security headers', () => {
  it('sets browser hardening headers without HSTS on plain HTTP', () => {
    const headers = webSecurityHeaders(false);

    expect(headers['Content-Security-Policy']).toBeUndefined();
    expect(headers['Cross-Origin-Opener-Policy']).toBe('same-origin');
    expect(headers['Permissions-Policy']).toContain('camera=()');
    expect(headers['Referrer-Policy']).toBe('no-referrer');
    expect(headers['X-Content-Type-Options']).toBe('nosniff');
    expect(headers['X-Frame-Options']).toBe('DENY');
    expect(headers['Strict-Transport-Security']).toBeUndefined();
  });

  it('sets HSTS only for secure transport', () => {
    expect(webSecurityHeaders(true)['Strict-Transport-Security']).toBe(
      'max-age=63072000; includeSubDomains'
    );
  });

  it('detects secure requests behind a trusted proxy', () => {
    const request = new Request('http://internal-web.local', {
      headers: {
        'x-forwarded-proto': 'https, http'
      }
    });

    expect(isSecureRequest(request, new URL('http://internal-web.local'))).toBe(true);
  });

  it('applies headers to a mutable copy of redirect responses', () => {
    const redirect = Response.redirect('https://example.com/login', 303);
    const response = applyWebSecurityHeaders(redirect, true);

    expect(response.status).toBe(303);
    expect(response.headers.get('location')).toBe('https://example.com/login');
    expect(response.headers.get('X-Frame-Options')).toBe('DENY');
    expect(response.headers.get('Strict-Transport-Security')).toBe(
      'max-age=63072000; includeSubDomains'
    );
  });
});
