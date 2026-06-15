import { describe, expect, it } from 'vitest';
import { localRedirectPath } from './navigation';

describe('localRedirectPath', () => {
  it('allows same-origin paths with query strings and fragments', () => {
    expect(localRedirectPath('/app?tab=settings#security')).toBe('/app?tab=settings#security');
  });

  it('falls back for absolute and protocol-relative URLs', () => {
    expect(localRedirectPath('https://example.com/app')).toBe('/admin');
    expect(localRedirectPath('//example.com/app')).toBe('/admin');
    expect(localRedirectPath('javascript:alert(1)')).toBe('/admin');
  });

  it('falls back for non-path and backslash redirects', () => {
    expect(localRedirectPath('app')).toBe('/admin');
    expect(localRedirectPath('/\\example.com')).toBe('/admin');
    expect(localRedirectPath(null, '/login')).toBe('/login');
  });
});
