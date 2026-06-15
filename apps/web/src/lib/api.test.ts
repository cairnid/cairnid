import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, apiList, resetCsrfTokenForTests, userSchema } from './api';

const originalFetch = globalThis.fetch;
const csrfToken = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg';

afterEach(() => {
  globalThis.fetch = originalFetch;
  resetCsrfTokenForTests();
  vi.restoreAllMocks();
});

describe('api schemas', () => {
  it('validates API user shape', () => {
    const parsed = userSchema.parse({
      id: 'u',
      organization_id: 'o',
      email: 'admin@example.com',
      email_verified: true,
      display_name: 'Admin',
      status: 'active',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });

    expect(parsed.email).toBe('admin@example.com');
  });

  it('adds CSRF headers for unsafe browser API requests', async () => {
    const calls: Array<{ input: RequestInfo | URL; init?: RequestInit }> = [];
    const userPayload = {
      id: 'u',
      organization_id: 'o',
      email: 'admin@example.com',
      email_verified: true,
      display_name: 'Admin',
      status: 'active',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ input, init });

      if (calls.length === 1) {
        return new Response(JSON.stringify({ csrf_token: csrfToken }), {
          headers: { 'Content-Type': 'application/json' },
          status: 200
        });
      }

      return new Response(JSON.stringify(userPayload), {
        headers: { 'Content-Type': 'application/json' },
        status: 201
      });
    }) as typeof fetch;

    await api('/api/v1/users', userSchema, {
      body: JSON.stringify({
        email: 'admin@example.com',
        display_name: 'Admin'
      }),
      method: 'POST'
    });

    expect(calls).toHaveLength(2);
    expect(String(calls[0].input)).toContain('/api/v1/session/csrf');

    const headers = calls[1].init?.headers;
    expect(headers).toBeInstanceOf(Headers);
    expect((headers as Headers).get('Content-Type')).toBe('application/json');
    expect((headers as Headers).get('X-CAIRN-CSRF')).toBe(csrfToken);
  });

  it('does not add JSON content type to bodyless GET requests', async () => {
    const calls: Array<{ input: RequestInfo | URL; init?: RequestInit }> = [];
    const userPayload = {
      id: 'u',
      organization_id: 'o',
      email: 'admin@example.com',
      email_verified: true,
      display_name: 'Admin',
      status: 'active',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ input, init });
      return new Response(JSON.stringify(userPayload), {
        headers: { 'Content-Type': 'application/json' },
        status: 200
      });
    }) as typeof fetch;

    await api('/api/v1/session/me', userSchema);

    expect(calls).toHaveLength(1);
    const headers = calls[0].init?.headers;
    expect(headers).toBeInstanceOf(Headers);
    expect((headers as Headers).get('Content-Type')).toBeNull();
    expect((headers as Headers).get('X-CAIRN-CSRF')).toBeNull();
  });

  it('follows paginated admin list cursors', async () => {
    const calls: Array<{ input: RequestInfo | URL; init?: RequestInit }> = [];
    const firstUser = {
      id: 'u1',
      organization_id: 'o',
      email: 'first@example.com',
      email_verified: true,
      display_name: 'First',
      status: 'active',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    const secondUser = {
      ...firstUser,
      id: 'u2',
      email: 'second@example.com',
      display_name: 'Second'
    };

    globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ input, init });
      const url = new URL(String(input));
      if (url.searchParams.get('cursor') === 'next-page') {
        return new Response(JSON.stringify({ items: [secondUser], next_cursor: null }), {
          headers: { 'Content-Type': 'application/json' },
          status: 200
        });
      }

      return new Response(JSON.stringify({ items: [firstUser], next_cursor: 'next-page' }), {
        headers: { 'Content-Type': 'application/json' },
        status: 200
      });
    }) as typeof fetch;

    const users = await apiList('/api/v1/users', userSchema, 1);

    expect(users.map((user) => user.email)).toEqual(['first@example.com', 'second@example.com']);
    expect(calls).toHaveLength(2);
    expect(String(calls[0].input)).toContain('/api/v1/users?limit=1');
    expect(String(calls[1].input)).toContain('/api/v1/users?limit=1&cursor=next-page');
    expect((calls[0].init?.headers as Headers).get('Content-Type')).toBeNull();
  });

  it('rejects malformed CSRF tokens before unsafe requests are sent', async () => {
    const calls: Array<{ input: RequestInfo | URL; init?: RequestInit }> = [];

    globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ input, init });

      return new Response(JSON.stringify({ csrf_token: 'csrf-token' }), {
        headers: { 'Content-Type': 'application/json' },
        status: 200
      });
    }) as typeof fetch;

    await expect(
      api('/api/v1/users', userSchema, {
        body: JSON.stringify({
          email: 'admin@example.com',
          display_name: 'Admin'
        }),
        method: 'POST'
      })
    ).rejects.toThrow();

    expect(calls).toHaveLength(1);
    expect(String(calls[0].input)).toContain('/api/v1/session/csrf');
  });
});
