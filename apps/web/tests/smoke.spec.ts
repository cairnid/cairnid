import { expect, type Route, test } from '@playwright/test';

const apiOrigin = 'http://localhost:8080';
const csrfToken = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg';
const corsHeaders = {
  'Access-Control-Allow-Credentials': 'true',
  'Access-Control-Allow-Headers': 'content-type,x-cairn-csrf',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Origin': 'http://localhost:3000'
};

test('web health endpoint returns an uncached ok payload', async ({ request }) => {
  const response = await request.get('/healthz');

  expect(response.status()).toBe(200);
  expect(response.headers()['cache-control']).toBe('no-store');
  expect(response.headers()['x-content-type-options']).toBe('nosniff');
  expect(await response.json()).toEqual({ status: 'ok' });
});

test('login page renders', async ({ page }) => {
  const response = await page.goto('/login');
  expect(response?.headers()['content-security-policy']).toContain("default-src 'self'");
  expect(response?.headers()['x-content-type-options']).toBe('nosniff');
  expect(response?.headers()['x-frame-options']).toBe('DENY');

  await expect(page.getByText('Cairn Identity')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
});

test('account lifecycle pages render', async ({ page }) => {
  await page.goto('/reset-password');
  await expect(page.getByRole('button', { name: 'Send recovery email' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Reset password' })).toBeVisible();

  await page.goto('/verify-email');
  await expect(page.getByRole('button', { name: 'Verify email' })).toBeVisible();

  await page.goto('/accept-invitation');
  await expect(page.getByRole('button', { name: 'Accept invitation' })).toBeVisible();
});

test('admin overview displays API and security settings', async ({ page }) => {
  await page.route(`${apiOrigin}/**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (request.method() === 'OPTIONS') {
      await route.fulfill({
        headers: corsHeaders,
        status: 204
      });
      return;
    }

    if (url.pathname === '/api/v1/settings') {
      await fulfillJson(route, {
        issuer: 'http://localhost:8080',
        public_web_origin: 'http://localhost:3000',
        organization_id: '11111111-1111-4111-8111-111111111111',
        signing_configured: true,
        database_signing_configured: true,
        key_encryption_configured: true
      });
      return;
    }

    await route.fallback();
  });

  await page.goto('/admin');
  await expect(page.getByText('Connected')).toBeVisible();
  await expect(page.getByText('http://localhost:8080')).toBeVisible();
  await expect(page.getByText('RS256 configured')).toBeVisible();
  await expect(page.getByText('KEK configured')).toBeVisible();
});

test('admin users page suspends a user through a CSRF-protected status update', async ({ page }) => {
  const adminUser = {
    id: 'user-1',
    organization_id: 'org-1',
    email: 'admin@example.com',
    email_verified: true,
    display_name: 'Admin',
    status: 'active',
    created_at: '2026-06-07T00:00:00Z',
    updated_at: '2026-06-07T00:00:00Z'
  };
  let targetUser = {
    id: 'user-2',
    organization_id: 'org-1',
    email: 'target@example.com',
    email_verified: true,
    display_name: 'Target User',
    status: 'active',
    created_at: '2026-06-07T00:00:00Z',
    updated_at: '2026-06-07T00:00:00Z'
  };
  let csrfRequests = 0;
  let statusUpdateRequests = 0;
  let userListRequests = 0;
  let sessionListRequests = 0;
  let sessionRevokeRequests = 0;
  let oldSessionActive = true;
  const oldSessionId = '11111111-1111-4111-8111-111111111910';

  await page.route(`${apiOrigin}/**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (request.method() === 'OPTIONS') {
      await route.fulfill({
        headers: corsHeaders,
        status: 204
      });
      return;
    }

    if (url.pathname === '/api/v1/session/csrf') {
      csrfRequests += 1;
      await fulfillJson(route, { csrf_token: csrfToken });
      return;
    }

    if (url.pathname === '/api/v1/users' && request.method() === 'GET') {
      userListRequests += 1;
      expect(url.searchParams.get('limit')).toBe('100');
      const query = url.searchParams.get('q');
      const users = query === 'target' ? [targetUser] : [adminUser, targetUser];
      await fulfillJson(route, { items: users, next_cursor: null });
      return;
    }

    if (url.pathname === '/api/v1/users/user-2/status') {
      expect(request.method()).toBe('PUT');
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      const payload = request.postDataJSON() as { status?: string };
      expect(payload.status).toBe('suspended');
      statusUpdateRequests += 1;
      targetUser = {
        ...targetUser,
        status: 'suspended',
        updated_at: '2026-06-07T00:01:00Z'
      };
      await fulfillJson(route, targetUser);
      return;
    }

    if (url.pathname === '/api/v1/users/user-2/browser-sessions' && request.method() === 'GET') {
      sessionListRequests += 1;
      await fulfillJson(route, {
        sessions: oldSessionActive
          ? [
              {
                id: oldSessionId,
                current: false,
                acr: 'urn:cairn:acr:password+totp',
                amr: ['pwd', 'otp'],
                created_at: '2026-06-07T00:00:00Z',
                expires_at: '2026-06-07T12:00:00Z',
                created_ip_address: '203.0.113.40',
                created_user_agent: 'Old Browser/1.0'
              }
            ]
          : []
      });
      return;
    }

    if (url.pathname === `/api/v1/users/user-2/browser-sessions/${oldSessionId}`) {
      expect(request.method()).toBe('DELETE');
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      sessionRevokeRequests += 1;
      oldSessionActive = false;
      await fulfillJson(route, {
        status: 'revoked',
        session_id: oldSessionId
      });
      return;
    }

    await route.fulfill({
      headers: corsHeaders,
      status: 404
    });
  });

  await page.goto('/admin/users');

  await page.getByLabel('Search').fill('target');
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await expect(page.getByRole('row').filter({ hasText: 'admin@example.com' })).toHaveCount(0);

  const targetRow = page.getByRole('row').filter({ hasText: 'target@example.com' });
  await expect(targetRow.getByRole('cell', { name: /^active$/ })).toBeVisible();
  await expect(targetRow.getByTitle('Suspend user')).toBeEnabled();

  await targetRow.getByTitle('Suspend user').click();

  await expect(targetRow.getByRole('cell', { name: /^suspended$/ })).toBeVisible();
  await expect(targetRow.getByTitle('Suspend user')).toBeDisabled();
  await expect(targetRow.getByTitle('Activate user')).toBeEnabled();

  await targetRow.getByTitle('Review browser sessions').click();
  await expect(page.getByText('Browser sessions', { exact: true })).toBeVisible();
  await expect(page.getByText('Old Browser/1.0')).toBeVisible();
  await page.getByRole('button', { name: `Revoke browser session ${oldSessionId}` }).click();
  await expect(page.getByText('Browser session revoked for target@example.com')).toBeVisible();
  await expect(page.getByText('Old Browser/1.0')).toBeHidden();

  expect(csrfRequests).toBe(1);
  expect(statusUpdateRequests).toBe(1);
  expect(userListRequests).toBe(3);
  expect(sessionListRequests).toBe(1);
  expect(sessionRevokeRequests).toBe(1);
});

test('admin users page sends lifecycle emails through CSRF-protected actions', async ({ page }) => {
  const targetUser = {
    id: 'user-lifecycle',
    organization_id: 'org-1',
    email: 'lifecycle@example.com',
    email_verified: false,
    display_name: 'Lifecycle User',
    status: 'active',
    created_at: '2026-06-07T00:00:00Z',
    updated_at: '2026-06-07T00:00:00Z'
  };
  let csrfRequests = 0;
  let userListRequests = 0;
  let verificationRequests = 0;
  let passwordResetRequests = 0;

  await page.route(`${apiOrigin}/**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (request.method() === 'OPTIONS') {
      await route.fulfill({
        headers: corsHeaders,
        status: 204
      });
      return;
    }

    if (url.pathname === '/api/v1/session/csrf') {
      csrfRequests += 1;
      await fulfillJson(route, { csrf_token: csrfToken });
      return;
    }

    if (url.pathname === '/api/v1/users' && request.method() === 'GET') {
      userListRequests += 1;
      expect(url.searchParams.get('limit')).toBe('100');
      await fulfillJson(route, { items: [targetUser], next_cursor: null });
      return;
    }

    if (url.pathname === '/api/v1/users/user-lifecycle/email-verification/request') {
      expect(request.method()).toBe('POST');
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      verificationRequests += 1;
      await fulfillJson(route, {
        status: 'queued',
        email_outbox_id: '11111111-1111-4111-8111-111111111920',
        recipient_email: targetUser.email,
        expires_at: '2026-06-08T00:00:00Z',
        preview_url: 'http://localhost:3000/verify-email?token=admin-verify'
      });
      return;
    }

    if (url.pathname === '/api/v1/users/user-lifecycle/password-recovery/request') {
      expect(request.method()).toBe('POST');
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      passwordResetRequests += 1;
      await fulfillJson(route, {
        status: 'queued',
        email_outbox_id: '11111111-1111-4111-8111-111111111921',
        recipient_email: targetUser.email,
        expires_at: '2026-06-07T01:00:00Z',
        preview_url: 'http://localhost:3000/reset-password?token=admin-reset'
      });
      return;
    }

    await route.fulfill({
      headers: corsHeaders,
      status: 404
    });
  });

  await page.goto('/admin/users');
  const targetRow = page.getByRole('row').filter({ hasText: targetUser.email });
  await expect(targetRow.getByTitle('Send verification email')).toBeEnabled();
  await expect(targetRow.getByTitle('Send password reset')).toBeEnabled();

  await targetRow.getByTitle('Send verification email').click();
  await expect(
    page.getByText('Verification email queued for lifecycle@example.com. Development preview link is available.')
  ).toBeVisible();
  await expect(page.getByRole('link', { name: /verify-email\?token=admin-verify/ })).toBeVisible();

  await targetRow.getByTitle('Send password reset').click();
  await expect(
    page.getByText('Password reset queued for lifecycle@example.com. Development preview link is available.')
  ).toBeVisible();
  await expect(page.getByRole('link', { name: /reset-password\?token=admin-reset/ })).toBeVisible();

  expect(csrfRequests).toBe(1);
  expect(userListRequests).toBe(1);
  expect(verificationRequests).toBe(1);
  expect(passwordResetRequests).toBe(1);
});

test('admin users page reviews security activity through a bounded list API', async ({ page }) => {
  const targetUser = {
    id: 'user-lifecycle',
    organization_id: 'org-1',
    email: 'lifecycle@example.com',
    email_verified: true,
    display_name: 'Lifecycle User',
    status: 'active',
    created_at: '2026-06-07T00:00:00Z',
    updated_at: '2026-06-07T00:00:00Z'
  };
  let userListRequests = 0;
  let securityEventRequests = 0;

  await page.route(`${apiOrigin}/**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (request.method() === 'OPTIONS') {
      await route.fulfill({
        headers: corsHeaders,
        status: 204
      });
      return;
    }

    if (url.pathname === '/api/v1/users' && request.method() === 'GET') {
      userListRequests += 1;
      expect(url.searchParams.get('limit')).toBe('100');
      await fulfillJson(route, { items: [targetUser], next_cursor: null });
      return;
    }

    if (url.pathname === '/api/v1/users/user-lifecycle/security-events' && request.method() === 'GET') {
      securityEventRequests += 1;
      expect(url.searchParams.get('limit')).toBe('25');
      expect(url.searchParams.get('cursor')).toBeNull();
      await fulfillJson(route, {
        items: [
          {
            id: 'event-1',
            organization_id: 'org-1',
            actor_kind: 'user',
            actor_id: targetUser.id,
            action: 'account.password_changed',
            target: targetUser.id,
            ip_address: '198.51.100.20',
            user_agent: 'Browser/1.0',
            created_at: '2026-06-07T00:02:00Z',
            metadata: {
              result: 'ok',
              subject_user_id: targetUser.id
            }
          }
        ],
        next_cursor: null
      });
      return;
    }

    await route.fulfill({
      headers: corsHeaders,
      status: 404
    });
  });

  await page.goto('/admin/users');

  const targetRow = page.getByRole('row').filter({ hasText: targetUser.email });
  await targetRow.getByTitle('Review security activity').click();

  await expect(page.getByText('Security activity', { exact: true })).toBeVisible();
  await expect(page.getByText(targetUser.email).last()).toBeVisible();
  await expect(page.getByText('account.password_changed')).toBeVisible();
  await expect(page.getByText(`user:${targetUser.id}`)).toBeVisible();
  await expect(page.getByText('198.51.100.20')).toBeVisible();
  await expect(page.getByText('Browser/1.0')).toBeVisible();
  await expect(page.getByText(/"subject_user_id":"user-lifecycle"/)).toBeVisible();

  expect(userListRequests).toBe(1);
  expect(securityEventRequests).toBe(1);
});

test('admin applications page filters OIDC clients through the list API', async ({ page }) => {
  const publicClient = {
    id: '11111111-1111-4111-8111-111111111101',
    organization_id: '11111111-1111-4111-8111-111111111001',
    client_id: 'public-web',
    consent_policy_template_id: null as string | null,
    name: 'Public Web',
    redirect_uris: [{ value: 'https://app.example.com/callback' }],
    post_logout_redirect_uris: [{ value: 'https://app.example.com/signed-out' }],
    allowed_scopes: ['openid', 'profile'],
    grant_types: ['authorization_code', 'refresh_token'],
    public_client: true,
    require_pkce: true,
    status: 'active',
    has_client_secret: false,
    created_at: '2026-06-07T00:00:00Z'
  };
  let confidentialClient = {
    id: '11111111-1111-4111-8111-111111111102',
    organization_id: '11111111-1111-4111-8111-111111111001',
    client_id: 'target-service',
    consent_policy_template_id: null as string | null,
    name: 'Target Service',
    redirect_uris: [{ value: 'https://service.example.com/callback' }],
    post_logout_redirect_uris: [{ value: 'https://service.example.com/signed-out' }],
    allowed_scopes: ['openid', 'email'],
    grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
    public_client: false,
    require_pkce: true,
    status: 'active',
    has_client_secret: true,
    created_at: '2026-06-07T00:01:00Z'
  };
  const consentPolicyTemplate = {
    id: '11111111-1111-4111-8111-111111111401',
    organization_id: publicClient.organization_id,
    slug: 'sensitive-claims',
    name: 'Sensitive Claims',
    grant_mode: 'always_required',
    created_at: '2026-06-07T00:02:00Z'
  };
  let consentPolicyTemplates: typeof consentPolicyTemplate[] = [];
  let createdClient: typeof publicClient | null = null;
  let clientListRequests = 0;
  let clientCreateRequests = 0;
  let policyListRequests = 0;
  let policyCreateRequests = 0;
  let clientUpdateRequests = 0;
  let secretRotationRequests = 0;
  let statusUpdateRequests = 0;
  let consentReviewRequests = 0;
  let consentRevocationRequests = 0;
  let csrfRequests = 0;
  let reviewedGrant = {
    id: '11111111-1111-4111-8111-111111111201',
    organization_id: confidentialClient.organization_id,
    user_id: '11111111-1111-4111-8111-111111111301',
    user_email: 'reader@example.com',
    user_display_name: 'Reader User',
    client_id: confidentialClient.id,
    scopes: ['openid', 'email'],
    created_at: '2026-06-07T00:02:00Z',
    revoked_at: null as string | null
  };

  await page.route(`${apiOrigin}/**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (request.method() === 'OPTIONS') {
      await route.fulfill({
        headers: corsHeaders,
        status: 204
      });
      return;
    }

    if (url.pathname === '/api/v1/session/csrf') {
      csrfRequests += 1;
      await fulfillJson(route, { csrf_token: csrfToken });
      return;
    }

    if (url.pathname === '/api/v1/oidc/clients' && request.method() === 'GET') {
      clientListRequests += 1;
      expect(url.searchParams.get('limit')).toBe('100');
      if (url.searchParams.get('q') === 'target') {
        expect(url.searchParams.get('client_type')).toBe('confidential');
        expect(url.searchParams.get('grant_type')).toBe('client_credentials');
        expect(url.searchParams.get('scope')).toBe('email');
        await fulfillJson(route, { items: [confidentialClient], next_cursor: null });
        return;
      }
      await fulfillJson(route, {
        items: [publicClient, confidentialClient, ...(createdClient ? [createdClient] : [])],
        next_cursor: null
      });
      return;
    }

    if (url.pathname === '/api/v1/oidc/clients' && request.method() === 'POST') {
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      const payload = request.postDataJSON() as {
        client_id?: string;
        name?: string;
        consent_policy_template_id?: string;
        redirect_uris?: string[];
        post_logout_redirect_uris?: string[];
        allowed_scopes?: string[];
        public_client?: boolean;
      };
      expect(payload.client_id).toBe('sensitive-web');
      expect(payload.name).toBe('Sensitive Web');
      expect(payload.consent_policy_template_id).toBe(consentPolicyTemplate.id);
      expect(payload.redirect_uris).toEqual(['https://sensitive.example.com/callback']);
      expect(payload.post_logout_redirect_uris).toEqual(['https://sensitive.example.com/signed-out']);
      expect(payload.allowed_scopes).toEqual(['openid', 'profile', 'email', 'groups']);
      expect(payload.public_client).toBe(true);
      clientCreateRequests += 1;
      createdClient = {
        ...publicClient,
        id: '11111111-1111-4111-8111-111111111103',
        client_id: 'sensitive-web',
        consent_policy_template_id: consentPolicyTemplate.id,
        name: 'Sensitive Web',
        redirect_uris: [{ value: 'https://sensitive.example.com/callback' }],
        post_logout_redirect_uris: [{ value: 'https://sensitive.example.com/signed-out' }],
        allowed_scopes: ['openid', 'profile', 'email', 'groups'],
        created_at: '2026-06-07T00:03:00Z'
      };
      await fulfillJson(route, { client: createdClient });
      return;
    }

    if (
      url.pathname === `/api/v1/oidc/clients/${confidentialClient.id}` &&
      request.method() === 'PUT'
    ) {
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      const payload = request.postDataJSON() as Record<string, unknown>;
      expect(Object.keys(payload).sort()).toEqual([
        'allowed_scopes',
        'consent_policy_template_id',
        'name',
        'post_logout_redirect_uris',
        'redirect_uris'
      ]);
      expect(payload.name).toBe('Target Service Updated');
      expect(payload.redirect_uris).toEqual(['https://service.example.com/callback-updated']);
      expect(payload.post_logout_redirect_uris).toEqual([
        'https://service.example.com/signed-out-updated'
      ]);
      expect(payload.allowed_scopes).toEqual(['openid', 'email', 'groups']);
      expect(payload.consent_policy_template_id).toBe(consentPolicyTemplate.id);
      expect(payload.client_id).toBeUndefined();
      expect(payload.public_client).toBeUndefined();
      expect(payload.grant_types).toBeUndefined();
      expect(payload.require_pkce).toBeUndefined();
      expect(payload.status).toBeUndefined();
      expect(payload.has_client_secret).toBeUndefined();
      expect(payload.client_secret_hash).toBeUndefined();
      clientUpdateRequests += 1;
      confidentialClient = {
        ...confidentialClient,
        consent_policy_template_id: consentPolicyTemplate.id,
        name: 'Target Service Updated',
        redirect_uris: [{ value: 'https://service.example.com/callback-updated' }],
        post_logout_redirect_uris: [{ value: 'https://service.example.com/signed-out-updated' }],
        allowed_scopes: ['openid', 'email', 'groups']
      };
      await fulfillJson(route, {
        client: confidentialClient,
        authorization_codes_invalidated: 2,
        access_tokens_revoked: 1,
        refresh_tokens_revoked: 0
      });
      return;
    }

    if (
      url.pathname === `/api/v1/oidc/clients/${confidentialClient.id}/secret/rotate` &&
      request.method() === 'POST'
    ) {
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      secretRotationRequests += 1;
      confidentialClient = { ...confidentialClient, has_client_secret: true };
      await fulfillJson(route, {
        client: confidentialClient,
        client_secret: 'rotated-secret-value'
      });
      return;
    }

    if (
      url.pathname === `/api/v1/oidc/clients/${confidentialClient.id}/status` &&
      request.method() === 'PUT'
    ) {
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      const payload = request.postDataJSON() as { status?: 'active' | 'disabled' };
      expect(['active', 'disabled']).toContain(payload.status);
      statusUpdateRequests += 1;
      confidentialClient = { ...confidentialClient, status: payload.status ?? 'active' };
      await fulfillJson(route, {
        client: confidentialClient,
        authorization_codes_invalidated: payload.status === 'disabled' ? 1 : 0,
        access_tokens_revoked: payload.status === 'disabled' ? 1 : 0,
        refresh_tokens_revoked: payload.status === 'disabled' ? 1 : 0
      });
      return;
    }

    if (
      url.pathname === '/api/v1/oidc/consent-policy-templates' &&
      request.method() === 'GET'
    ) {
      policyListRequests += 1;
      expect(url.searchParams.get('limit')).toBe('100');
      await fulfillJson(route, { items: consentPolicyTemplates, next_cursor: null });
      return;
    }

    if (
      url.pathname === '/api/v1/oidc/consent-policy-templates' &&
      request.method() === 'POST'
    ) {
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      const payload = request.postDataJSON() as {
        slug?: string;
        name?: string;
        grant_mode?: string;
      };
      expect(payload.slug).toBe(consentPolicyTemplate.slug);
      expect(payload.name).toBe(consentPolicyTemplate.name);
      expect(payload.grant_mode).toBe(consentPolicyTemplate.grant_mode);
      policyCreateRequests += 1;
      consentPolicyTemplates = [consentPolicyTemplate];
      await fulfillJson(route, consentPolicyTemplate, 201);
      return;
    }

    if (
      url.pathname === `/api/v1/oidc/clients/${confidentialClient.id}/consent-grants` &&
      request.method() === 'GET'
    ) {
      consentReviewRequests += 1;
      expect(url.searchParams.get('limit')).toBe('25');
      await fulfillJson(route, {
        items: [reviewedGrant],
        next_cursor: null
      });
      return;
    }

    if (
      url.pathname ===
        `/api/v1/oidc/clients/${confidentialClient.id}/consent-grants/${reviewedGrant.id}` &&
      request.method() === 'DELETE'
    ) {
      consentRevocationRequests += 1;
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      reviewedGrant = { ...reviewedGrant, revoked_at: '2026-06-07T00:03:00Z' };
      await fulfillJson(route, {
        grant: reviewedGrant,
        consent_grants_revoked: 1,
        authorization_codes_invalidated: 1,
        access_tokens_revoked: 1,
        refresh_tokens_revoked: 1
      });
      return;
    }

    await route.fulfill({
      headers: corsHeaders,
      status: 404
    });
  });

  await page.goto('/admin/applications');
  await expect(page.getByRole('row').filter({ hasText: 'public-web' })).toHaveCount(1);

  await page.getByLabel('Slug').fill('sensitive-claims');
  await page.getByLabel('Policy name').fill('Sensitive Claims');
  await page.getByLabel('Grant mode').selectOption('always_required');
  await page.getByRole('button', { name: 'Create policy' }).click();
  await expect(page.getByRole('row').filter({ hasText: 'Sensitive Claims' })).toHaveCount(1);

  await page.getByLabel('Client ID').fill('sensitive-web');
  await page.getByLabel('Client name').fill('Sensitive Web');
  await page
    .getByLabel('Authorization redirect URIs')
    .fill('https://sensitive.example.com/callback');
  await page
    .getByLabel('Post-logout redirect URIs')
    .fill('https://sensitive.example.com/signed-out');
  await page.getByLabel('Consent policy').selectOption(consentPolicyTemplate.id);
  await page.getByRole('button', { name: 'Create client' }).click();
  const sensitiveRow = page.getByRole('row').filter({ hasText: 'sensitive-web' });
  await expect(sensitiveRow).toHaveCount(1);
  await expect(sensitiveRow.getByText('Sensitive Claims (Always required)')).toBeVisible();

  await page.getByLabel('Search').fill('target');
  await page.getByLabel('Client type').selectOption('confidential');
  await page.getByLabel('Grant type').selectOption('client_credentials');
  await page.getByLabel('Scope filter').fill('email');
  await page.getByRole('button', { name: 'Apply filters' }).click();

  const targetRow = page.getByRole('row').filter({ hasText: 'target-service' });
  await expect(targetRow).toHaveCount(1);
  await expect(page.getByRole('row').filter({ hasText: 'public-web' })).toHaveCount(0);
  await expect(page.getByText('email_verified')).toBeVisible();

  await targetRow.getByRole('button', { name: 'Edit client target-service' }).click();
  const editPanel = page.getByRole('region', { name: 'Edit application' });
  await expect(editPanel.getByText('target-service / Confidential / Active')).toBeVisible();
  await expect(editPanel.getByLabel('Edit client name')).toHaveValue('Target Service');
  await expect(editPanel.getByLabel('Edit authorization redirect URIs')).toHaveValue(
    'https://service.example.com/callback'
  );
  await expect(editPanel.getByLabel('Edit post-logout redirect URIs')).toHaveValue(
    'https://service.example.com/signed-out'
  );
  await expect(editPanel.getByLabel('Edit scopes')).toHaveValue('openid email');
  await expect(editPanel.getByLabel('Edit consent policy')).toHaveValue('');
  await expect(editPanel.getByLabel('Edit client ID')).toHaveCount(0);
  await expect(editPanel.getByLabel('Public client')).toHaveCount(0);
  await expect(editPanel.getByLabel('Grant types')).toHaveCount(0);
  await expect(editPanel.getByLabel('PKCE')).toHaveCount(0);
  await expect(editPanel.getByLabel('Status')).toHaveCount(0);
  await expect(editPanel.getByLabel('Secret')).toHaveCount(0);

  await editPanel.getByLabel('Edit client name').fill('Target Service Updated');
  await editPanel
    .getByLabel('Edit authorization redirect URIs')
    .fill('https://service.example.com/callback-updated');
  await editPanel
    .getByLabel('Edit post-logout redirect URIs')
    .fill('https://service.example.com/signed-out-updated');
  await editPanel.getByLabel('Edit scopes').fill('openid email groups');
  await editPanel.getByLabel('Edit consent policy').selectOption(consentPolicyTemplate.id);
  await editPanel.getByRole('button', { name: 'Save changes' }).click();
  await expect(
    editPanel.getByText(
      'Client updated for target-service; authorization codes invalidated: 2; access tokens revoked: 1; refresh tokens revoked: 0'
    )
  ).toBeVisible();
  await expect(targetRow.getByText('Target Service Updated')).toBeVisible();
  await expect(targetRow.getByText('https://service.example.com/callback-updated')).toBeVisible();
  await expect(targetRow.getByText('https://service.example.com/signed-out-updated')).toBeVisible();
  await expect(targetRow.getByRole('cell', { name: 'openid, email, groups' })).toBeVisible();
  await expect(targetRow.getByText('Sensitive Claims (Always required)')).toBeVisible();

  page.once('dialog', async (dialog) => {
    expect(dialog.message()).toContain('target-service');
    await dialog.accept();
  });
  await targetRow.getByRole('button', { name: 'Rotate secret for target-service' }).click();
  await expect(page.getByText('Rotated client secret: rotated-secret-value')).toBeVisible();

  page.once('dialog', async (dialog) => {
    expect(dialog.message()).toContain('target-service');
    await dialog.accept();
  });
  await targetRow.getByRole('button', { name: 'Disable client target-service' }).click();
  await expect(
    page.getByText('Client disabled for target-service; 3 runtime credentials invalidated')
  ).toBeVisible();
  await expect(targetRow.getByText('Disabled', { exact: true })).toBeVisible();

  await targetRow.getByRole('button', { name: 'Reactivate client target-service' }).click();
  await expect(page.getByText('Client reactivated for target-service')).toBeVisible();
  await expect(targetRow.getByText('Active', { exact: true })).toBeVisible();

  await targetRow.getByRole('button', { name: 'Review consent for target-service' }).click();
  await expect(page.getByText('reader@example.com')).toBeVisible();
  await expect(page.getByText('Reader User')).toBeVisible();
  const readerConsent = targetRow.locator('.consent-entry').filter({ hasText: 'reader@example.com' });
  await expect(readerConsent.getByText('Active', { exact: true })).toBeVisible();

  page.once('dialog', async (dialog) => {
    expect(dialog.message()).toContain('reader@example.com');
    await dialog.accept();
  });
  await page.getByRole('button', { name: 'Revoke consent for reader@example.com' }).click();
  await expect(readerConsent.getByText('Revoked', { exact: true })).toBeVisible();
  expect(clientListRequests).toBe(4);
  expect(clientCreateRequests).toBe(1);
  expect(policyListRequests).toBe(4);
  expect(policyCreateRequests).toBe(1);
  expect(clientUpdateRequests).toBe(1);
  expect(secretRotationRequests).toBe(1);
  expect(statusUpdateRequests).toBe(2);
  expect(consentReviewRequests).toBe(2);
  expect(consentRevocationRequests).toBe(1);
  expect(csrfRequests).toBe(1);
});

test('admin audit page filters events through the list API', async ({ page }) => {
  const matchingEvent = {
    id: 'event-1',
    actor_kind: 'user',
    actor_id: '11111111-1111-4111-8111-111111111111',
    action: 'admin.user_created',
    target: 'user-2',
    metadata: { status: 'created' },
    created_at: '2026-06-07T00:00:00Z'
  };
  const otherEvent = {
    id: 'event-2',
    actor_kind: 'system',
    actor_id: null,
    action: 'system.started',
    target: 'control-plane',
    metadata: {},
    created_at: '2026-06-07T00:01:00Z'
  };
  let auditListRequests = 0;

  await page.route(`${apiOrigin}/**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (request.method() === 'OPTIONS') {
      await route.fulfill({
        headers: corsHeaders,
        status: 204
      });
      return;
    }

    if (url.pathname === '/api/v1/audit-events' && request.method() === 'GET') {
      auditListRequests += 1;
      expect(url.searchParams.get('limit')).toBe('100');
      if (url.searchParams.get('action') === 'admin.user') {
        expect(url.searchParams.get('target')).toBe('user-2');
        expect(url.searchParams.get('actor_kind')).toBe('user');
        expect(url.searchParams.get('actor_id')).toBe(matchingEvent.actor_id);
        await fulfillJson(route, { items: [matchingEvent], next_cursor: null });
        return;
      }
      await fulfillJson(route, { items: [matchingEvent, otherEvent], next_cursor: null });
      return;
    }

    await route.fulfill({
      headers: corsHeaders,
      status: 404
    });
  });

  await page.goto('/admin/audit');
  await expect(page.getByRole('row').filter({ hasText: 'system.started' })).toHaveCount(1);

  await page.getByLabel('Action').fill('admin.user');
  await page.getByLabel('Target').fill('user-2');
  await page.getByLabel('Actor kind').selectOption('user');
  await page.getByLabel('Actor ID').fill(matchingEvent.actor_id);
  await page.getByRole('button', { name: 'Apply filters' }).click();

  await expect(page.getByRole('row').filter({ hasText: 'admin.user_created' })).toHaveCount(1);
  await expect(page.getByRole('row').filter({ hasText: 'system.started' })).toHaveCount(0);
  expect(auditListRequests).toBe(2);
});

test('account page changes password after inline reauthentication', async ({ page }) => {
  let passwordChangeRequests = 0;
  let reauthenticationRequests = 0;

  await page.route(`${apiOrigin}/**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (request.method() === 'OPTIONS') {
      await route.fulfill({
        headers: corsHeaders,
        status: 204
      });
      return;
    }

    if (url.pathname === '/api/v1/session/csrf') {
      await fulfillJson(route, { csrf_token: csrfToken });
      return;
    }

    if (url.pathname === '/api/v1/session/me') {
      await fulfillJson(route, {
        id: 'user-1',
        organization_id: 'org-1',
        email: 'admin@example.com',
        email_verified: true,
        display_name: 'Admin',
        status: 'active',
        created_at: '2026-06-07T00:00:00Z',
        updated_at: '2026-06-07T00:00:00Z'
      });
      return;
    }

    if (url.pathname === '/api/v1/session/mfa/credentials') {
      await fulfillJson(route, {
        credentials: [
          {
            id: 'credential-1',
            kind: 'totp',
            label: 'Authenticator app',
            status: 'active',
            created_at: '2026-06-07T00:00:00Z',
            last_used_at: null
          }
        ],
        recovery_code_count: 10
      });
      return;
    }

    if (url.pathname === '/api/v1/session/browser-sessions') {
      await fulfillJson(route, browserSessionList());
      return;
    }

    if (url.pathname === '/api/v1/session/consent-grants') {
      expect(request.method()).toBe('GET');
      expect(url.searchParams.get('status')).toBe('all');
      expect(url.searchParams.get('limit')).toBe('25');
      await fulfillJson(route, { items: [], next_cursor: null });
      return;
    }

    if (url.pathname === '/api/v1/session/password/change') {
      expect(request.method()).toBe('POST');
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      const payload = request.postDataJSON() as {
        current_password?: string;
        new_password?: string;
      };
      expect(payload.current_password).toBe('old-password-1234');
      expect(payload.new_password).toBe('new-password-1234');
      passwordChangeRequests += 1;
      if (passwordChangeRequests === 1) {
        await fulfillJson(route, { error: 'fresh MFA verification required' }, 403);
        return;
      }

      await fulfillJson(
        route,
        {
          status: 'changed',
          sessions_revoked: 2,
          access_tokens_revoked: 1,
          refresh_tokens_revoked: 1,
          account_tokens_consumed: 1,
          acr: 'urn:cairn:acr:password+totp',
          amr: ['pwd', 'otp']
        },
        200,
        {
          'Set-Cookie': 'cairn_session=password-change-session; Path=/; HttpOnly; SameSite=Lax'
        }
      );
      return;
    }

    if (url.pathname === '/api/v1/session/reauthenticate') {
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      const payload = request.postDataJSON() as { password?: string; mfa_code?: string };
      expect(payload.password).toBe('correct-password');
      expect(payload.mfa_code).toBe('123456');
      reauthenticationRequests += 1;
      await fulfillJson(route, {
        status: 'reauthenticated',
        acr: 'urn:cairn:acr:password+totp',
        amr: ['pwd', 'otp']
      });
      return;
    }

    await route.fulfill({
      headers: corsHeaders,
      status: 404
    });
  });

  await page.goto('/app');
  await page.getByLabel('Current password').fill('old-password-1234');
  await page.getByLabel('New password').fill('new-password-1234');
  await page.getByLabel('Confirm password').fill('new-password-1234');
  await page.getByRole('button', { name: 'Change password' }).click();

  await expect(page.getByText('Reauthenticate to change password')).toBeVisible();
  await expect(page.locator('strong').filter({ hasText: 'Change password' })).toBeVisible();

  await page.getByLabel('Password', { exact: true }).fill('correct-password');
  await page.getByLabel('Authenticator or recovery code').fill('123456');
  await page.getByRole('button', { name: 'Confirm' }).click();

  await expect(page.getByText('Password changed. 2 sessions revoked.')).toBeVisible();
  await expect(page.getByLabel('Current password')).toHaveValue('');
  await expect(page.getByLabel('New password')).toHaveValue('');
  await expect(page.getByLabel('Confirm password')).toHaveValue('');
  expect(passwordChangeRequests).toBe(2);
  expect(reauthenticationRequests).toBe(1);
});

test('account page revokes an old browser session', async ({ page }) => {
  const oldSessionId = '11111111-1111-4111-8111-111111111902';
  let oldSessionActive = true;
  let sessionListRequests = 0;
  let sessionRevokeRequests = 0;

  await page.route(`${apiOrigin}/**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (request.method() === 'OPTIONS') {
      await route.fulfill({
        headers: corsHeaders,
        status: 204
      });
      return;
    }

    if (url.pathname === '/api/v1/session/csrf') {
      await fulfillJson(route, { csrf_token: csrfToken });
      return;
    }

    if (url.pathname === '/api/v1/session/me') {
      await fulfillJson(route, {
        id: 'user-1',
        organization_id: 'org-1',
        email: 'admin@example.com',
        email_verified: true,
        display_name: 'Admin',
        status: 'active',
        created_at: '2026-06-07T00:00:00Z',
        updated_at: '2026-06-07T00:00:00Z'
      });
      return;
    }

    if (url.pathname === '/api/v1/session/mfa/credentials') {
      await fulfillJson(route, {
        credentials: [],
        recovery_code_count: 0
      });
      return;
    }

    if (url.pathname === '/api/v1/session/consent-grants') {
      await fulfillJson(route, { items: [], next_cursor: null });
      return;
    }

    if (url.pathname === '/api/v1/session/browser-sessions' && request.method() === 'GET') {
      sessionListRequests += 1;
      await fulfillJson(
        route,
        browserSessionList(
          oldSessionActive
            ? [
                {
                  id: oldSessionId,
                  current: false,
                  acr: 'urn:cairn:acr:password',
                  amr: ['pwd'],
                  created_at: '2026-06-06T00:00:00Z',
                  expires_at: '2026-06-06T12:00:00Z',
                  created_ip_address: '198.51.100.8',
                  created_user_agent: 'Old Browser/1.0'
                }
              ]
            : []
        )
      );
      return;
    }

    if (url.pathname === `/api/v1/session/browser-sessions/${oldSessionId}`) {
      expect(request.method()).toBe('DELETE');
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      sessionRevokeRequests += 1;
      oldSessionActive = false;
      await fulfillJson(route, {
        status: 'revoked',
        session_id: oldSessionId
      });
      return;
    }

    await route.fulfill({
      headers: corsHeaders,
      status: 404
    });
  });

  await page.goto('/app');
  await expect(page.getByText('Browser sessions', { exact: true })).toBeVisible();
  await expect(page.getByText('Old Browser/1.0')).toBeVisible();
  await expect(page.getByText('Chromium Test/1.0')).toBeVisible();
  await expect(page.getByText('Current', { exact: true })).toBeVisible();

  await page.getByRole('button', { name: `Revoke browser session ${oldSessionId}` }).click();

  await expect(page.getByText('Browser session revoked')).toBeVisible();
  await expect(page.getByText('Old Browser/1.0')).toBeHidden();
  await expect(page.getByText('Chromium Test/1.0')).toBeVisible();
  expect(sessionListRequests).toBe(1);
  expect(sessionRevokeRequests).toBe(1);
});

test('account page regenerates recovery codes after inline reauthentication', async ({ page }) => {
  let credentialListRequests = 0;
  let regenerateRequests = 0;
  let reauthenticationRequests = 0;

  await page.route(`${apiOrigin}/**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (request.method() === 'OPTIONS') {
      await route.fulfill({
        headers: corsHeaders,
        status: 204
      });
      return;
    }

    if (url.pathname === '/api/v1/session/csrf') {
      await fulfillJson(route, { csrf_token: csrfToken });
      return;
    }

    if (url.pathname === '/api/v1/session/me') {
      await fulfillJson(route, {
        id: 'user-1',
        organization_id: 'org-1',
        email: 'admin@example.com',
        email_verified: true,
        display_name: 'Admin',
        status: 'active',
        created_at: '2026-06-07T00:00:00Z',
        updated_at: '2026-06-07T00:00:00Z'
      });
      return;
    }

    if (url.pathname === '/api/v1/session/mfa/credentials') {
      credentialListRequests += 1;
      await fulfillJson(route, {
        credentials: [
          {
            id: 'credential-1',
            kind: 'totp',
            label: 'Authenticator app',
            status: 'active',
            created_at: '2026-06-07T00:00:00Z',
            last_used_at: null
          }
        ],
        recovery_code_count: credentialListRequests === 1 ? 2 : 10
      });
      return;
    }

    if (url.pathname === '/api/v1/session/browser-sessions') {
      await fulfillJson(route, browserSessionList());
      return;
    }

    if (url.pathname === '/api/v1/session/consent-grants') {
      expect(request.method()).toBe('GET');
      expect(url.searchParams.get('status')).toBe('all');
      expect(url.searchParams.get('limit')).toBe('25');
      await fulfillJson(route, { items: [], next_cursor: null });
      return;
    }

    if (url.pathname === '/api/v1/session/mfa/recovery-codes/regenerate') {
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      regenerateRequests += 1;
      if (regenerateRequests === 1) {
        await fulfillJson(route, { error: 'fresh MFA verification required' }, 403);
      } else {
        await fulfillJson(route, {
          status: 'regenerated',
          recovery_codes: ['fresh-code-1', 'fresh-code-2']
        });
      }
      return;
    }

    if (url.pathname === '/api/v1/session/reauthenticate') {
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      const payload = request.postDataJSON() as { password?: string; mfa_code?: string };
      expect(payload.password).toBe('correct-password');
      expect(payload.mfa_code).toBe('123456');
      reauthenticationRequests += 1;
      await fulfillJson(
        route,
        {
          status: 'reauthenticated',
          acr: 'urn:cairn:acr:password+totp',
          amr: ['pwd', 'otp']
        },
        200,
        {
          'Set-Cookie': 'cairn_session=new-session; Path=/; HttpOnly; SameSite=Lax'
        }
      );
      return;
    }

    await route.fulfill({
      headers: corsHeaders,
      status: 404
    });
  });

  await page.goto('/app');
  await expect(page.getByRole('button', { name: 'Regenerate codes' })).toBeVisible();
  await page.getByRole('button', { name: 'Regenerate codes' }).click();

  await expect(page.getByText('Reauthenticate to regenerate recovery codes')).toBeVisible();
  await expect(page.getByText('Regenerate recovery codes', { exact: true })).toBeVisible();

  await page.getByLabel('Password', { exact: true }).fill('correct-password');
  await page.getByLabel('Authenticator or recovery code').fill('123456');
  await page.getByRole('button', { name: 'Confirm' }).click();

  await expect(page.getByText('Recovery codes regenerated. Store these recovery codes now.')).toBeVisible();
  await expect(page.locator('input[readonly]').nth(0)).toHaveValue('fresh-code-1');
  await expect(page.locator('input[readonly]').nth(1)).toHaveValue('fresh-code-2');
  await expect(page.getByText('10 recovery codes active')).toBeVisible();
  expect(regenerateRequests).toBe(2);
  expect(reauthenticationRequests).toBe(1);
});

test('account page reauthenticates before revoking an MFA credential', async ({ page }) => {
  let credentialRevoked = false;
  let credentialListRequests = 0;
  let revokeRequests = 0;
  let reauthenticationRequests = 0;

  await page.route(`${apiOrigin}/**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (request.method() === 'OPTIONS') {
      await route.fulfill({
        headers: corsHeaders,
        status: 204
      });
      return;
    }

    if (url.pathname === '/api/v1/session/csrf') {
      await fulfillJson(route, { csrf_token: csrfToken });
      return;
    }

    if (url.pathname === '/api/v1/session/me') {
      await fulfillJson(route, {
        id: 'user-1',
        organization_id: 'org-1',
        email: 'admin@example.com',
        email_verified: true,
        display_name: 'Admin',
        status: 'active',
        created_at: '2026-06-07T00:00:00Z',
        updated_at: '2026-06-07T00:00:00Z'
      });
      return;
    }

    if (url.pathname === '/api/v1/session/mfa/credentials') {
      credentialListRequests += 1;
      await fulfillJson(route, {
        credentials: credentialRevoked
          ? []
          : [
              {
                id: 'credential-1',
                kind: 'totp',
                label: 'Authenticator app',
                status: 'active',
                created_at: '2026-06-07T00:00:00Z',
                last_used_at: null
              }
            ],
        recovery_code_count: credentialRevoked ? 0 : 10
      });
      return;
    }

    if (url.pathname === '/api/v1/session/browser-sessions') {
      await fulfillJson(route, browserSessionList());
      return;
    }

    if (url.pathname === '/api/v1/session/consent-grants') {
      expect(request.method()).toBe('GET');
      expect(url.searchParams.get('status')).toBe('all');
      expect(url.searchParams.get('limit')).toBe('25');
      await fulfillJson(route, { items: [], next_cursor: null });
      return;
    }

    if (url.pathname === '/api/v1/session/mfa/credentials/credential-1') {
      expect(request.method()).toBe('DELETE');
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      revokeRequests += 1;

      if (revokeRequests === 1) {
        await fulfillJson(route, { error: 'fresh MFA verification required' }, 403);
        return;
      }

      credentialRevoked = true;
      await fulfillJson(route, {
        id: 'credential-1',
        kind: 'totp',
        label: 'Authenticator app',
        status: 'revoked',
        created_at: '2026-06-07T00:00:00Z',
        last_used_at: null
      });
      return;
    }

    if (url.pathname === '/api/v1/session/reauthenticate') {
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      const payload = request.postDataJSON() as { password?: string; mfa_code?: string };
      expect(payload.password).toBe('correct-password');
      expect(payload.mfa_code).toBe('123456');
      reauthenticationRequests += 1;
      await fulfillJson(
        route,
        {
          status: 'reauthenticated',
          acr: 'urn:cairn:acr:password+totp',
          amr: ['pwd', 'otp']
        },
        200,
        {
          'Set-Cookie': 'cairn_session=revocation-session; Path=/; HttpOnly; SameSite=Lax'
        }
      );
      return;
    }

    await route.fulfill({
      headers: corsHeaders,
      status: 404
    });
  });

  await page.goto('/app');
  await expect(page.getByRole('cell', { name: 'Authenticator app' }).first()).toBeVisible();
  await expect(page.getByText('10 recovery codes active')).toBeVisible();

  await page.getByTitle('Revoke MFA credential').click();
  await expect(page.getByText('Reauthenticate to revoke Authenticator app')).toBeVisible();
  await expect(page.getByText('Revoke Authenticator app', { exact: true })).toBeVisible();

  await page.getByLabel('Password', { exact: true }).fill('correct-password');
  await page.getByLabel('Authenticator or recovery code').fill('123456');
  await page.getByRole('button', { name: 'Confirm' }).click();

  await expect(page.getByText('Authenticator app revoked')).toBeVisible();
  await expect(page.getByText('No MFA devices enrolled')).toBeVisible();
  await expect(page.getByText('0 recovery codes active')).toBeVisible();
  await expect(page.getByText('Revoke Authenticator app', { exact: true })).toBeHidden();
  expect(credentialListRequests).toBe(2);
  expect(revokeRequests).toBe(2);
  expect(reauthenticationRequests).toBe(1);
});

test('account page revokes application consent through the session API', async ({ page }) => {
  const grantId = '11111111-1111-4111-8111-111111111201';
  const organizationId = '11111111-1111-4111-8111-111111111001';
  const userId = '11111111-1111-4111-8111-111111111101';
  const clientId = '11111111-1111-4111-8111-111111111301';
  let consentRevoked = false;
  let consentListRequests = 0;
  let consentRevokeRequests = 0;

  await page.route(`${apiOrigin}/**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (request.method() === 'OPTIONS') {
      await route.fulfill({
        headers: corsHeaders,
        status: 204
      });
      return;
    }

    if (url.pathname === '/api/v1/session/csrf') {
      await fulfillJson(route, { csrf_token: csrfToken });
      return;
    }

    if (url.pathname === '/api/v1/session/me') {
      await fulfillJson(route, {
        id: userId,
        organization_id: organizationId,
        email: 'admin@example.com',
        email_verified: true,
        display_name: 'Admin',
        status: 'active',
        created_at: '2026-06-07T00:00:00Z',
        updated_at: '2026-06-07T00:00:00Z'
      });
      return;
    }

    if (url.pathname === '/api/v1/session/mfa/credentials') {
      await fulfillJson(route, {
        credentials: [],
        recovery_code_count: 0
      });
      return;
    }

    if (url.pathname === '/api/v1/session/browser-sessions') {
      await fulfillJson(route, browserSessionList());
      return;
    }

    if (url.pathname === '/api/v1/session/consent-grants' && request.method() === 'GET') {
      consentListRequests += 1;
      expect(url.searchParams.get('status')).toBe('all');
      expect(url.searchParams.get('limit')).toBe('25');
      await fulfillJson(route, {
        items: [
          {
            id: grantId,
            organization_id: organizationId,
            user_id: userId,
            client_id: clientId,
            client_public_id: 'example-web',
            client_name: 'Example App',
            scopes: ['openid', 'profile', 'email'],
            created_at: '2026-06-07T00:00:00Z',
            revoked_at: consentRevoked ? '2026-06-07T00:01:00Z' : null
          }
        ],
        next_cursor: null
      });
      return;
    }

    if (url.pathname === `/api/v1/session/consent-grants/${grantId}`) {
      expect(request.method()).toBe('DELETE');
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      consentRevokeRequests += 1;
      consentRevoked = true;
      await fulfillJson(route, {
        grant: {
          id: grantId,
          organization_id: organizationId,
          user_id: userId,
          user_email: 'admin@example.com',
          user_display_name: 'Admin',
          client_id: clientId,
          scopes: ['openid', 'profile', 'email'],
          created_at: '2026-06-07T00:00:00Z',
          revoked_at: '2026-06-07T00:01:00Z'
        },
        consent_grants_revoked: 1,
        authorization_codes_invalidated: 1,
        access_tokens_revoked: 1,
        refresh_tokens_revoked: 1
      });
      return;
    }

    await route.fulfill({
      headers: corsHeaders,
      status: 404
    });
  });

  await page.goto('/app');
  const applicationRow = page.getByRole('row').filter({ hasText: 'Example App' });
  await expect(applicationRow.getByRole('cell', { name: 'Active' })).toBeVisible();
  await expect(applicationRow.getByText('openid')).toBeVisible();

  page.once('dialog', async (dialog) => {
    expect(dialog.message()).toBe('Revoke consent for Example App?');
    await dialog.accept();
  });
  await applicationRow.getByTitle('Revoke consent for Example App').click();

  await expect(page.getByText('Consent revoked for Example App')).toBeVisible();
  await expect(applicationRow.getByRole('cell', { name: 'Revoked' })).toBeVisible();
  await expect(applicationRow.getByTitle('Revoke consent for Example App')).toBeHidden();
  expect(consentListRequests).toBe(2);
  expect(consentRevokeRequests).toBe(1);
});

test('passkey enrollment and login use a browser virtual authenticator', async ({
  browserName,
  page
}) => {
  test.skip(browserName !== 'chromium', 'Chromium CDP WebAuthn virtual authenticators are required.');

  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');
  const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      automaticPresenceSimulation: true,
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      protocol: 'ctap2',
      transport: 'internal'
    }
  });

  let passkeyEnabled = false;
  let registeredCredentialId = '';
  let passkeyStartRequests = 0;
  let passkeyFinishRequests = 0;
  let loginRequests = 0;

  await page.route(`${apiOrigin}/**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (request.method() === 'OPTIONS') {
      await route.fulfill({
        headers: corsHeaders,
        status: 204
      });
      return;
    }

    if (url.pathname === '/api/v1/session/csrf') {
      await fulfillJson(route, { csrf_token: csrfToken });
      return;
    }

    if (url.pathname === '/api/v1/session/me') {
      await fulfillJson(route, {
        id: 'user-1',
        organization_id: 'org-1',
        email: 'admin@example.com',
        email_verified: true,
        display_name: 'Admin',
        status: 'active',
        created_at: '2026-06-07T00:00:00Z',
        updated_at: '2026-06-07T00:00:00Z'
      });
      return;
    }

    if (url.pathname === '/api/v1/session/mfa/credentials') {
      await fulfillJson(route, {
        credentials: passkeyEnabled
          ? [
              {
                id: 'passkey-1',
                kind: 'web_authn',
                label: 'Passkey',
                status: 'active',
                created_at: '2026-06-07T00:00:00Z',
                last_used_at: null
              }
            ]
          : [],
        recovery_code_count: 0
      });
      return;
    }

    if (url.pathname === '/api/v1/session/browser-sessions') {
      await fulfillJson(route, browserSessionList());
      return;
    }

    if (url.pathname === '/api/v1/session/consent-grants') {
      expect(request.method()).toBe('GET');
      expect(url.searchParams.get('status')).toBe('all');
      expect(url.searchParams.get('limit')).toBe('25');
      await fulfillJson(route, { items: [], next_cursor: null });
      return;
    }

    if (url.pathname === '/api/v1/session/mfa/webauthn/start') {
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      const payload = request.postDataJSON() as { label?: string };
      expect(payload.label).toBe('Passkey');
      passkeyStartRequests += 1;
      await fulfillJson(route, {
        challenge_id: 'registration-challenge-1',
        label: 'Passkey',
        options: passkeyCreationOptions()
      });
      return;
    }

    if (url.pathname === '/api/v1/session/mfa/webauthn/finish') {
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      const payload = request.postDataJSON() as {
        challenge_id?: string;
        credential?: {
          rawId?: string;
          response?: {
            attestationObject?: string;
            clientDataJSON?: string;
          };
          type?: string;
        };
        label?: string;
      };
      expect(payload.challenge_id).toBe('registration-challenge-1');
      expect(payload.label).toBe('Passkey');
      expect(payload.credential?.type).toBe('public-key');
      expect(payload.credential?.rawId).toEqual(expect.any(String));
      expect(payload.credential?.response?.attestationObject).toEqual(expect.any(String));
      expect(payload.credential?.response?.clientDataJSON).toEqual(expect.any(String));
      registeredCredentialId = payload.credential?.rawId ?? '';
      passkeyEnabled = true;
      passkeyFinishRequests += 1;
      await fulfillJson(route, {
        status: 'enabled',
        credential_id: 'passkey-1',
        label: 'Passkey'
      });
      return;
    }

    if (url.pathname === '/api/v1/session/login') {
      expect(request.headers()['x-cairn-csrf']).toBe(csrfToken);
      const payload = request.postDataJSON() as {
        email?: string;
        password?: string;
        webauthn_challenge_id?: string;
        webauthn_credential?: {
          rawId?: string;
          response?: {
            authenticatorData?: string;
            clientDataJSON?: string;
            signature?: string;
          };
          type?: string;
        };
      };
      expect(payload.email).toBe('admin@example.com');
      expect(payload.password).toBe('correct-password');
      loginRequests += 1;

      if (loginRequests === 1) {
        expect(payload.webauthn_credential).toBeUndefined();
        await fulfillJson(route, {
          status: 'mfa_required',
          methods: ['web_authn'],
          webauthn: {
            challenge_id: 'authentication-challenge-1',
            options: passkeyRequestOptions(registeredCredentialId)
          }
        });
        return;
      }

      expect(payload.webauthn_challenge_id).toBe('authentication-challenge-1');
      expect(payload.webauthn_credential?.type).toBe('public-key');
      expect(payload.webauthn_credential?.rawId).toBe(registeredCredentialId);
      expect(payload.webauthn_credential?.response?.authenticatorData).toEqual(expect.any(String));
      expect(payload.webauthn_credential?.response?.clientDataJSON).toEqual(expect.any(String));
      expect(payload.webauthn_credential?.response?.signature).toEqual(expect.any(String));
      await fulfillJson(
        route,
        {
          status: 'authenticated'
        },
        200,
        {
          'Set-Cookie': 'cairn_session=passkey-session; Path=/; HttpOnly; SameSite=Lax'
        }
      );
      return;
    }

    await route.fulfill({
      headers: corsHeaders,
      status: 404
    });
  });

  try {
    await page.goto('/app');
    await expect(page.getByRole('button', { name: 'Add passkey' })).toBeVisible();
    await expect(page.getByText('No MFA devices enrolled')).toBeVisible();

    await page.getByRole('button', { name: 'Add passkey' }).click();
    await expect(page.getByText('Passkey enabled')).toBeVisible();
    await expect(page.getByRole('cell', { name: 'Passkey' }).first()).toBeVisible();

    const { credentials } = await client.send('WebAuthn.getCredentials', { authenticatorId });
    expect(credentials).toHaveLength(1);
    expect(credentials[0]?.rpId).toBe('localhost');
    expect(registeredCredentialId).not.toBe('');

    await page.goto('/login?return_to=/app');
    await page.getByLabel('Email').fill('admin@example.com');
    await page.getByLabel('Password').fill('correct-password');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByText('Use your passkey or enter an authenticator code')).toBeVisible();
    await page.getByRole('button', { name: 'Use passkey' }).click();
    await expect.poll(() => loginRequests, { timeout: 10000 }).toBe(2);
    await expect(page).toHaveURL('http://localhost:3000/app');

    expect(passkeyStartRequests).toBe(1);
    expect(passkeyFinishRequests).toBe(1);
  } finally {
    await client.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId }).catch(() => {});
    await client.send('WebAuthn.disable').catch(() => {});
  }
});

async function fulfillJson(
  route: Route,
  body: unknown,
  status = 200,
  headers: Record<string, string> = {}
) {
  await route.fulfill({
    body: JSON.stringify(body),
    headers: {
      ...corsHeaders,
      ...headers,
      'Content-Type': 'application/json'
    },
    status
  });
}

function passkeyCreationOptions() {
  return {
    publicKey: {
      attestation: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required'
      },
      challenge: 'cmVnaXN0cmF0aW9uLWNoYWxsZW5nZQ',
      pubKeyCredParams: [
        {
          alg: -7,
          type: 'public-key'
        },
        {
          alg: -257,
          type: 'public-key'
        }
      ],
      rp: {
        id: 'localhost',
        name: 'Cairn Identity'
      },
      timeout: 60000,
      user: {
        displayName: 'Admin',
        id: 'dXNlci0x',
        name: 'admin@example.com'
      }
    }
  };
}

function browserSessionList(extraSessions: Array<Record<string, unknown>> = []) {
  return {
    sessions: [
      {
        id: '11111111-1111-4111-8111-111111111901',
        current: true,
        acr: 'urn:cairn:acr:password+totp',
        amr: ['pwd', 'otp'],
        created_at: '2026-06-07T00:00:00Z',
        expires_at: '2026-06-07T12:00:00Z',
        created_ip_address: '203.0.113.10',
        created_user_agent: 'Chromium Test/1.0'
      },
      ...extraSessions
    ]
  };
}

function passkeyRequestOptions(credentialId: string) {
  return {
    publicKey: {
      allowCredentials: [
        {
          id: credentialId,
          transports: ['internal'],
          type: 'public-key'
        }
      ],
      challenge: 'YXV0aGVudGljYXRpb24tY2hhbGxlbmdl',
      rpId: 'localhost',
      timeout: 60000,
      userVerification: 'required'
    }
  };
}
