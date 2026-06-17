import * as z from 'zod';
import { apiOrigin } from './config';

const CSRF_TOKEN_MIN_LENGTH = 32;
const CSRF_TOKEN_MAX_LENGTH = 128;
const CSRF_TOKEN_PATTERN = /^[A-Za-z0-9_-]+$/;

const csrfSchema = z.object({
  csrf_token: z
    .string()
    .min(CSRF_TOKEN_MIN_LENGTH)
    .max(CSRF_TOKEN_MAX_LENGTH)
    .regex(CSRF_TOKEN_PATTERN)
});

export const userStatusSchema = z.enum(['active', 'suspended', 'locked']);

export const userSchema = z.object({
  id: z.string(),
  organization_id: z.string(),
  email: z.string(),
  email_verified: z.boolean(),
  display_name: z.string(),
  status: userStatusSchema,
  created_at: z.string(),
  updated_at: z.string()
});

export const deliverySchema = z.object({
  status: z.string(),
  email_outbox_id: z.string().optional(),
  recipient_email: z.string().optional(),
  expires_at: z.string().optional(),
  preview_url: z.string().optional()
});

export const groupSchema = z.object({
  id: z.string(),
  organization_id: z.string(),
  slug: z.string(),
  display_name: z.string(),
  created_at: z.string()
});

export const membershipRoleSchema = z.enum(['member', 'owner']);
export const oidcClientStatusSchema = z.enum(['active', 'disabled']);
export const oidcGrantTypeSchema = z.enum([
  'authorization_code',
  'refresh_token',
  'client_credentials'
]);

export const membershipSchema = z.object({
  organization_id: z.string(),
  user_id: z.string(),
  group_id: z.string(),
  role: membershipRoleSchema,
  created_at: z.string()
});

export const clientSchema = z.object({
  id: z.string(),
  organization_id: z.string(),
  client_id: z.string(),
  consent_policy_template_id: z.string().uuid().nullable(),
  name: z.string(),
  redirect_uris: z.array(z.object({ value: z.string() })),
  post_logout_redirect_uris: z.array(z.object({ value: z.string() })),
  allowed_scopes: z.array(z.string()),
  grant_types: z.array(oidcGrantTypeSchema),
  public_client: z.boolean(),
  require_pkce: z.boolean(),
  status: oidcClientStatusSchema,
  has_client_secret: z.boolean(),
  created_at: z.string()
});

export const clientSecretRotationSchema = z.object({
  client: clientSchema,
  client_secret: z.string().min(1)
});

export const clientStatusUpdateSchema = z.object({
  client: clientSchema,
  authorization_codes_invalidated: z.number().int().nonnegative(),
  access_tokens_revoked: z.number().int().nonnegative(),
  refresh_tokens_revoked: z.number().int().nonnegative()
});

export const clientDetailsUpdateSchema = z.object({
  client: clientSchema,
  authorization_codes_invalidated: z.number().int().nonnegative(),
  access_tokens_revoked: z.number().int().nonnegative(),
  refresh_tokens_revoked: z.number().int().nonnegative()
});

export const consentGrantModeSchema = z.enum(['required_once', 'always_required']);

export const consentPolicyTemplateSchema = z.object({
  id: z.string().uuid(),
  organization_id: z.string().uuid(),
  slug: z.string(),
  name: z.string(),
  grant_mode: consentGrantModeSchema,
  created_at: z.string()
});

export const auditEventSchema = z.object({
  id: z.string(),
  action: z.string(),
  target: z.string(),
  actor_kind: z.string(),
  actor_id: z.string().nullable().optional(),
  ip_address: z.string().nullable().optional(),
  user_agent: z.string().nullable().optional(),
  created_at: z.string(),
  metadata: z.unknown()
});

export const consentGrantSchema = z.object({
  id: z.string().uuid(),
  organization_id: z.string().uuid(),
  user_id: z.string().uuid(),
  user_email: z.string(),
  user_display_name: z.string(),
  client_id: z.string().uuid(),
  scopes: z.array(z.string()),
  created_at: z.string(),
  revoked_at: z.string().nullable()
});

export const userConsentGrantSchema = consentGrantSchema
  .omit({
    user_email: true,
    user_display_name: true
  })
  .extend({
    client_public_id: z.string(),
    client_name: z.string()
  });

export const browserSessionSchema = z.object({
  id: z.string(),
  current: z.boolean(),
  acr: z.string(),
  amr: z.array(z.string()),
  created_at: z.string(),
  expires_at: z.string(),
  created_ip_address: z.string().nullable().optional(),
  created_user_agent: z.string().nullable().optional()
});

export const browserSessionListSchema = z.object({
  sessions: z.array(browserSessionSchema)
});

export const browserSessionRevocationSchema = z.object({
  status: z.literal('revoked'),
  session_id: z.string()
});

export type User = z.infer<typeof userSchema>;
export type UserStatus = z.infer<typeof userStatusSchema>;
export type Delivery = z.infer<typeof deliverySchema>;
export type Group = z.infer<typeof groupSchema>;
export type Membership = z.infer<typeof membershipSchema>;
export type MembershipRole = z.infer<typeof membershipRoleSchema>;
export type OidcClientStatus = z.infer<typeof oidcClientStatusSchema>;
export type OidcGrantType = z.infer<typeof oidcGrantTypeSchema>;
export type OidcClient = z.infer<typeof clientSchema>;
export type ClientSecretRotation = z.infer<typeof clientSecretRotationSchema>;
export type ClientStatusUpdate = z.infer<typeof clientStatusUpdateSchema>;
export type ClientDetailsUpdate = z.infer<typeof clientDetailsUpdateSchema>;
export type ConsentGrantMode = z.infer<typeof consentGrantModeSchema>;
export type ConsentPolicyTemplate = z.infer<typeof consentPolicyTemplateSchema>;
export type AuditEvent = z.infer<typeof auditEventSchema>;
export type ConsentGrant = z.infer<typeof consentGrantSchema>;
export type UserConsentGrant = z.infer<typeof userConsentGrantSchema>;
export type BrowserSession = z.infer<typeof browserSessionSchema>;
type ListPagePayload<T> = {
  items: T[];
  next_cursor: string | null;
};

let csrfToken: string | null = null;
let csrfTokenPromise: Promise<string> | null = null;

export async function api<T>(path: string, schema: z.ZodType<T>, init: RequestInit = {}): Promise<T> {
  const method = init.method?.toUpperCase() ?? 'GET';
  const headers = new Headers(init.headers);

  if (typeof init.body === 'string' && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  if (requiresCsrf(method)) {
    headers.set('X-CAIRN-CSRF', await getCsrfToken());
  }

  const response = await fetch(`${apiOrigin}${path}`, {
    credentials: 'include',
    ...init,
    headers
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = typeof payload.error === 'string' ? payload.error : 'Request failed';
    throw new Error(message);
  }

  return schema.parse(payload);
}

export async function apiList<T>(
  path: string,
  itemSchema: z.ZodType<T>,
  pageLimit = 100
): Promise<T[]> {
  const items: T[] = [];
  let cursor: string | null = null;

  for (let pageCount = 0; pageCount < 1000; pageCount += 1) {
    const page: ListPagePayload<T> = await api(
      pathWithListParams(path, pageLimit, cursor),
      listPageSchema(itemSchema)
    );
    items.push(...page.items);
    cursor = page.next_cursor;
    if (!cursor) {
      return items;
    }
  }

  throw new Error('Too many API pages');
}

export const unknownJson = z.unknown();

function listPageSchema<T>(itemSchema: z.ZodType<T>): z.ZodType<ListPagePayload<T>> {
  return z.object({
    items: z.array(itemSchema),
    next_cursor: z.string().nullable()
  });
}

function pathWithListParams(path: string, limit: number, cursor: string | null): string {
  const [pathname, query = ''] = path.split('?');
  const params = new URLSearchParams(query);
  params.set('limit', String(limit));
  if (cursor) {
    params.set('cursor', cursor);
  }
  const encoded = params.toString();
  return encoded ? `${pathname}?${encoded}` : pathname;
}

async function getCsrfToken(): Promise<string> {
  if (csrfToken) {
    return csrfToken;
  }

  csrfTokenPromise ??= fetch(`${apiOrigin}/api/v1/session/csrf`, {
    credentials: 'include'
  })
    .then(async (response) => {
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error('Could not issue CSRF token');
      }

      return csrfSchema.parse(payload).csrf_token;
    })
    .finally(() => {
      csrfTokenPromise = null;
    });

  csrfToken = await csrfTokenPromise;
  return csrfToken;
}

function requiresCsrf(method: string): boolean {
  return method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';
}

export function resetCsrfTokenForTests(): void {
  csrfToken = null;
  csrfTokenPromise = null;
}
