import type { OidcClientStatus, OidcGrantType } from '$lib/api';

export type ClientTypeFilter = 'all' | 'public' | 'confidential';
export type ClientStatusFilter = 'all' | OidcClientStatus;
export type GrantTypeFilter = OidcGrantType | 'all';
