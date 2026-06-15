<script lang="ts">
  import { onMount } from 'svelte';
  import { RefreshCw } from '@lucide/svelte';
  import Shell from '$lib/components/Shell.svelte';
  import {
    api,
    apiList,
    clientSecretRotationSchema,
    clientStatusUpdateSchema,
    clientSchema,
    consentGrantSchema,
    consentPolicyTemplateSchema,
    type ConsentGrant,
    type ConsentGrantMode,
    type OidcClient,
    type OidcClientStatus,
    type OidcGrantType,
    type ConsentPolicyTemplate,
    unknownJson
  } from '$lib/api';
  import ApplicationFilters from './components/ApplicationFilters.svelte';
  import ApplicationsTable from './components/ApplicationsTable.svelte';
  import ClientCreatePanel from './components/ClientCreatePanel.svelte';
  import ConsentPoliciesPanel from './components/ConsentPoliciesPanel.svelte';
  import type {
    ClientStatusFilter,
    ClientTypeFilter,
    GrantTypeFilter
  } from './components/types';

  let clients: OidcClient[] = [];
  let consentPolicyTemplates: ConsentPolicyTemplate[] = [];
  let consentGrantsByClient = new Map<string, ConsentGrant[]>();
  let loadingConsentClientId: string | null = null;
  let revokingConsentGrantId: string | null = null;
  let rotatingSecretClientId: string | null = null;
  let policySlug = '';
  let policyName = '';
  let policyGrantMode: ConsentGrantMode = 'required_once';
  let selectedConsentPolicyTemplateId = '';
  let clientId = '';
  let name = '';
  let redirectUris = 'https://app.example.com/callback';
  let postLogoutRedirectUris = 'https://app.example.com/signed-out';
  let scopes = 'openid profile email groups';
  let publicClient = true;
  let search = '';
  let clientType: ClientTypeFilter = 'all';
  let clientStatus: ClientStatusFilter = 'all';
  let grantType: GrantTypeFilter = 'all';
  let scope = '';
  let createdSecret = '';
  let rotatedSecret = '';
  let updatingStatusClientId: string | null = null;
  let message = '';

  async function load() {
    const [nextClients, nextTemplates] = await Promise.all([
      apiList(clientsPath(), clientSchema),
      apiList('/api/v1/oidc/consent-policy-templates', consentPolicyTemplateSchema)
    ]);
    clients = nextClients;
    consentPolicyTemplates = nextTemplates;
    consentGrantsByClient = new Map();
    if (
      selectedConsentPolicyTemplateId &&
      !consentPolicyTemplates.some((template) => template.id === selectedConsentPolicyTemplateId)
    ) {
      selectedConsentPolicyTemplateId = '';
    }
  }

  function clientsPath(): string {
    const params = new URLSearchParams();
    const trimmedSearch = search.trim();
    const trimmedScope = scope.trim();
    if (trimmedSearch) {
      params.set('q', trimmedSearch);
    }
    if (clientType !== 'all') {
      params.set('client_type', clientType);
    }
    if (clientStatus !== 'all') {
      params.set('status', clientStatus);
    }
    if (grantType !== 'all') {
      params.set('grant_type', grantType);
    }
    if (trimmedScope) {
      params.set('scope', trimmedScope);
    }
    const query = params.toString();
    return query ? `/api/v1/oidc/clients?${query}` : '/api/v1/oidc/clients';
  }

  async function create() {
    message = '';
    createdSecret = '';
    rotatedSecret = '';
    try {
      const response = (await api('/api/v1/oidc/clients', unknownJson, {
        method: 'POST',
        body: JSON.stringify({
          client_id: clientId,
          name,
          redirect_uris: redirectUris.split(/\s+/).filter(Boolean),
          post_logout_redirect_uris: postLogoutRedirectUris.split(/\s+/).filter(Boolean),
          allowed_scopes: scopes.split(/\s+/).filter(Boolean),
          public_client: publicClient,
          consent_policy_template_id: selectedConsentPolicyTemplateId || undefined
        })
      })) as { client_secret?: string };
      createdSecret = response.client_secret ?? '';
      clientId = '';
      name = '';
      selectedConsentPolicyTemplateId = '';
      await load();
    } catch (error) {
      message = error instanceof Error ? error.message : 'Create failed';
    }
  }

  async function rotateSecret(client: OidcClient) {
    if (client.public_client || !confirm(`Rotate secret for ${client.client_id}?`)) {
      return;
    }

    message = '';
    createdSecret = '';
    rotatedSecret = '';
    rotatingSecretClientId = client.id;
    try {
      const response = await api(
        `/api/v1/oidc/clients/${client.id}/secret/rotate`,
        clientSecretRotationSchema,
        { method: 'POST' }
      );
      rotatedSecret = response.client_secret;
      clients = clients.map((candidate) =>
        candidate.id === response.client.id ? response.client : candidate
      );
      message = `Client secret rotated for ${client.client_id}`;
    } catch (error) {
      message = error instanceof Error ? error.message : 'Secret rotation failed';
    } finally {
      rotatingSecretClientId = null;
    }
  }

  async function updateClientStatus(client: OidcClient, status: OidcClientStatus) {
    if (status === 'disabled' && !confirm(`Disable client ${client.client_id}?`)) {
      return;
    }

    message = '';
    createdSecret = '';
    rotatedSecret = '';
    updatingStatusClientId = client.id;
    try {
      const response = await api(
        `/api/v1/oidc/clients/${client.id}/status`,
        clientStatusUpdateSchema,
        {
          method: 'PUT',
          body: JSON.stringify({ status })
        }
      );
      clients = clients.map((candidate) =>
        candidate.id === response.client.id ? response.client : candidate
      );
      const revoked =
        response.authorization_codes_invalidated +
        response.access_tokens_revoked +
        response.refresh_tokens_revoked;
      message =
        status === 'disabled'
          ? `Client disabled for ${client.client_id}; ${revoked} runtime credentials invalidated`
          : `Client reactivated for ${client.client_id}`;
    } catch (error) {
      message = error instanceof Error ? error.message : 'Client status update failed';
    } finally {
      updatingStatusClientId = null;
    }
  }

  async function createPolicyTemplate() {
    message = '';
    try {
      await api('/api/v1/oidc/consent-policy-templates', consentPolicyTemplateSchema, {
        method: 'POST',
        body: JSON.stringify({
          slug: policySlug,
          name: policyName,
          grant_mode: policyGrantMode
        })
      });
      policySlug = '';
      policyName = '';
      policyGrantMode = 'required_once';
      await load();
    } catch (error) {
      message = error instanceof Error ? error.message : 'Consent policy creation failed';
    }
  }

  async function reviewConsent(client: OidcClient) {
    message = '';
    loadingConsentClientId = client.id;
    try {
      const grants = await apiList(
        `/api/v1/oidc/clients/${client.id}/consent-grants`,
        consentGrantSchema,
        25
      );
      const next = new Map(consentGrantsByClient);
      next.set(client.id, grants);
      consentGrantsByClient = next;
    } catch (error) {
      message = error instanceof Error ? error.message : 'Consent review failed';
    } finally {
      loadingConsentClientId = null;
    }
  }

  async function revokeConsent(client: OidcClient, grant: ConsentGrant) {
    if (!confirm(`Revoke consent for ${grant.user_email}?`)) {
      return;
    }

    message = '';
    revokingConsentGrantId = grant.id;
    try {
      await api(
        `/api/v1/oidc/clients/${client.id}/consent-grants/${grant.id}`,
        unknownJson,
        { method: 'DELETE' }
      );
      await reviewConsent(client);
    } catch (error) {
      message = error instanceof Error ? error.message : 'Consent revocation failed';
    } finally {
      revokingConsentGrantId = null;
    }
  }

  onMount(() => void load().catch((error) => (message = error.message)));
</script>

<Shell>
  <div class="toolbar">
    <div>
      <h1>Applications</h1>
      <p class="status-line">Register OIDC clients with exact redirect URIs and PKCE enabled.</p>
    </div>
    <button class="icon-button" title="Refresh" onclick={load}><RefreshCw size={17} /></button>
  </div>

  <ApplicationFilters
    bind:search
    bind:clientType
    bind:clientStatus
    bind:grantType
    bind:scope
    onApply={load}
  />

  <ConsentPoliciesPanel
    templates={consentPolicyTemplates}
    bind:policySlug
    bind:policyName
    bind:policyGrantMode
    onCreate={createPolicyTemplate}
  />

  <ClientCreatePanel
    {consentPolicyTemplates}
    bind:clientId
    bind:name
    bind:redirectUris
    bind:postLogoutRedirectUris
    bind:scopes
    bind:publicClient
    bind:selectedConsentPolicyTemplateId
    {createdSecret}
    {rotatedSecret}
    {message}
    onCreate={create}
  />

  <ApplicationsTable
    {clients}
    {consentPolicyTemplates}
    {consentGrantsByClient}
    {loadingConsentClientId}
    {revokingConsentGrantId}
    {rotatingSecretClientId}
    {updatingStatusClientId}
    onRotateSecret={rotateSecret}
    onUpdateClientStatus={updateClientStatus}
    onReviewConsent={reviewConsent}
    onRevokeConsent={revokeConsent}
  />
</Shell>
