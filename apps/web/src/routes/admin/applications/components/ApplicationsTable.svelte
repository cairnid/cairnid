<script lang="ts">
  import { Ban, CircleCheck, Eye, KeyRound, Pencil, Trash2 } from '@lucide/svelte';
  import type {
    ConsentGrant,
    ConsentPolicyTemplate,
    OidcClient,
    OidcClientStatus
  } from '$lib/api';
  import { claimPreview, policyLabelForClient } from './helpers';

  export let clients: OidcClient[] = [];
  export let consentPolicyTemplates: ConsentPolicyTemplate[] = [];
  export let consentGrantsByClient = new Map<string, ConsentGrant[]>();
  export let loadingConsentClientId: string | null = null;
  export let revokingConsentGrantId: string | null = null;
  export let rotatingSecretClientId: string | null = null;
  export let updatingStatusClientId: string | null = null;
  export let editingClientId: string | null = null;
  export let onEditClient: (client: OidcClient) => void;
  export let onRotateSecret: (client: OidcClient) => void | Promise<void>;
  export let onUpdateClientStatus: (
    client: OidcClient,
    status: OidcClientStatus
  ) => void | Promise<void>;
  export let onReviewConsent: (client: OidcClient) => void | Promise<void>;
  export let onRevokeConsent: (
    client: OidcClient,
    grant: ConsentGrant
  ) => void | Promise<void>;
</script>

<section class="panel panel-spaced">
  <table class="data-table responsive-table">
    <thead>
      <tr>
        <th>Client ID</th>
        <th>Name</th>
        <th>Redirect URIs</th>
        <th>Post-Logout URIs</th>
        <th>Grants</th>
        <th>Scopes</th>
        <th>Claims</th>
        <th>Policy</th>
        <th>Type</th>
        <th>Status</th>
        <th>Secret</th>
        <th>Consent</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      {#each clients as client}
        <tr>
          <td data-label="Client ID">{client.client_id}</td>
          <td data-label="Name">{client.name}</td>
          <td data-label="Redirect URIs">{client.redirect_uris.map((uri) => uri.value).join(', ')}</td>
          <td data-label="Post-Logout URIs">
            {client.post_logout_redirect_uris.map((uri) => uri.value).join(', ')}
          </td>
          <td data-label="Grants">{client.grant_types.join(', ')}</td>
          <td data-label="Scopes">{client.allowed_scopes.join(', ')}</td>
          <td data-label="Claims">
            <div class="chip-list">
              {#each claimPreview(client.allowed_scopes) as claim}
                <span class="chip">{claim}</span>
              {:else}
                <span class="muted">No user claims</span>
              {/each}
            </div>
          </td>
          <td data-label="Policy">{policyLabelForClient(client, consentPolicyTemplates)}</td>
          <td data-label="Type">{client.public_client ? 'Public' : 'Confidential'}</td>
          <td data-label="Status">
            <div class="status-actions">
              <span
                class={[
                  'status-pill',
                  {
                    active: client.status === 'active',
                    disabled: client.status === 'disabled'
                  }
                ]}
              >
                {client.status === 'active' ? 'Active' : 'Disabled'}
              </span>
              {#if client.status === 'active'}
                <button
                  class="icon-button"
                  title={`Disable client ${client.client_id}`}
                  aria-label={`Disable client ${client.client_id}`}
                  disabled={updatingStatusClientId === client.id}
                  onclick={() => onUpdateClientStatus(client, 'disabled')}
                >
                  <Ban size={17} />
                </button>
              {:else}
                <button
                  class="icon-button"
                  title={`Reactivate client ${client.client_id}`}
                  aria-label={`Reactivate client ${client.client_id}`}
                  disabled={updatingStatusClientId === client.id}
                  onclick={() => onUpdateClientStatus(client, 'active')}
                >
                  <CircleCheck size={17} />
                </button>
              {/if}
            </div>
          </td>
          <td data-label="Secret">
            {#if client.public_client}
              <span class="muted">None</span>
            {:else}
              <div class="secret-actions">
                <button
                  class="icon-button"
                  title={`Rotate secret for ${client.client_id}`}
                  aria-label={`Rotate secret for ${client.client_id}`}
                  disabled={rotatingSecretClientId === client.id}
                  onclick={() => onRotateSecret(client)}
                >
                  <KeyRound size={17} />
                </button>
                <span class="muted">{client.has_client_secret ? 'Set' : 'Missing'}</span>
              </div>
            {/if}
          </td>
          <td data-label="Consent">
            <button
              class="icon-button"
              title={`Review consent for ${client.client_id}`}
              aria-label={`Review consent for ${client.client_id}`}
              disabled={loadingConsentClientId === client.id}
              onclick={() => onReviewConsent(client)}
            >
              <Eye size={17} />
            </button>
            {#if consentGrantsByClient.has(client.id)}
              <div class="consent-list">
                {#each consentGrantsByClient.get(client.id) ?? [] as grant}
                  <div class="consent-entry">
                    <div class="consent-entry-header">
                      <strong>{grant.user_email}</strong>
                      {#if grant.revoked_at}
                        <span class="status-pill revoked">Revoked</span>
                      {:else}
                        <span class="status-pill active">Active</span>
                      {/if}
                    </div>
                    <span>{grant.user_display_name}</span>
                    <span class="chip-list">
                      {#each grant.scopes as grantScope}
                        <span class="chip">{grantScope}</span>
                      {/each}
                    </span>
                    {#if grant.revoked_at}
                      <span class="muted">Revoked {grant.revoked_at}</span>
                    {:else}
                      <button
                        class="icon-button"
                        title={`Revoke consent for ${grant.user_email}`}
                        aria-label={`Revoke consent for ${grant.user_email}`}
                        disabled={revokingConsentGrantId === grant.id}
                        onclick={() => onRevokeConsent(client, grant)}
                      >
                        <Trash2 size={16} />
                      </button>
                    {/if}
                  </div>
                {:else}
                  <span class="muted">No consent grants</span>
                {/each}
              </div>
            {/if}
          </td>
          <td data-label="">
            <div class="table-actions">
              <button
                class="icon-button"
                title={`Edit client ${client.client_id}`}
                aria-label={`Edit client ${client.client_id}`}
                disabled={editingClientId === client.id}
                onclick={() => onEditClient(client)}
              >
                <Pencil size={17} />
              </button>
            </div>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</section>
