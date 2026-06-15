<script lang="ts">
  import { Ban, CircleCheck, Eye, KeyRound, Trash2 } from '@lucide/svelte';
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
  <table class="data-table">
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
      </tr>
    </thead>
    <tbody>
      {#each clients as client}
        <tr>
          <td>{client.client_id}</td>
          <td>{client.name}</td>
          <td>{client.redirect_uris.map((uri) => uri.value).join(', ')}</td>
          <td>{client.post_logout_redirect_uris.map((uri) => uri.value).join(', ')}</td>
          <td>{client.grant_types.join(', ')}</td>
          <td>{client.allowed_scopes.join(', ')}</td>
          <td>
            <div class="chip-list">
              {#each claimPreview(client.allowed_scopes) as claim}
                <span class="chip">{claim}</span>
              {:else}
                <span class="muted">No user claims</span>
              {/each}
            </div>
          </td>
          <td>{policyLabelForClient(client, consentPolicyTemplates)}</td>
          <td>{client.public_client ? 'Public' : 'Confidential'}</td>
          <td>
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
          <td>
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
          <td>
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
        </tr>
      {/each}
    </tbody>
  </table>
</section>
