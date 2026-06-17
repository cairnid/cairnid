<script lang="ts">
  import { Save, X } from '@lucide/svelte';
  import type { ConsentPolicyTemplate, OidcClient } from '$lib/api';
  import { grantModeLabel, policyLabelForClient } from './helpers';

  export let client: OidcClient | null = null;
  export let consentPolicyTemplates: ConsentPolicyTemplate[] = [];
  export let name = '';
  export let redirectUris = '';
  export let postLogoutRedirectUris = '';
  export let scopes = '';
  export let selectedConsentPolicyTemplateId = '';
  export let updating = false;
  export let message = '';
  export let onSave: () => void | Promise<void>;
  export let onCancel: () => void;

  function handleSubmit(event: SubmitEvent) {
    event.preventDefault();
    void onSave();
  }
</script>

{#if client}
  <section class="panel panel-spaced edit-panel" aria-label="Edit application">
    <div class="edit-header">
      <div>
        <h2 class="section-heading">Edit application</h2>
        <p class="status-line">
          {client.client_id} / {client.public_client ? 'Public' : 'Confidential'} /
          {client.status === 'active' ? 'Active' : 'Disabled'}
        </p>
      </div>
      <button
        class="icon-button"
        title="Close edit panel"
        aria-label="Close edit panel"
        type="button"
        onclick={onCancel}
      >
        <X size={17} />
      </button>
    </div>

    <dl class="immutable-grid">
      <div>
        <dt>Public ID</dt>
        <dd>{client.client_id}</dd>
      </div>
      <div>
        <dt>Client type</dt>
        <dd>{client.public_client ? 'Public' : 'Confidential'}</dd>
      </div>
      <div>
        <dt>Grant types</dt>
        <dd>{client.grant_types.join(', ')}</dd>
      </div>
      <div>
        <dt>PKCE</dt>
        <dd>{client.require_pkce ? 'Required' : 'Not required'}</dd>
      </div>
      <div>
        <dt>Status</dt>
        <dd>{client.status === 'active' ? 'Active' : 'Disabled'}</dd>
      </div>
      <div>
        <dt>Secret</dt>
        <dd>{client.public_client ? 'None' : client.has_client_secret ? 'Set' : 'Missing'}</dd>
      </div>
      <div>
        <dt>Current policy</dt>
        <dd>{policyLabelForClient(client, consentPolicyTemplates)}</dd>
      </div>
    </dl>

    <form onsubmit={handleSubmit}>
      <div class="form-grid">
        <div class="field">
          <label for="edit-client-name">Edit client name</label>
          <input id="edit-client-name" bind:value={name} disabled={updating} />
        </div>
        <div class="field">
          <label for="edit-scopes">Edit scopes</label>
          <input id="edit-scopes" bind:value={scopes} disabled={updating} />
        </div>
        <div class="field">
          <label for="edit-redirects">Edit authorization redirect URIs</label>
          <textarea id="edit-redirects" bind:value={redirectUris} disabled={updating}></textarea>
        </div>
        <div class="field">
          <label for="edit-post-logout-redirects">Edit post-logout redirect URIs</label>
          <textarea
            id="edit-post-logout-redirects"
            bind:value={postLogoutRedirectUris}
            disabled={updating}
          ></textarea>
        </div>
        <div class="field">
          <label for="edit-consent-policy">Edit consent policy</label>
          <select
            id="edit-consent-policy"
            bind:value={selectedConsentPolicyTemplateId}
            disabled={updating}
          >
            <option value="">Required once</option>
            {#each consentPolicyTemplates as template}
              <option value={template.id}>{template.name} ({grantModeLabel(template.grant_mode)})</option>
            {/each}
          </select>
        </div>
      </div>

      <div class="button-row section-action">
        <button class="primary-button" type="submit" disabled={updating}>
          <Save size={17} />
          <span>{updating ? 'Saving' : 'Save changes'}</span>
        </button>
        <button class="secondary-button" type="button" disabled={updating} onclick={onCancel}>
          Cancel
        </button>
      </div>
    </form>

    {#if message}<p class="status-line">{message}</p>{/if}
  </section>
{/if}

<style>
  .edit-panel {
    display: grid;
    gap: 14px;
  }

  .edit-header {
    align-items: start;
    display: flex;
    gap: 12px;
    justify-content: space-between;
  }

  .edit-header .status-line {
    margin-bottom: 0;
  }

  .immutable-grid {
    border-top: 1px solid #e5e9f0;
    display: grid;
    gap: 10px 14px;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    margin: 0;
    padding-top: 14px;
  }

  .immutable-grid div {
    min-width: 0;
  }

  .immutable-grid dt {
    color: #44546a;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
  }

  .immutable-grid dd {
    margin: 4px 0 0;
    overflow-wrap: anywhere;
  }
</style>
