<script lang="ts">
  import { AppWindow } from '@lucide/svelte';
  import type { ConsentPolicyTemplate } from '$lib/api';
  import { grantModeLabel } from './helpers';

  export let consentPolicyTemplates: ConsentPolicyTemplate[] = [];
  export let clientId = '';
  export let name = '';
  export let redirectUris = '';
  export let postLogoutRedirectUris = '';
  export let scopes = '';
  export let publicClient = true;
  export let selectedConsentPolicyTemplateId = '';
  export let createdSecret = '';
  export let rotatedSecret = '';
  export let message = '';
  export let onCreate: () => void | Promise<void>;
</script>

<section class="panel panel-spaced">
  <div class="form-grid">
    <div class="field">
      <label for="client-id">Client ID</label>
      <input id="client-id" bind:value={clientId} />
    </div>
    <div class="field">
      <label for="name">Client name</label>
      <input id="name" bind:value={name} />
    </div>
    <div class="field">
      <label for="scopes">Scopes</label>
      <input id="scopes" bind:value={scopes} />
    </div>
    <div class="field">
      <label for="redirects">Authorization redirect URIs</label>
      <textarea id="redirects" bind:value={redirectUris}></textarea>
    </div>
    <div class="field">
      <label for="post-logout-redirects">Post-logout redirect URIs</label>
      <textarea id="post-logout-redirects" bind:value={postLogoutRedirectUris}></textarea>
    </div>
    <div class="field">
      <label for="consent-policy">Consent policy</label>
      <select id="consent-policy" bind:value={selectedConsentPolicyTemplateId}>
        <option value="">Required once</option>
        {#each consentPolicyTemplates as template}
          <option value={template.id}>{template.name} ({grantModeLabel(template.grant_mode)})</option>
        {/each}
      </select>
    </div>
    <label class="checkbox-field">
      <input type="checkbox" bind:checked={publicClient} />
      <span>Public client</span>
    </label>
  </div>
  <button class="primary-button section-action" onclick={onCreate}>
    <AppWindow size={17} />
    <span>Create client</span>
  </button>
  {#if createdSecret}
    <p class="status-line">Client secret: {createdSecret}</p>
  {/if}
  {#if rotatedSecret}
    <p class="status-line">Rotated client secret: {rotatedSecret}</p>
  {/if}
  {#if message}<p class="status-line">{message}</p>{/if}
</section>
