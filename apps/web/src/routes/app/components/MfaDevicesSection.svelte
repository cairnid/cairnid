<script lang="ts">
  import { Fingerprint, RefreshCw, ShieldCheck, Trash2, X } from '@lucide/svelte';
  import type { MfaCredential } from './types';

  export let credentials: MfaCredential[] = [];
  export let recoveryCodeCount = 0;
  export let showReauthentication = false;
  export let pendingActionLabel = 'Reauthenticate';
  export let reauthenticationPassword = '';
  export let reauthenticationCode = '';
  export let reauthenticationBusy = false;
  export let canUsePasskey = false;
  export let onRegenerateRecoveryCodes: () => void | Promise<void>;
  export let onRevokeCredential: (credential: MfaCredential) => void | Promise<void>;
  export let onSubmitReauthentication: () => void | Promise<void>;
  export let onCompleteReauthenticationPasskey: () => void | Promise<void>;
  export let onClearReauthentication: () => void;

  function mfaKindLabel(kind: MfaCredential['kind']) {
    switch (kind) {
      case 'totp':
        return 'Authenticator app';
      case 'web_authn':
        return 'Passkey';
      case 'recovery_code':
        return 'Recovery code';
    }
  }
</script>

<div class="account-section">
  <div class="toolbar">
    <strong>MFA devices</strong>
    <span class="status-line inline-status-line">{recoveryCodeCount} recovery codes active</span>
  </div>
  {#if credentials.some((credential) => credential.status === 'active')}
    <button class="secondary-button section-action" onclick={onRegenerateRecoveryCodes}>
      <RefreshCw size={16} />
      <span>Regenerate codes</span>
    </button>
  {/if}
  {#if credentials.length}
    <table class="data-table responsive-table">
      <thead>
        <tr>
          <th>Type</th>
          <th>Label</th>
          <th>Status</th>
          <th>Last used</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each credentials as credential}
          <tr>
            <td data-label="Type">{mfaKindLabel(credential.kind)}</td>
            <td data-label="Label">{credential.label}</td>
            <td data-label="Status">{credential.status}</td>
            <td data-label="Last used">{credential.last_used_at ?? 'Never'}</td>
            <td data-label="" class="row-actions">
              <button
                class="icon-button"
                title="Revoke MFA credential"
                onclick={() => onRevokeCredential(credential)}
              >
                <Trash2 size={16} />
              </button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {:else}
    <p class="status-line">No MFA devices enrolled</p>
  {/if}
  {#if showReauthentication}
    <div class="form-grid reauthentication-panel">
      <div class="toolbar">
        <strong>{pendingActionLabel}</strong>
        <button class="icon-button" title="Cancel reauthentication" onclick={onClearReauthentication}>
          <X size={16} />
        </button>
      </div>
      <div class="field">
        <label for="reauth-password">Password</label>
        <input
          id="reauth-password"
          bind:value={reauthenticationPassword}
          type="password"
          autocomplete="current-password"
        />
      </div>
      <div class="field">
        <label for="reauth-code">Authenticator or recovery code</label>
        <input
          id="reauth-code"
          bind:value={reauthenticationCode}
          inputmode="numeric"
          autocomplete="one-time-code"
        />
      </div>
      <div class="button-row">
        <button class="primary-button" disabled={reauthenticationBusy} onclick={onSubmitReauthentication}>
          <ShieldCheck size={17} />
          <span>Confirm</span>
        </button>
        {#if canUsePasskey}
          <button
            class="secondary-button"
            disabled={reauthenticationBusy}
            onclick={onCompleteReauthenticationPasskey}
          >
            <Fingerprint size={17} />
            <span>Use passkey</span>
          </button>
        {/if}
      </div>
    </div>
  {/if}
</div>
