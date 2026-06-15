<script lang="ts">
  import { ShieldCheck } from '@lucide/svelte';
  import type { TotpSetup } from './types';

  export let setup: TotpSetup | null = null;
  export let code = '';
  export let onConfirm: () => void | Promise<void>;
</script>

{#if setup}
  <div class="form-grid single-column-grid totp-enrollment">
    <div class="field">
      <label for="totp-secret">Manual secret</label>
      <input id="totp-secret" value={setup.secret_base32} readonly />
    </div>
    <div class="field">
      <label for="totp-url">Authenticator URI</label>
      <textarea id="totp-url" readonly rows="3">{setup.otpauth_url}</textarea>
    </div>
    <div class="field">
      <label for="totp-confirm">Authenticator code</label>
      <input id="totp-confirm" bind:value={code} inputmode="numeric" autocomplete="one-time-code" />
    </div>
    <button class="primary-button" onclick={onConfirm}>
      <ShieldCheck size={17} />
      <span>Enable TOTP</span>
    </button>
  </div>
{/if}
