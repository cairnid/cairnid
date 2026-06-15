<script lang="ts">
  import { KeyRound } from '@lucide/svelte';

  export let currentPassword = '';
  export let newPassword = '';
  export let confirmNewPassword = '';
  export let changingPassword = false;
  export let onChangePassword: () => void | Promise<void>;
</script>

<div class="account-section">
  <div class="toolbar">
    <strong>Password</strong>
  </div>
  <div class="form-grid">
    <div class="field">
      <label for="current-password">Current password</label>
      <input
        id="current-password"
        bind:value={currentPassword}
        type="password"
        autocomplete="current-password"
      />
    </div>
    <div class="field">
      <label for="new-password">New password</label>
      <input
        id="new-password"
        bind:value={newPassword}
        type="password"
        autocomplete="new-password"
        minlength="12"
      />
    </div>
    <div class="field">
      <label for="confirm-new-password">Confirm password</label>
      <input
        id="confirm-new-password"
        bind:value={confirmNewPassword}
        type="password"
        autocomplete="new-password"
        minlength="12"
      />
    </div>
  </div>
  <button class="primary-button section-action" disabled={changingPassword} onclick={onChangePassword}>
    <KeyRound size={17} />
    <span>Change password</span>
  </button>
</div>
