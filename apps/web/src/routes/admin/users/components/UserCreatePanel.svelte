<script lang="ts">
  import { UserPlus } from '@lucide/svelte';

  export let email = '';
  export let displayName = '';
  export let password = '';
  export let message = '';
  export let previewUrl = '';
  export let onCreate: () => void | Promise<void>;
  export let onInvite: () => void | Promise<void>;
</script>

<section class="panel panel-spaced">
  <div class="form-grid">
    <div class="field">
      <label for="email">Email</label>
      <input id="email" bind:value={email} />
    </div>
    <div class="field">
      <label for="display-name">Display name</label>
      <input id="display-name" bind:value={displayName} />
    </div>
    <div class="field">
      <label for="password">Initial password</label>
      <input id="password" type="password" bind:value={password} />
    </div>
  </div>
  <div class="button-row section-action">
    <button class="primary-button" onclick={onCreate}>
      <UserPlus size={17} />
      <span>Create user</span>
    </button>
    <button class="secondary-button" onclick={onInvite}>
      <UserPlus size={17} />
      <span>Invite user</span>
    </button>
  </div>
  {#if message}
    <p class="status-line">{message}</p>
  {/if}
  {#if previewUrl}
    <p class="status-line"><a href={previewUrl}>{previewUrl}</a></p>
  {/if}
</section>
