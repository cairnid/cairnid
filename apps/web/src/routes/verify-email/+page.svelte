<script lang="ts">
  import { onMount } from 'svelte';
  import { CheckCircle, KeyRound } from '@lucide/svelte';
  import { api, unknownJson } from '$lib/api';

  const params = new URLSearchParams(globalThis.location?.search ?? '');
  let token = params.get('token') ?? '';
  let message = 'Ready';
  let busy = false;

  async function verify() {
    busy = true;
    message = '';
    try {
      await api('/api/v1/session/email-verification/confirm', unknownJson, {
        method: 'POST',
        body: JSON.stringify({ token })
      });
      message = 'Email verified';
    } catch (error) {
      message = error instanceof Error ? error.message : 'Verification failed';
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    if (token) {
      void verify();
    }
  });
</script>

<main class="content" style="display: grid; min-height: 100vh; place-items: center;">
  <section class="panel" style="width: min(440px, 100%);">
    <div class="brand">
      <KeyRound size={24} />
      <span>Cairn Identity</span>
    </div>

    <div class="field">
      <label for="token">Verification token</label>
      <input id="token" bind:value={token} autocomplete="one-time-code" />
    </div>

    <button class="primary-button" style="margin-top: 16px;" disabled={busy} onclick={verify}>
      <CheckCircle size={17} />
      <span>Verify email</span>
    </button>

    {#if message}
      <p class="status-line">{message}</p>
    {/if}
  </section>
</main>
