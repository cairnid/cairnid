<script lang="ts">
  import { goto } from '$app/navigation';
  import { KeyRound, UserPlus } from '@lucide/svelte';
  import { z } from 'zod';
  import { api, unknownJson } from '$lib/api';

  const params = new URLSearchParams(globalThis.location?.search ?? '');
  let token = params.get('token') ?? '';
  let password = '';
  let message = '';
  let busy = false;

  async function accept() {
    busy = true;
    message = '';
    try {
      await api('/api/v1/invitations/accept', unknownJson, {
        method: 'POST',
        body: JSON.stringify({
          token: z.string().min(1).parse(token),
          password: z.string().min(12).parse(password)
        })
      });
      await goto('/login');
    } catch (error) {
      message = error instanceof Error ? error.message : 'Invitation failed';
    } finally {
      busy = false;
    }
  }
</script>

<main class="content" style="display: grid; min-height: 100vh; place-items: center;">
  <section class="panel" style="width: min(440px, 100%);">
    <div class="brand">
      <KeyRound size={24} />
      <span>Cairn Identity</span>
    </div>

    <div class="form-grid" style="grid-template-columns: 1fr;">
      <div class="field">
        <label for="token">Invitation token</label>
        <input id="token" bind:value={token} autocomplete="one-time-code" />
      </div>
      <div class="field">
        <label for="password">New password</label>
        <input id="password" bind:value={password} type="password" autocomplete="new-password" />
      </div>
    </div>

    <button class="primary-button" style="margin-top: 16px;" disabled={busy} onclick={accept}>
      <UserPlus size={17} />
      <span>Accept invitation</span>
    </button>

    {#if message}
      <p class="status-line">{message}</p>
    {/if}
  </section>
</main>
