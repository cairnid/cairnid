<script lang="ts">
  import { KeyRound, Mail, RotateCcw } from '@lucide/svelte';
  import { z } from 'zod';
  import { api, deliverySchema, unknownJson } from '$lib/api';

  const params = new URLSearchParams(globalThis.location?.search ?? '');
  let token = params.get('token') ?? '';
  let email = '';
  let password = '';
  let message = '';
  let previewUrl = '';
  let busy = false;

  async function requestReset() {
    busy = true;
    message = '';
    previewUrl = '';
    try {
      const delivery = await api('/api/v1/session/password-recovery/request', deliverySchema, {
        method: 'POST',
        body: JSON.stringify({
          email: z.string().email().parse(email)
        })
      });
      previewUrl = delivery.preview_url ?? '';
      message = delivery.preview_url ? 'Recovery queued. Development preview link is available.' : 'Recovery queued.';
    } catch (error) {
      message = error instanceof Error ? error.message : 'Recovery request failed';
    } finally {
      busy = false;
    }
  }

  async function completeReset() {
    busy = true;
    message = '';
    try {
      await api('/api/v1/session/password-recovery/complete', unknownJson, {
        method: 'POST',
        body: JSON.stringify({
          token: z.string().min(1).parse(token),
          password: z.string().min(12).parse(password)
        })
      });
      message = 'Password updated';
      password = '';
    } catch (error) {
      message = error instanceof Error ? error.message : 'Password reset failed';
    } finally {
      busy = false;
    }
  }
</script>

<main class="content" style="display: grid; min-height: 100vh; place-items: center;">
  <section class="panel" style="width: min(460px, 100%);">
    <div class="brand">
      <KeyRound size={24} />
      <span>Cairn Identity</span>
    </div>

    <div class="form-grid" style="grid-template-columns: 1fr;">
      <div class="field">
        <label for="email">Email</label>
        <input id="email" bind:value={email} autocomplete="email" />
      </div>
      <button class="secondary-button" disabled={busy} onclick={requestReset}>
        <Mail size={17} />
        <span>Send recovery email</span>
      </button>

      <div class="field">
        <label for="token">Recovery token</label>
        <input id="token" bind:value={token} autocomplete="one-time-code" />
      </div>
      <div class="field">
        <label for="password">New password</label>
        <input id="password" bind:value={password} type="password" autocomplete="new-password" />
      </div>
      <button class="primary-button" disabled={busy} onclick={completeReset}>
        <RotateCcw size={17} />
        <span>Reset password</span>
      </button>
    </div>

    {#if message}
      <p class="status-line">{message}</p>
    {/if}
    {#if previewUrl}
      <p class="status-line"><a href={previewUrl}>{previewUrl}</a></p>
    {/if}
  </section>
</main>
