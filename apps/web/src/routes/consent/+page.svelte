<script lang="ts">
  import { ShieldCheck } from '@lucide/svelte';
  import { api, unknownJson } from '$lib/api';
  import { localRedirectPath } from '$lib/navigation';

  const params = new URLSearchParams(globalThis.location?.search ?? '');
  const returnTo = localRedirectPath(params.get('return_to'), '/admin');
  const clientId = params.get('client_id') ?? '';
  const clientName = params.get('client_name') ?? clientId;
  const scopes = (params.get('scopes') ?? 'openid').split(/\s+/).filter(Boolean);
  let message = '';
  let busy = false;

  async function approve() {
    busy = true;
    message = '';
    try {
      await api('/api/v1/consent', unknownJson, {
        method: 'POST',
        body: JSON.stringify({ client_id: clientId, return_to: returnTo, scopes })
      });
      globalThis.location.href = returnTo;
    } catch (error) {
      message = error instanceof Error ? error.message : 'Consent failed';
    } finally {
      busy = false;
    }
  }
</script>

<main class="content" style="display: grid; min-height: 100vh; place-items: center;">
  <section class="panel" style="width: min(520px, 100%);">
    <div class="brand">
      <ShieldCheck size={24} />
      <span>Authorize Application</span>
    </div>
    <p>{clientName} is requesting access to these scopes:</p>
    <ul>
      {#each scopes as scope}
        <li>{scope}</li>
      {/each}
    </ul>
    <button class="primary-button" disabled={busy || !clientId} onclick={approve}>Approve</button>
    {#if message}<p class="status-line">{message}</p>{/if}
  </section>
</main>
