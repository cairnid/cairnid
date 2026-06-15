<script lang="ts">
  import { onMount } from 'svelte';
  import { CheckCircle, KeyRound, Server, ShieldAlert } from '@lucide/svelte';
  import Shell from '$lib/components/Shell.svelte';
  import { api, unknownJson } from '$lib/api';

  let settings: Record<string, unknown> = {};
  let status = 'Loading';

  onMount(async () => {
    try {
      settings = (await api('/api/v1/settings', unknownJson)) as Record<string, unknown>;
      status = 'Connected';
    } catch (error) {
      status = error instanceof Error ? error.message : 'Unable to load settings';
    }
  });

  function keyStatus(): string {
    if (settings.key_encryption_configured) return 'KEK configured';
    return 'KEK required for encrypted signing keys and lifecycle email links';
  }
</script>

<Shell>
  <div class="toolbar">
    <div>
      <h1>Overview</h1>
      <p class="status-line">Identity control plane status and configuration.</p>
    </div>
  </div>

  <section class="form-grid">
    <div class="panel">
      <h2><Server size={18} /> API</h2>
      <p>{status}</p>
    </div>
    <div class="panel">
      <h2><KeyRound size={18} /> Issuer</h2>
      <p>{settings.issuer ?? 'Not loaded'}</p>
    </div>
    <div class="panel">
      <h2><CheckCircle size={18} /> Signing</h2>
      <p>{settings.signing_configured ? 'RS256 configured' : 'RS256 key required for token issuing'}</p>
    </div>
    <div class="panel">
      <h2><ShieldAlert size={18} /> Security</h2>
      <p>{keyStatus()}</p>
    </div>
  </section>
</Shell>
