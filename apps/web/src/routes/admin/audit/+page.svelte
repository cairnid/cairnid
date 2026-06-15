<script lang="ts">
  import { onMount } from 'svelte';
  import { RefreshCw, Search } from '@lucide/svelte';
  import Shell from '$lib/components/Shell.svelte';
  import { apiList, auditEventSchema, type AuditEvent } from '$lib/api';

  type ActorKindFilter = 'all' | 'user' | 'client' | 'system';

  let events: AuditEvent[] = [];
  let action = '';
  let target = '';
  let actorKind: ActorKindFilter = 'all';
  let actorId = '';
  let from = '';
  let to = '';
  let message = '';

  async function load() {
    events = await apiList(auditPath(), auditEventSchema);
  }

  function auditPath(): string {
    const params = new URLSearchParams();
    const trimmedAction = action.trim();
    const trimmedTarget = target.trim();
    const trimmedActorId = actorId.trim();

    if (trimmedAction) {
      params.set('action', trimmedAction);
    }
    if (trimmedTarget) {
      params.set('target', trimmedTarget);
    }
    if (actorKind !== 'all') {
      params.set('actor_kind', actorKind);
    }
    if (trimmedActorId) {
      params.set('actor_id', trimmedActorId);
    }
    if (from) {
      params.set('from', new Date(from).toISOString());
    }
    if (to) {
      params.set('to', new Date(to).toISOString());
    }

    const query = params.toString();
    return query ? `/api/v1/audit-events?${query}` : '/api/v1/audit-events';
  }

  function actorLabel(event: AuditEvent): string {
    return event.actor_id ? `${event.actor_kind}:${event.actor_id}` : event.actor_kind;
  }

  onMount(() => void load().catch((error) => (message = error.message)));
</script>

<Shell>
  <div class="toolbar">
    <div>
      <h1>Audit</h1>
      <p class="status-line">Review security-relevant administrative and authentication events.</p>
    </div>
    <button class="icon-button" title="Refresh" onclick={load}><RefreshCw size={17} /></button>
  </div>

  <section class="panel">
    <div class="form-grid">
      <div class="field">
        <label for="audit-action">Action</label>
        <input id="audit-action" bind:value={action} />
      </div>
      <div class="field">
        <label for="audit-target">Target</label>
        <input id="audit-target" bind:value={target} />
      </div>
      <div class="field">
        <label for="audit-actor-kind">Actor kind</label>
        <select id="audit-actor-kind" bind:value={actorKind}>
          <option value="all">All</option>
          <option value="user">User</option>
          <option value="client">Client</option>
          <option value="system">System</option>
        </select>
      </div>
      <div class="field">
        <label for="audit-actor-id">Actor ID</label>
        <input id="audit-actor-id" bind:value={actorId} />
      </div>
      <div class="field">
        <label for="audit-from">From</label>
        <input id="audit-from" type="datetime-local" bind:value={from} />
      </div>
      <div class="field">
        <label for="audit-to">To</label>
        <input id="audit-to" type="datetime-local" bind:value={to} />
      </div>
    </div>
    <button class="secondary-button" style="margin-top: 14px;" onclick={load}>
      <Search size={17} />
      <span>Apply filters</span>
    </button>
  </section>

  <section class="panel" style="margin-top: 16px;">
    {#if message}<p class="status-line">{message}</p>{/if}
    <table class="data-table">
      <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Metadata</th></tr></thead>
      <tbody>
        {#each events as event}
          <tr>
            <td>{new Date(event.created_at).toLocaleString()}</td>
            <td>{actorLabel(event)}</td>
            <td>{event.action}</td>
            <td>{event.target}</td>
            <td><code>{JSON.stringify(event.metadata)}</code></td>
          </tr>
        {/each}
      </tbody>
    </table>
  </section>
</Shell>
