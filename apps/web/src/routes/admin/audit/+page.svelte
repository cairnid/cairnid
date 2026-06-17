<script lang="ts">
  import { onMount } from 'svelte';
  import { Download, RefreshCw, Search } from '@lucide/svelte';
  import Shell from '$lib/components/Shell.svelte';
  import { apiList, apiText, auditEventSchema, type AuditEvent } from '$lib/api';

  type ActorKindFilter = 'all' | 'user' | 'client' | 'system';
  const MAX_EXPORT_PAGES = 1000;

  let events: AuditEvent[] = [];
  let action = '';
  let target = '';
  let actorKind: ActorKindFilter = 'all';
  let actorId = '';
  let from = '';
  let to = '';
  let message = '';
  let exporting = false;

  async function load() {
    events = await apiList(auditPath(), auditEventSchema);
  }

  function auditParams(): URLSearchParams {
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

    return params;
  }

  function auditPath(pathname = '/api/v1/audit-events', params = auditParams()): string {
    const query = params.toString();
    return query ? `${pathname}?${query}` : pathname;
  }

  async function exportNdjson() {
    exporting = true;
    message = '';

    try {
      const params = auditParams();
      let cursor: string | null = null;
      let body = '';
      let rowCount = 0;
      let pageCount = 0;

      for (let pageIndex = 0; pageIndex < MAX_EXPORT_PAGES; pageIndex += 1) {
        if (cursor) {
          params.set('cursor', cursor);
        } else {
          params.delete('cursor');
        }

        const response = await apiText(auditPath('/api/v1/audit-events/export', params), {
          headers: {
            Accept: 'application/x-ndjson'
          }
        });
        body = appendNdjson(body, response.body);
        rowCount += countNdjsonRows(response.body);
        pageCount = pageIndex + 1;

        cursor = response.headers.get('x-cairn-next-cursor');
        if (!cursor) {
          downloadNdjson(body);
          message = `Exported ${rowCount} audit ${rowCount === 1 ? 'row' : 'rows'} across ${pageCount} ${pageCount === 1 ? 'page' : 'pages'}.`;
          return;
        }
      }

      throw new Error('Too many audit export pages');
    } catch (error) {
      message = error instanceof Error ? error.message : 'Audit export failed';
    } finally {
      exporting = false;
    }
  }

  function downloadNdjson(body: string) {
    const blob = new Blob([body], { type: 'application/x-ndjson' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `cairn-audit-events-${new Date().toISOString().replace(/[:.]/g, '-')}.ndjson`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  function appendNdjson(current: string, next: string): string {
    if (!current) {
      return next;
    }
    if (!next) {
      return current;
    }
    return current.endsWith('\n') ? `${current}${next}` : `${current}\n${next}`;
  }

  function countNdjsonRows(body: string): number {
    return body.split(/\r?\n/).filter((line) => line.length > 0).length;
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
    <div class="actions-row">
      <button class="secondary-button" onclick={load}>
        <Search size={17} />
        <span>Apply filters</span>
      </button>
      <button class="secondary-button" disabled={exporting} onclick={exportNdjson}>
        <Download size={17} />
        <span>{exporting ? 'Exporting...' : 'Export NDJSON'}</span>
      </button>
    </div>
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

<style>
  .actions-row {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 14px;
  }
</style>
