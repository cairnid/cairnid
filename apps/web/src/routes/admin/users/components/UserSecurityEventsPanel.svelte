<script lang="ts">
  import { RefreshCw } from '@lucide/svelte';
  import type { AuditEvent, User } from '$lib/api';
  import { auditActorLabel, metadataLabel } from './helpers';

  export let selectedUser: User | null = null;
  export let events: AuditEvent[] = [];
  export let loading = false;
  export let onRefresh: () => void | Promise<void>;
</script>

{#if selectedUser}
  <section class="panel panel-spaced">
    <div class="toolbar">
      <div>
        <h2 class="section-heading">Security activity</h2>
        <p class="status-line">{selectedUser.email}</p>
      </div>
      <button
        class="icon-button"
        title="Refresh security activity"
        disabled={loading}
        onclick={onRefresh}
      >
        <RefreshCw size={17} />
      </button>
    </div>
    {#if events.length}
      <table class="data-table responsive-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Target</th>
            <th>Address</th>
            <th>Browser</th>
            <th>Metadata</th>
          </tr>
        </thead>
        <tbody>
          {#each events as event}
            <tr>
              <td data-label="Time">{new Date(event.created_at).toLocaleString()}</td>
              <td data-label="Actor" class="wrapped-cell">{auditActorLabel(event)}</td>
              <td data-label="Action" class="wrapped-cell">{event.action}</td>
              <td data-label="Target" class="wrapped-cell">{event.target}</td>
              <td data-label="Address">{event.ip_address ?? 'Unknown'}</td>
              <td data-label="Browser" class="wrapped-cell">{event.user_agent ?? 'Unknown'}</td>
              <td data-label="Metadata" class="wrapped-cell">{metadataLabel(event.metadata)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else}
      <p class="status-line">
        {loading ? 'Loading security activity' : 'No security activity found'}
      </p>
    {/if}
  </section>
{/if}
