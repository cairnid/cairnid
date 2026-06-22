<script lang="ts">
  import { RefreshCw } from '@lucide/svelte';
  import type { SecurityActivityEvent } from '$lib/api';

  export let events: SecurityActivityEvent[] = [];
  export let loading = false;
  export let onRefresh: () => void | Promise<void>;

  function formatTimestamp(value: string): string {
    const timestamp = new Date(value);
    return Number.isNaN(timestamp.getTime()) ? value : timestamp.toLocaleString();
  }
</script>

<div class="account-section">
  <div class="toolbar">
    <strong>Security activity</strong>
    <button
      class="icon-button"
      title="Refresh security activity"
      disabled={loading}
      onclick={onRefresh}
    >
      <RefreshCw size={16} />
    </button>
  </div>
  {#if events.length}
    <table class="data-table responsive-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Activity</th>
          <th>Address</th>
          <th>Browser</th>
        </tr>
      </thead>
      <tbody>
        {#each events as event}
          <tr>
            <td data-label="Time">
              <time datetime={event.occurred_at} title={event.occurred_at}>
                {formatTimestamp(event.occurred_at)}
              </time>
            </td>
            <td data-label="Activity">{event.summary}</td>
            <td data-label="Address">{event.ip_address ?? 'Unknown'}</td>
            <td data-label="Browser" class="wrapped-cell">{event.user_agent ?? 'Unknown'}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {:else}
    <p class="status-line">{loading ? 'Loading security activity' : 'No security activity'}</p>
  {/if}
</div>
