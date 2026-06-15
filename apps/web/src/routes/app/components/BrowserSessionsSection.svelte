<script lang="ts">
  import { RefreshCw, Trash2 } from '@lucide/svelte';
  import type { BrowserSession } from '$lib/api';
  import { sessionAuthLabel } from '$lib/session-labels';

  export let sessions: BrowserSession[] = [];
  export let revokingSessionId: string | null = null;
  export let onRefresh: () => void | Promise<void>;
  export let onRevoke: (session: BrowserSession) => void | Promise<void>;
</script>

<div class="account-section">
  <div class="toolbar">
    <strong>Browser sessions</strong>
    <button class="icon-button" title="Refresh browser sessions" onclick={onRefresh}>
      <RefreshCw size={16} />
    </button>
  </div>
  {#if sessions.length}
    <table class="data-table responsive-table">
      <thead>
        <tr>
          <th>Started</th>
          <th>Expires</th>
          <th>Authentication</th>
          <th>Address</th>
          <th>Browser</th>
          <th>Status</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each sessions as session}
          <tr>
            <td data-label="Started">{session.created_at}</td>
            <td data-label="Expires">{session.expires_at}</td>
            <td data-label="Authentication">{sessionAuthLabel(session)}</td>
            <td data-label="Address">{session.created_ip_address ?? 'Unknown'}</td>
            <td data-label="Browser" class="wrapped-cell">{session.created_user_agent ?? 'Unknown'}</td>
            <td data-label="Status">
              {#if session.current}
                <span class="status-pill active">Current</span>
              {:else}
                <span class="status-pill neutral">Active</span>
              {/if}
            </td>
            <td data-label="" class="row-actions">
              {#if !session.current}
                <button
                  aria-label={`Revoke browser session ${session.id}`}
                  class="icon-button"
                  disabled={revokingSessionId === session.id}
                  title="Revoke browser session"
                  onclick={() => onRevoke(session)}
                >
                  <Trash2 size={16} />
                </button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {:else}
    <p class="status-line">No active browser sessions</p>
  {/if}
</div>
