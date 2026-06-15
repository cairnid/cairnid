<script lang="ts">
  import { RefreshCw, Trash2 } from '@lucide/svelte';
  import type { BrowserSession, User } from '$lib/api';
  import { sessionAuthLabel } from '$lib/session-labels';

  export let selectedUser: User | null = null;
  export let sessions: BrowserSession[] = [];
  export let loading = false;
  export let revokingSessionId: string | null = null;
  export let onRefresh: () => void | Promise<void>;
  export let onRevoke: (session: BrowserSession) => void | Promise<void>;
</script>

{#if selectedUser}
  <section class="panel panel-spaced">
    <div class="toolbar">
      <div>
        <h2 class="section-heading">Browser sessions</h2>
        <p class="status-line">{selectedUser.email}</p>
      </div>
      <button class="icon-button" title="Refresh browser sessions" disabled={loading} onclick={onRefresh}>
        <RefreshCw size={17} />
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
      <p class="status-line">{loading ? 'Loading browser sessions' : 'No active browser sessions'}</p>
    {/if}
  </section>
{/if}
