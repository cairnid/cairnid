<script lang="ts">
  import { RefreshCw, Trash2 } from '@lucide/svelte';
  import type { UserConsentGrant } from '$lib/api';

  export let grants: UserConsentGrant[] = [];
  export let revokingGrantId: string | null = null;
  export let onRefresh: () => void | Promise<void>;
  export let onRevoke: (grant: UserConsentGrant) => void | Promise<void>;
</script>

<div class="account-section">
  <div class="toolbar">
    <strong>Authorized applications</strong>
    <button class="icon-button" title="Refresh authorized applications" onclick={onRefresh}>
      <RefreshCw size={16} />
    </button>
  </div>
  {#if grants.length}
    <table class="data-table responsive-table">
      <thead>
        <tr>
          <th>Application</th>
          <th>Client ID</th>
          <th>Scopes</th>
          <th>Status</th>
          <th>Granted</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each grants as grant}
          <tr>
            <td data-label="Application">{grant.client_name}</td>
            <td data-label="Client ID">{grant.client_public_id}</td>
            <td data-label="Scopes">
              <span class="chip-list">
                {#each grant.scopes as scope}
                  <span class="chip">{scope}</span>
                {/each}
              </span>
            </td>
            <td data-label="Status">
              {#if grant.revoked_at}
                <span class="status-pill revoked">Revoked</span>
              {:else}
                <span class="status-pill active">Active</span>
              {/if}
            </td>
            <td data-label="Granted">{grant.created_at}</td>
            <td data-label="" class="row-actions">
              {#if !grant.revoked_at}
                <button
                  aria-label={`Revoke consent for ${grant.client_name}`}
                  class="icon-button"
                  disabled={revokingGrantId === grant.id}
                  title={`Revoke consent for ${grant.client_name}`}
                  onclick={() => onRevoke(grant)}
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
    <p class="status-line">No authorized applications</p>
  {/if}
</div>
