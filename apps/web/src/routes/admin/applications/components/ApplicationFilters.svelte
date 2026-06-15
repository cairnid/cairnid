<script lang="ts">
  import { Search } from '@lucide/svelte';
  import type { ClientStatusFilter, ClientTypeFilter, GrantTypeFilter } from './types';

  export let search = '';
  export let clientType: ClientTypeFilter = 'all';
  export let clientStatus: ClientStatusFilter = 'all';
  export let grantType: GrantTypeFilter = 'all';
  export let scope = '';
  export let onApply: () => void | Promise<void>;
</script>

<section class="panel">
  <div class="form-grid">
    <div class="field">
      <label for="client-search">Search</label>
      <input id="client-search" bind:value={search} />
    </div>
    <div class="field">
      <label for="client-type-filter">Client type</label>
      <select id="client-type-filter" bind:value={clientType}>
        <option value="all">All</option>
        <option value="public">Public</option>
        <option value="confidential">Confidential</option>
      </select>
    </div>
    <div class="field">
      <label for="client-status-filter">Status</label>
      <select id="client-status-filter" bind:value={clientStatus}>
        <option value="all">All</option>
        <option value="active">Active</option>
        <option value="disabled">Disabled</option>
      </select>
    </div>
    <div class="field">
      <label for="grant-type-filter">Grant type</label>
      <select id="grant-type-filter" bind:value={grantType}>
        <option value="all">All</option>
        <option value="authorization_code">Authorization code</option>
        <option value="refresh_token">Refresh token</option>
        <option value="client_credentials">Client credentials</option>
      </select>
    </div>
    <div class="field">
      <label for="scope-filter">Scope filter</label>
      <input id="scope-filter" bind:value={scope} />
    </div>
  </div>
  <button class="secondary-button section-action" onclick={onApply}>
    <Search size={17} />
    <span>Apply filters</span>
  </button>
</section>
