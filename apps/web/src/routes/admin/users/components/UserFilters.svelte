<script lang="ts">
  import { Search } from '@lucide/svelte';
  import type { UserStatusFilter } from './types';

  export let search = '';
  export let statusFilter: UserStatusFilter = 'all';
  export let onApply: () => void | Promise<void>;
</script>

<section class="panel">
  <div class="form-grid">
    <div class="field">
      <label for="user-search">Search</label>
      <input id="user-search" bind:value={search} />
    </div>
    <div class="field">
      <label for="status-filter">Status</label>
      <select id="status-filter" bind:value={statusFilter}>
        <option value="all">All</option>
        <option value="active">Active</option>
        <option value="suspended">Suspended</option>
        <option value="locked">Locked</option>
      </select>
    </div>
  </div>
  <button class="secondary-button section-action" onclick={onApply}>
    <Search size={17} />
    <span>Apply filters</span>
  </button>
</section>
