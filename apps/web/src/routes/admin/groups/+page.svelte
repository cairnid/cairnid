<script lang="ts">
  import { onMount } from 'svelte';
  import { Plus, RefreshCw, Trash2, UserPlus } from '@lucide/svelte';
  import Shell from '$lib/components/Shell.svelte';
  import {
    api,
    apiList,
    groupSchema,
    membershipSchema,
    unknownJson,
    userSchema,
    type Group,
    type Membership,
    type MembershipRole,
    type User
  } from '$lib/api';

  let groups: Group[] = [];
  let users: User[] = [];
  let memberships: Membership[] = [];
  let selectedGroupId = '';
  let selectedUserId = '';
  let selectedRole: MembershipRole = 'member';
  let slug = '';
  let displayName = '';
  let message = '';

  async function load() {
    const [nextGroups, nextUsers] = await Promise.all([
      apiList('/api/v1/groups', groupSchema),
      apiList('/api/v1/users', userSchema)
    ]);
    groups = nextGroups;
    users = nextUsers;

    if (!groups.some((group) => group.id === selectedGroupId)) {
      selectedGroupId = groups[0]?.id ?? '';
    }
    if (!users.some((user) => user.id === selectedUserId)) {
      selectedUserId = users[0]?.id ?? '';
    }

    await loadMemberships();
  }

  async function loadMemberships() {
    if (!selectedGroupId) {
      memberships = [];
      return;
    }

    memberships = await apiList(`/api/v1/groups/${selectedGroupId}/memberships`, membershipSchema);
  }

  async function create() {
    message = '';
    try {
      await api('/api/v1/groups', groupSchema, {
        method: 'POST',
        body: JSON.stringify({ slug, display_name: displayName })
      });
      slug = '';
      displayName = '';
      await load();
    } catch (error) {
      message = error instanceof Error ? error.message : 'Create failed';
    }
  }

  async function selectGroup(event: Event) {
    selectedGroupId = (event.currentTarget as HTMLSelectElement).value;
    message = '';
    try {
      await loadMemberships();
    } catch (error) {
      message = error instanceof Error ? error.message : 'Load failed';
    }
  }

  async function assignMembership() {
    if (!selectedGroupId || !selectedUserId) {
      return;
    }

    message = '';
    try {
      await api(
        `/api/v1/groups/${selectedGroupId}/memberships/${selectedUserId}`,
        membershipSchema,
        {
          method: 'PUT',
          body: JSON.stringify({ role: selectedRole })
        }
      );
      await loadMemberships();
    } catch (error) {
      message = error instanceof Error ? error.message : 'Membership update failed';
    }
  }

  async function removeMembership(membership: Membership) {
    message = '';
    try {
      await api(
        `/api/v1/groups/${membership.group_id}/memberships/${membership.user_id}`,
        unknownJson,
        { method: 'DELETE' }
      );
      await loadMemberships();
    } catch (error) {
      message = error instanceof Error ? error.message : 'Membership removal failed';
    }
  }

  function selectedGroup(): Group | undefined {
    return groups.find((group) => group.id === selectedGroupId);
  }

  function membershipUser(membership: Membership): User | undefined {
    return users.find((user) => user.id === membership.user_id);
  }

  onMount(() =>
    void load().catch((error) => {
      message = error instanceof Error ? error.message : 'Load failed';
    })
  );
</script>

<Shell>
  <div class="toolbar">
    <div>
      <h1>Groups</h1>
      <p class="status-line">Organize users for claims and future access policies.</p>
    </div>
    <button class="icon-button" title="Refresh" onclick={load}><RefreshCw size={17} /></button>
  </div>

  <section class="panel">
    <div class="form-grid">
      <div class="field">
        <label for="slug">Slug</label>
        <input id="slug" bind:value={slug} />
      </div>
      <div class="field">
        <label for="display-name">Display name</label>
        <input id="display-name" bind:value={displayName} />
      </div>
    </div>
    <button class="primary-button" style="margin-top: 14px;" onclick={create}>
      <Plus size={17} />
      <span>Create group</span>
    </button>
    {#if message}<p class="status-line">{message}</p>{/if}
  </section>

  <section class="panel" style="margin-top: 16px;">
    <table class="data-table">
      <thead><tr><th>Slug</th><th>Name</th><th>Created</th></tr></thead>
      <tbody>
        {#each groups as group}
          <tr>
            <td>{group.slug}</td>
            <td>{group.display_name}</td>
            <td>{new Date(group.created_at).toLocaleString()}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </section>

  <section class="panel" style="margin-top: 16px;">
    <div class="toolbar">
      <div>
        <h2>Memberships</h2>
        <p class="status-line">{selectedGroup()?.display_name ?? 'Select a group'}</p>
      </div>
      <button class="icon-button" title="Refresh memberships" onclick={loadMemberships} disabled={!selectedGroupId}>
        <RefreshCw size={17} />
      </button>
    </div>

    <div class="form-grid">
      <div class="field">
        <label for="group">Group</label>
        <select id="group" bind:value={selectedGroupId} onchange={selectGroup}>
          {#each groups as group}
            <option value={group.id}>{group.display_name}</option>
          {/each}
        </select>
      </div>
      <div class="field">
        <label for="user">User</label>
        <select id="user" bind:value={selectedUserId}>
          {#each users as user}
            <option value={user.id}>{user.email}</option>
          {/each}
        </select>
      </div>
      <div class="field">
        <label for="role">Role</label>
        <select id="role" bind:value={selectedRole}>
          <option value="member">Member</option>
          <option value="owner">Owner</option>
        </select>
      </div>
    </div>

    <button
      class="primary-button"
      style="margin-top: 14px;"
      onclick={assignMembership}
      disabled={!selectedGroupId || !selectedUserId}
    >
      <UserPlus size={17} />
      <span>Save membership</span>
    </button>

    <table class="data-table" style="margin-top: 16px;">
      <thead><tr><th>User</th><th>Name</th><th>Role</th><th>Added</th><th></th></tr></thead>
      <tbody>
        {#each memberships as membership}
          {@const user = membershipUser(membership)}
          <tr>
            <td>{user?.email ?? membership.user_id}</td>
            <td>{user?.display_name ?? 'Unknown user'}</td>
            <td>{membership.role}</td>
            <td>{new Date(membership.created_at).toLocaleString()}</td>
            <td>
              <button
                class="icon-button"
                title="Remove membership"
                onclick={() => removeMembership(membership)}
              >
                <Trash2 size={17} />
              </button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </section>
</Shell>
