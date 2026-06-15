<script lang="ts">
  import { onMount } from 'svelte';
  import { RefreshCw } from '@lucide/svelte';
  import Shell from '$lib/components/Shell.svelte';
  import {
    api,
    apiList,
    auditEventSchema,
    browserSessionListSchema,
    browserSessionRevocationSchema,
    deliverySchema,
    type AuditEvent,
    type BrowserSession,
    userSchema,
    type User,
    type UserStatus
  } from '$lib/api';
  import UserCreatePanel from './components/UserCreatePanel.svelte';
  import UserFilters from './components/UserFilters.svelte';
  import UserSecurityEventsPanel from './components/UserSecurityEventsPanel.svelte';
  import UserSessionsPanel from './components/UserSessionsPanel.svelte';
  import UsersTable from './components/UsersTable.svelte';
  import type { UserStatusFilter } from './components/types';

  let users: User[] = [];
  let email = '';
  let displayName = '';
  let password = '';
  let search = '';
  let statusFilter: UserStatusFilter = 'all';
  let message = '';
  let previewUrl = '';
  let selectedSessionUser: User | null = null;
  let userBrowserSessions: BrowserSession[] = [];
  let loadingUserSessions = false;
  let revokingUserSessionId: string | null = null;
  let selectedSecurityUser: User | null = null;
  let userSecurityEvents: AuditEvent[] = [];
  let loadingUserSecurityEvents = false;

  async function load() {
    users = await apiList(usersPath(), userSchema);
  }

  function usersPath(): string {
    const params = new URLSearchParams();
    const trimmedSearch = search.trim();
    if (trimmedSearch) {
      params.set('q', trimmedSearch);
    }
    if (statusFilter !== 'all') {
      params.set('status', statusFilter);
    }
    const query = params.toString();
    return query ? `/api/v1/users?${query}` : '/api/v1/users';
  }

  async function create() {
    message = '';
    previewUrl = '';
    try {
      await api('/api/v1/users', userSchema, {
        method: 'POST',
        body: JSON.stringify({
          email,
          display_name: displayName,
          password: password || undefined
        })
      });
      email = '';
      displayName = '';
      password = '';
      await load();
    } catch (error) {
      message = error instanceof Error ? error.message : 'Create failed';
    }
  }

  async function invite() {
    message = '';
    previewUrl = '';
    try {
      const delivery = await api('/api/v1/invitations', deliverySchema, {
        method: 'POST',
        body: JSON.stringify({
          email,
          display_name: displayName || email
        })
      });
      previewUrl = delivery.preview_url ?? '';
      message = delivery.preview_url ? 'Invitation queued. Development preview link is available.' : 'Invitation queued.';
      email = '';
      displayName = '';
      password = '';
      await load();
    } catch (error) {
      message = error instanceof Error ? error.message : 'Invitation failed';
    }
  }

  async function setStatus(user: User, status: UserStatus) {
    message = '';
    previewUrl = '';
    try {
      await api(`/api/v1/users/${user.id}/status`, userSchema, {
        method: 'PUT',
        body: JSON.stringify({ status })
      });
      await load();
    } catch (error) {
      message = error instanceof Error ? error.message : 'Status update failed';
    }
  }

  async function sendEmailVerification(user: User) {
    message = '';
    previewUrl = '';
    try {
      const delivery = await api(
        `/api/v1/users/${user.id}/email-verification/request`,
        deliverySchema,
        { method: 'POST' }
      );
      previewUrl = delivery.preview_url ?? '';
      message =
        delivery.status === 'already_verified'
          ? `${user.email} is already verified.`
          : delivery.preview_url
            ? `Verification email queued for ${user.email}. Development preview link is available.`
            : `Verification email queued for ${user.email}.`;
    } catch (error) {
      message = error instanceof Error ? error.message : 'Verification request failed';
    }
  }

  async function sendPasswordReset(user: User) {
    message = '';
    previewUrl = '';
    try {
      const delivery = await api(
        `/api/v1/users/${user.id}/password-recovery/request`,
        deliverySchema,
        { method: 'POST' }
      );
      previewUrl = delivery.preview_url ?? '';
      message = delivery.preview_url
        ? `Password reset queued for ${user.email}. Development preview link is available.`
        : `Password reset queued for ${user.email}.`;
    } catch (error) {
      message = error instanceof Error ? error.message : 'Password reset request failed';
    }
  }

  async function loadUserSessions(user: User) {
    message = '';
    previewUrl = '';
    selectedSessionUser = user;
    loadingUserSessions = true;
    try {
      const response = await api(`/api/v1/users/${user.id}/browser-sessions`, browserSessionListSchema);
      userBrowserSessions = response.sessions;
    } catch (error) {
      userBrowserSessions = [];
      message = error instanceof Error ? error.message : 'Session load failed';
    } finally {
      loadingUserSessions = false;
    }
  }

  async function reloadSelectedUserSessions() {
    if (selectedSessionUser) {
      await loadUserSessions(selectedSessionUser);
    }
  }

  async function revokeUserSession(session: BrowserSession) {
    if (!selectedSessionUser) {
      return;
    }
    if (session.current) {
      message = 'Use sign out to end the current admin session';
      return;
    }

    revokingUserSessionId = session.id;
    try {
      const response = await api(
        `/api/v1/users/${selectedSessionUser.id}/browser-sessions/${session.id}`,
        browserSessionRevocationSchema,
        { method: 'DELETE' }
      );
      userBrowserSessions = userBrowserSessions.filter((candidate) => candidate.id !== response.session_id);
      message = `Browser session revoked for ${selectedSessionUser.email}`;
    } catch (error) {
      message = error instanceof Error ? error.message : 'Session revocation failed';
    } finally {
      revokingUserSessionId = null;
    }
  }

  async function loadUserSecurityEvents(user: User) {
    message = '';
    previewUrl = '';
    selectedSecurityUser = user;
    loadingUserSecurityEvents = true;
    try {
      userSecurityEvents = await apiList(
        `/api/v1/users/${user.id}/security-events`,
        auditEventSchema,
        25
      );
    } catch (error) {
      userSecurityEvents = [];
      message = error instanceof Error ? error.message : 'Security activity load failed';
    } finally {
      loadingUserSecurityEvents = false;
    }
  }

  async function reloadSelectedUserSecurityEvents() {
    if (selectedSecurityUser) {
      await loadUserSecurityEvents(selectedSecurityUser);
    }
  }

  onMount(() => {
    void load().catch((error) => {
      message = error instanceof Error ? error.message : 'Load failed';
    });
  });
</script>

<Shell>
  <div class="toolbar">
    <div>
      <h1>Users</h1>
      <p class="status-line">Manage workforce identities for the default organization.</p>
    </div>
    <button class="icon-button" title="Refresh" onclick={load}>
      <RefreshCw size={17} />
    </button>
  </div>

  <UserFilters bind:search bind:statusFilter onApply={load} />

  <UserCreatePanel
    bind:email
    bind:displayName
    bind:password
    {message}
    {previewUrl}
    onCreate={create}
    onInvite={invite}
  />

  <UsersTable
    {users}
    onSetStatus={setStatus}
    onSendEmailVerification={sendEmailVerification}
    onSendPasswordReset={sendPasswordReset}
    onReviewSecurityActivity={loadUserSecurityEvents}
    onReviewBrowserSessions={loadUserSessions}
  />

  <UserSessionsPanel
    selectedUser={selectedSessionUser}
    sessions={userBrowserSessions}
    loading={loadingUserSessions}
    revokingSessionId={revokingUserSessionId}
    onRefresh={reloadSelectedUserSessions}
    onRevoke={revokeUserSession}
  />

  <UserSecurityEventsPanel
    selectedUser={selectedSecurityUser}
    events={userSecurityEvents}
    loading={loadingUserSecurityEvents}
    onRefresh={reloadSelectedUserSecurityEvents}
  />
</Shell>
