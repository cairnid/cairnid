<script lang="ts">
  import {
    Ban,
    CheckCircle2,
    KeyRound,
    Lock,
    MailCheck,
    Monitor,
    ShieldCheck
  } from '@lucide/svelte';
  import type { User, UserStatus } from '$lib/api';

  export let users: User[] = [];
  export let onSetStatus: (user: User, status: UserStatus) => void | Promise<void>;
  export let onSendEmailVerification: (user: User) => void | Promise<void>;
  export let onSendPasswordReset: (user: User) => void | Promise<void>;
  export let onReviewSecurityActivity: (user: User) => void | Promise<void>;
  export let onReviewBrowserSessions: (user: User) => void | Promise<void>;
</script>

<section class="panel panel-spaced">
  <table class="data-table responsive-table">
    <thead>
      <tr><th>Email</th><th>Name</th><th>Status</th><th>Verified</th><th>Created</th><th></th></tr>
    </thead>
    <tbody>
      {#each users as user}
        <tr>
          <td data-label="Email">{user.email}</td>
          <td data-label="Name">{user.display_name}</td>
          <td data-label="Status">{user.status}</td>
          <td data-label="Verified">{user.email_verified ? 'Yes' : 'No'}</td>
          <td data-label="Created">{new Date(user.created_at).toLocaleString()}</td>
          <td data-label="">
            <div class="table-actions">
              <button
                class="icon-button"
                title="Activate user"
                disabled={user.status === 'active'}
                onclick={() => onSetStatus(user, 'active')}
              >
                <CheckCircle2 size={17} />
              </button>
              <button
                class="icon-button"
                title="Suspend user"
                disabled={user.status === 'suspended'}
                onclick={() => onSetStatus(user, 'suspended')}
              >
                <Ban size={17} />
              </button>
              <button
                class="icon-button"
                title="Lock user"
                disabled={user.status === 'locked'}
                onclick={() => onSetStatus(user, 'locked')}
              >
                <Lock size={17} />
              </button>
              <button
                class="icon-button"
                title="Send verification email"
                disabled={user.email_verified || user.status !== 'active'}
                onclick={() => onSendEmailVerification(user)}
              >
                <MailCheck size={17} />
              </button>
              <button
                class="icon-button"
                title="Send password reset"
                disabled={user.status !== 'active'}
                onclick={() => onSendPasswordReset(user)}
              >
                <KeyRound size={17} />
              </button>
              <button
                class="icon-button"
                title="Review security activity"
                onclick={() => onReviewSecurityActivity(user)}
              >
                <ShieldCheck size={17} />
              </button>
              <button
                class="icon-button"
                title="Review browser sessions"
                onclick={() => onReviewBrowserSessions(user)}
              >
                <Monitor size={17} />
              </button>
            </div>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</section>
