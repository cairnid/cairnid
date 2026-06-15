<script lang="ts">
  import { onMount } from 'svelte';
  import { Fingerprint, KeyRound, LogOut, MailCheck, ShieldCheck } from '@lucide/svelte';
  import { z } from 'zod';
  import {
    api,
    apiList,
    browserSessionListSchema,
    browserSessionRevocationSchema,
    deliverySchema,
    type BrowserSession,
    type User,
    type UserConsentGrant,
    userConsentGrantSchema,
    userSchema,
    unknownJson
  } from '$lib/api';
  import { createPasskeyCredential, getPasskeyCredential } from '$lib/webauthn';
  import AuthorizedApplicationsSection from './components/AuthorizedApplicationsSection.svelte';
  import BrowserSessionsSection from './components/BrowserSessionsSection.svelte';
  import MfaDevicesSection from './components/MfaDevicesSection.svelte';
  import PasswordSection from './components/PasswordSection.svelte';
  import RecoveryCodes from './components/RecoveryCodes.svelte';
  import TotpEnrollment from './components/TotpEnrollment.svelte';
  import type { MfaCredential } from './components/types';

  const totpStartSchema = z.object({
    credential_id: z.string(),
    otpauth_url: z.string(),
    secret_base32: z.string()
  });
  const totpConfirmSchema = z.object({
    status: z.string(),
    recovery_codes: z.array(z.string())
  });
  const recoveryCodeRegenerationSchema = z.object({
    status: z.string(),
    recovery_codes: z.array(z.string())
  });
  const passkeyStartSchema = z.object({
    challenge_id: z.string(),
    options: z.unknown(),
    label: z.string()
  });
  const passkeyFinishSchema = z.object({
    status: z.string(),
    credential_id: z.string(),
    label: z.string()
  });
  const mfaCredentialSchema = z.object({
    id: z.string(),
    kind: z.enum(['totp', 'web_authn', 'recovery_code']),
    label: z.string(),
    status: z.string(),
    created_at: z.string(),
    last_used_at: z.string().nullable().optional()
  });
  const mfaCredentialListSchema = z.object({
    credentials: z.array(mfaCredentialSchema),
    recovery_code_count: z.number()
  });
  const webauthnChallengeSchema = z.object({
    challenge_id: z.string(),
    options: z.unknown()
  });
  const reauthenticationResponseSchema = z.object({
    status: z.string(),
    methods: z.array(z.string()).optional(),
    webauthn: webauthnChallengeSchema.nullable().optional()
  }).passthrough();
  const passwordChangeResponseSchema = z.object({
    status: z.literal('changed'),
    sessions_revoked: z.number(),
    access_tokens_revoked: z.number(),
    refresh_tokens_revoked: z.number(),
    account_tokens_consumed: z.number(),
    acr: z.string(),
    amr: z.array(z.string())
  });
  type WebAuthnChallenge = z.infer<typeof webauthnChallengeSchema>;
  type PendingPrivilegedAction =
    | { kind: 'revoke_mfa_credential'; credential: MfaCredential }
    | { kind: 'regenerate_recovery_codes' }
    | { kind: 'change_password' };

  let user: User | null = null;
  let message = 'Loading';
  let previewUrl = '';
  let totpSetup: z.infer<typeof totpStartSchema> | null = null;
  let totpCode = '';
  let recoveryCodes: string[] = [];
  let passkeyLabel = 'Passkey';
  let mfaCredentials: MfaCredential[] = [];
  let recoveryCodeCount = 0;
  let consentGrants: UserConsentGrant[] = [];
  let revokingConsentGrantId: string | null = null;
  let browserSessions: BrowserSession[] = [];
  let revokingBrowserSessionId: string | null = null;
  let pendingPrivilegedAction: PendingPrivilegedAction | null = null;
  let reauthenticationPassword = '';
  let reauthenticationCode = '';
  let reauthenticationWebAuthnChallenge: WebAuthnChallenge | null = null;
  let reauthenticationBusy = false;
  let currentPassword = '';
  let newPassword = '';
  let confirmNewPassword = '';
  let changingPassword = false;

  onMount(async () => {
    try {
      user = await api('/api/v1/session/me', userSchema);
      await Promise.all([loadMfaCredentials(), loadConsentGrants(), loadBrowserSessions()]);
      message = 'Signed in';
    } catch (error) {
      message = error instanceof Error ? error.message : 'Unable to load profile';
    }
  });

  async function logout() {
    await api('/api/v1/session/logout', unknownJson, { method: 'POST', body: '{}' });
    globalThis.location.href = '/login';
  }

  async function requestVerification() {
    previewUrl = '';
    const delivery = await api('/api/v1/session/email-verification/request', deliverySchema, {
      method: 'POST',
      body: '{}'
    });
    previewUrl = delivery.preview_url ?? '';
    message = delivery.preview_url ? 'Verification queued. Development preview link is available.' : 'Verification queued.';
  }

  async function startTotpEnrollment() {
    recoveryCodes = [];
    totpSetup = await api('/api/v1/session/mfa/totp/start', totpStartSchema, {
      method: 'POST',
      body: JSON.stringify({ label: 'Authenticator app' })
    });
    message = 'TOTP enrollment started';
  }

  async function confirmTotpEnrollment() {
    if (!totpSetup) {
      return;
    }
    const response = await api('/api/v1/session/mfa/totp/confirm', totpConfirmSchema, {
      method: 'POST',
      body: JSON.stringify({
        credential_id: totpSetup.credential_id,
        code: totpCode
      })
    });
    recoveryCodes = response.recovery_codes;
    totpSetup = null;
    totpCode = '';
    message = 'TOTP enabled. Store these recovery codes now.';
    await loadMfaCredentials();
  }

  async function enrollPasskey() {
    const started = await api('/api/v1/session/mfa/webauthn/start', passkeyStartSchema, {
      method: 'POST',
      body: JSON.stringify({ label: passkeyLabel })
    });
    const credential = await createPasskeyCredential(started.options);
    const response = await api('/api/v1/session/mfa/webauthn/finish', passkeyFinishSchema, {
      method: 'POST',
      body: JSON.stringify({
        challenge_id: started.challenge_id,
        label: passkeyLabel,
        credential
      })
    });
    message = `${response.label} enabled`;
    await loadMfaCredentials();
  }

  async function loadMfaCredentials() {
    const response = await api('/api/v1/session/mfa/credentials', mfaCredentialListSchema);
    mfaCredentials = response.credentials;
    recoveryCodeCount = response.recovery_code_count;
  }

  async function loadConsentGrants() {
    consentGrants = await apiList(
      '/api/v1/session/consent-grants?status=all',
      userConsentGrantSchema,
      25
    );
  }

  async function loadBrowserSessions() {
    const response = await api('/api/v1/session/browser-sessions', browserSessionListSchema);
    browserSessions = response.sessions;
  }

  async function revokeBrowserSession(session: BrowserSession) {
    if (session.current) {
      message = 'Use sign out to end the current session';
      return;
    }

    revokingBrowserSessionId = session.id;
    try {
      const response = await api(`/api/v1/session/browser-sessions/${session.id}`, browserSessionRevocationSchema, {
        method: 'DELETE'
      });
      browserSessions = browserSessions.filter((candidate) => candidate.id !== response.session_id);
      message = 'Browser session revoked';
    } catch (error) {
      message = error instanceof Error ? error.message : 'Unable to revoke browser session';
    } finally {
      revokingBrowserSessionId = null;
    }
  }

  async function revokeConsentGrant(grant: UserConsentGrant) {
    if (grant.revoked_at || !globalThis.confirm(`Revoke consent for ${grant.client_name}?`)) {
      return;
    }

    revokingConsentGrantId = grant.id;
    try {
      await api(`/api/v1/session/consent-grants/${grant.id}`, unknownJson, {
        method: 'DELETE'
      });
      message = `Consent revoked for ${grant.client_name}`;
      await loadConsentGrants();
    } catch (error) {
      message = error instanceof Error ? error.message : 'Unable to revoke application consent';
    } finally {
      revokingConsentGrantId = null;
    }
  }

  async function revokeMfaCredential(credential: MfaCredential) {
    try {
      await api(`/api/v1/session/mfa/credentials/${credential.id}`, mfaCredentialSchema, {
        method: 'DELETE'
      });
      message = `${credential.label} revoked`;
      clearReauthentication();
      await loadMfaCredentials();
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unable to revoke MFA credential';
      if (errorMessage === 'fresh MFA verification required') {
        beginReauthentication(
          { kind: 'revoke_mfa_credential', credential },
          `Reauthenticate to revoke ${credential.label}`
        );
        return;
      }

      message = errorMessage;
    }
  }

  async function regenerateRecoveryCodes() {
    try {
      const response = await api('/api/v1/session/mfa/recovery-codes/regenerate', recoveryCodeRegenerationSchema, {
        method: 'POST',
        body: '{}'
      });
      recoveryCodes = response.recovery_codes;
      message = 'Recovery codes regenerated. Store these recovery codes now.';
      clearReauthentication();
      await loadMfaCredentials();
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unable to regenerate recovery codes';
      if (errorMessage === 'fresh MFA verification required') {
        beginReauthentication(
          { kind: 'regenerate_recovery_codes' },
          'Reauthenticate to regenerate recovery codes'
        );
        return;
      }

      if (errorMessage === 'active MFA credential required') {
        message = 'Set up an authenticator app or passkey before regenerating recovery codes';
        return;
      }

      message = errorMessage;
    }
  }

  async function changePassword() {
    if (newPassword !== confirmNewPassword) {
      message = 'New passwords do not match';
      return;
    }
    if (newPassword.length < 12) {
      message = 'Password must be at least 12 characters';
      return;
    }

    changingPassword = true;
    try {
      const response = await api('/api/v1/session/password/change', passwordChangeResponseSchema, {
        method: 'POST',
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword
        })
      });
      currentPassword = '';
      newPassword = '';
      confirmNewPassword = '';
      clearReauthentication();
      message = `Password changed. ${response.sessions_revoked} sessions revoked.`;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unable to change password';
      if (errorMessage === 'fresh MFA verification required') {
        beginReauthentication(
          { kind: 'change_password' },
          'Reauthenticate to change password'
        );
        return;
      }

      message = errorMessage;
    } finally {
      changingPassword = false;
    }
  }

  function beginReauthentication(action: PendingPrivilegedAction, nextMessage: string) {
    pendingPrivilegedAction = action;
    reauthenticationPassword = '';
    reauthenticationCode = '';
    reauthenticationWebAuthnChallenge = null;
    message = nextMessage;
  }

  async function retryPendingPrivilegedAction(action: PendingPrivilegedAction) {
    switch (action.kind) {
      case 'revoke_mfa_credential':
        await revokeMfaCredential(action.credential);
        return;
      case 'regenerate_recovery_codes':
        await regenerateRecoveryCodes();
        return;
      case 'change_password':
        await changePassword();
        return;
    }
  }

  async function submitReauthentication(webauthnCredential?: unknown) {
    if (!pendingPrivilegedAction) {
      return;
    }
    reauthenticationBusy = true;
    try {
      const response = await api('/api/v1/session/reauthenticate', reauthenticationResponseSchema, {
        method: 'POST',
        body: JSON.stringify({
          password: reauthenticationPassword,
          mfa_code: reauthenticationCode || undefined,
          webauthn_challenge_id: webauthnCredential ? reauthenticationWebAuthnChallenge?.challenge_id : undefined,
          webauthn_credential: webauthnCredential
        })
      });
      if (response.status === 'mfa_required') {
        reauthenticationWebAuthnChallenge = response.webauthn ?? null;
        message = reauthenticationWebAuthnChallenge
          ? 'Use your passkey or enter an authenticator code'
          : 'Enter your authenticator code';
        return;
      }

      const action = pendingPrivilegedAction;
      reauthenticationPassword = '';
      reauthenticationCode = '';
      reauthenticationWebAuthnChallenge = null;
      await retryPendingPrivilegedAction(action);
    } catch (error) {
      message = error instanceof Error ? error.message : 'Reauthentication failed';
    } finally {
      reauthenticationBusy = false;
    }
  }

  async function completeReauthenticationPasskey() {
    if (!reauthenticationWebAuthnChallenge) {
      return;
    }
    try {
      const credential = await getPasskeyCredential(reauthenticationWebAuthnChallenge.options);
      await submitReauthentication(credential);
    } catch (error) {
      message = error instanceof Error ? error.message : 'Passkey authentication failed';
    }
  }

  function clearReauthentication() {
    pendingPrivilegedAction = null;
    reauthenticationPassword = '';
    reauthenticationCode = '';
    reauthenticationWebAuthnChallenge = null;
  }

  function pendingPrivilegedActionLabel() {
    if (!pendingPrivilegedAction) {
      return 'Reauthenticate';
    }

    switch (pendingPrivilegedAction.kind) {
      case 'revoke_mfa_credential':
        return `Revoke ${pendingPrivilegedAction.credential.label}`;
      case 'regenerate_recovery_codes':
        return 'Regenerate recovery codes';
      case 'change_password':
        return 'Change password';
    }
  }
</script>

<main class="content">
  <section class="panel">
    <div class="brand">
      <KeyRound size={22} />
      <span>Cairn Identity</span>
    </div>
    {#if user}
      <table class="data-table">
        <tbody>
          <tr><th>Email</th><td>{user.email}</td></tr>
          <tr><th>Email verified</th><td>{user.email_verified ? 'Yes' : 'No'}</td></tr>
          <tr><th>Name</th><td>{user.display_name}</td></tr>
          <tr><th>Status</th><td>{user.status}</td></tr>
          <tr><th>User ID</th><td>{user.id}</td></tr>
        </tbody>
      </table>
      <div style="display: flex; gap: 10px; margin-top: 14px; flex-wrap: wrap;">
        <button class="secondary-button" onclick={requestVerification}>
          <MailCheck size={17} />
          <span>Verify email</span>
        </button>
        <button class="secondary-button" onclick={startTotpEnrollment}>
          <ShieldCheck size={17} />
          <span>Set up TOTP</span>
        </button>
        <button class="secondary-button" onclick={enrollPasskey}>
          <Fingerprint size={17} />
          <span>Add passkey</span>
        </button>
        <button class="secondary-button" onclick={logout}>
          <LogOut size={17} />
          <span>Sign out</span>
        </button>
      </div>
      {#if message}
        <p class="status-line">{message}</p>
      {/if}
      {#if previewUrl}
        <p class="status-line"><a href={previewUrl}>{previewUrl}</a></p>
      {/if}
      <PasswordSection
        bind:currentPassword
        bind:newPassword
        bind:confirmNewPassword
        {changingPassword}
        onChangePassword={changePassword}
      />
      <BrowserSessionsSection
        sessions={browserSessions}
        revokingSessionId={revokingBrowserSessionId}
        onRefresh={loadBrowserSessions}
        onRevoke={revokeBrowserSession}
      />
      <AuthorizedApplicationsSection
        grants={consentGrants}
        revokingGrantId={revokingConsentGrantId}
        onRefresh={loadConsentGrants}
        onRevoke={revokeConsentGrant}
      />
      <MfaDevicesSection
        credentials={mfaCredentials}
        {recoveryCodeCount}
        showReauthentication={pendingPrivilegedAction !== null}
        pendingActionLabel={pendingPrivilegedActionLabel()}
        bind:reauthenticationPassword
        bind:reauthenticationCode
        {reauthenticationBusy}
        canUsePasskey={reauthenticationWebAuthnChallenge !== null}
        onRegenerateRecoveryCodes={regenerateRecoveryCodes}
        onRevokeCredential={revokeMfaCredential}
        onSubmitReauthentication={() => submitReauthentication()}
        onCompleteReauthenticationPasskey={completeReauthenticationPasskey}
        onClearReauthentication={clearReauthentication}
      />
      <TotpEnrollment setup={totpSetup} bind:code={totpCode} onConfirm={confirmTotpEnrollment} />
      <RecoveryCodes codes={recoveryCodes} />
    {:else}
      <p class="status-line">{message}</p>
    {/if}
  </section>
</main>
