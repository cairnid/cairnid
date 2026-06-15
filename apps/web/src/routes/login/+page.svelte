<script lang="ts">
  import { goto } from '$app/navigation';
  import { Fingerprint, KeyRound, LogIn, UserPlus } from '@lucide/svelte';
  import { z } from 'zod';
  import { api } from '$lib/api';
  import { localRedirectPath } from '$lib/navigation';
  import { getPasskeyCredential } from '$lib/webauthn';

  const loginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(1),
    mfa_code: z.string().optional(),
    webauthn_challenge_id: z.string().optional(),
    webauthn_credential: z.unknown().optional()
  });

  const bootstrapSchema = loginSchema.extend({
    display_name: z.string().min(1),
    setup_secret: z.string().optional()
  });

  const webauthnLoginChallengeSchema = z.object({
    challenge_id: z.string(),
    options: z.unknown()
  });

  const loginResponseSchema = z.object({
    status: z.string().optional(),
    methods: z.array(z.string()).optional(),
    webauthn: webauthnLoginChallengeSchema.nullable().optional()
  }).passthrough();

  let email = '';
  let password = '';
  let totpCode = '';
  let displayName = '';
  let setupSecret = '';
  let message = '';
  let mfaRequired = false;
  let webauthnChallenge: z.infer<typeof webauthnLoginChallengeSchema> | null = null;
  let busy = false;

  const params = new URLSearchParams(globalThis.location?.search ?? '');
  const returnTo = localRedirectPath(params.get('return_to'), '/admin');

  async function submitLogin(webauthnCredential?: unknown) {
    busy = true;
    message = '';
    try {
      const payload = loginSchema.parse({
        email,
        password,
        mfa_code: totpCode || undefined,
        webauthn_challenge_id: webauthnCredential ? webauthnChallenge?.challenge_id : undefined,
        webauthn_credential: webauthnCredential
      });
      const response = await api('/api/v1/session/login', loginResponseSchema, {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      if (response.status === 'mfa_required') {
        mfaRequired = true;
        webauthnChallenge = response.webauthn ?? null;
        message = webauthnChallenge
          ? 'Use your passkey or enter an authenticator code'
          : 'Enter your authenticator code';
        return;
      }
      globalThis.location.href = returnTo;
    } catch (error) {
      message = error instanceof Error ? error.message : 'Login failed';
    } finally {
      busy = false;
    }
  }

  async function completePasskeyLogin() {
    if (!webauthnChallenge) {
      return;
    }
    try {
      const credential = await getPasskeyCredential(webauthnChallenge.options);
      await submitLogin(credential);
    } catch (error) {
      message = error instanceof Error ? error.message : 'Passkey authentication failed';
    }
  }

  async function submitBootstrap() {
    busy = true;
    message = '';
    try {
      const payload = bootstrapSchema.parse({
        email,
        password,
        mfa_code: undefined,
        webauthn_challenge_id: undefined,
        webauthn_credential: undefined,
        display_name: displayName || email,
        setup_secret: setupSecret || undefined
      });
      await api('/api/v1/bootstrap', loginResponseSchema, {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      await submitLogin();
    } catch (error) {
      message = error instanceof Error ? error.message : 'Bootstrap failed';
    } finally {
      busy = false;
    }
  }
</script>

<main class="content" style="display: grid; min-height: 100vh; place-items: center;">
  <section class="panel" style="width: min(440px, 100%);">
    <div class="brand">
      <KeyRound size={24} />
      <span>Cairn Identity</span>
    </div>

    <div class="form-grid" style="grid-template-columns: 1fr;">
      <div class="field">
        <label for="email">Email</label>
        <input id="email" bind:value={email} autocomplete="email" />
      </div>
      <div class="field">
        <label for="display-name">Display name</label>
        <input id="display-name" bind:value={displayName} autocomplete="name" />
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input id="password" bind:value={password} type="password" autocomplete="current-password" />
      </div>
      <div class="field">
        <label for="setup-secret">Setup secret</label>
        <input id="setup-secret" bind:value={setupSecret} type="password" autocomplete="off" />
      </div>
      {#if mfaRequired}
        <div class="field">
          <label for="totp-code">Authenticator or recovery code</label>
          <input id="totp-code" bind:value={totpCode} inputmode="numeric" autocomplete="one-time-code" />
        </div>
        {#if webauthnChallenge}
          <button class="secondary-button" disabled={busy} onclick={completePasskeyLogin}>
            <Fingerprint size={17} />
            <span>Use passkey</span>
          </button>
        {/if}
      {/if}
    </div>

    <div style="display: flex; gap: 10px; margin-top: 16px; flex-wrap: wrap;">
      <button class="primary-button" disabled={busy} onclick={() => submitLogin()}>
        <LogIn size={17} />
        <span>Sign in</span>
      </button>
      <button class="secondary-button" disabled={busy} onclick={submitBootstrap}>
        <UserPlus size={17} />
        <span>Bootstrap first admin</span>
      </button>
    </div>
    <p class="status-line"><a href="/reset-password">Reset password</a></p>

    {#if message}
      <p class="status-line">{message}</p>
    {/if}
  </section>
</main>
