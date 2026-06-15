import { describe, expect, it } from 'vitest';
import { sessionAuthLabel } from './session-labels';

describe('sessionAuthLabel', () => {
  it('prefers specific MFA method labels over generic MFA', () => {
    expect(sessionAuthLabel({ amr: ['pwd', 'mfa', 'otp'] })).toBe('Authenticator app');
    expect(sessionAuthLabel({ amr: ['pwd', 'mfa', 'recovery'] })).toBe('Recovery code');
    expect(sessionAuthLabel({ amr: ['pwd', 'mfa', 'user'] })).toBe('Passkey');
  });

  it('labels generic MFA and password-only sessions', () => {
    expect(sessionAuthLabel({ amr: ['pwd', 'mfa'] })).toBe('Multi-factor');
    expect(sessionAuthLabel({ amr: ['pwd'] })).toBe('Password');
  });
});
