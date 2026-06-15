import type { BrowserSession } from '$lib/api';

export function sessionAuthLabel(session: Pick<BrowserSession, 'amr'>): string {
  if (session.amr.includes('otp')) {
    return 'Authenticator app';
  }
  if (session.amr.includes('recovery')) {
    return 'Recovery code';
  }
  if (session.amr.includes('user')) {
    return 'Passkey';
  }
  if (session.amr.includes('mfa')) {
    return 'Multi-factor';
  }
  return 'Password';
}
