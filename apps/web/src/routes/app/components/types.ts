export type MfaCredential = {
  id: string;
  kind: 'totp' | 'web_authn' | 'recovery_code';
  label: string;
  status: string;
  created_at: string;
  last_used_at?: string | null;
};

export type TotpSetup = {
  credential_id: string;
  otpauth_url: string;
  secret_base32: string;
};
