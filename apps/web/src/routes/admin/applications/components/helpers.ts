import type { ConsentGrantMode, ConsentPolicyTemplate, OidcClient } from '$lib/api';

const CLAIMS_BY_SCOPE: Record<string, string[]> = {
  openid: ['sub'],
  profile: ['name'],
  email: ['email', 'email_verified'],
  groups: ['groups']
};

export function claimPreview(scopes: string[]): string[] {
  const claims = new Set<string>();
  for (const scope of scopes) {
    for (const claim of CLAIMS_BY_SCOPE[scope] ?? []) {
      claims.add(claim);
    }
  }
  return [...claims];
}

export function grantModeLabel(mode: ConsentGrantMode) {
  switch (mode) {
    case 'required_once':
      return 'Required once';
    case 'always_required':
      return 'Always required';
  }
}

export function policyLabelForClient(
  client: OidcClient,
  templates: ConsentPolicyTemplate[]
) {
  const template = templates.find(
    (candidate) => candidate.id === client.consent_policy_template_id
  );
  return template ? `${template.name} (${grantModeLabel(template.grant_mode)})` : 'Required once';
}
