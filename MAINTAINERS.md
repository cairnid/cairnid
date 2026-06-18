# Maintainers

This file records project ownership for review and release decisions.

## Current Maintainer Records

- `@ibuuvai`: current maintainer for review, release, and security triage coverage.

CODEOWNERS currently routes all paths to `@ibuuvai`. Move CODEOWNERS to an organization team when the `cairnid` organization has a real maintainer team with the intended repository permissions.

## Responsibilities

Maintainers review and approve changes that affect:

- Authentication, authorization, OIDC/OAuth behavior, sessions, MFA, signing keys, organization isolation, SCIM, audit, and secrets handling.
- Deployment, release evidence, release artifacts, dependency policy, and public release claims.
- Security policy, threat model, release gates, governance, and support documentation.

Maintainers also triage private vulnerability reports, publish draft-reviewed releases, and keep public documentation aligned with implemented behavior.

## Review Coverage

At least one maintainer review is expected for ordinary changes. Security-sensitive changes, release workflow changes, or changes that alter public release readiness should receive maintainer review from someone who did not author the change.

When a maintainer is unavailable, defer release-sensitive decisions rather than weakening a gate or publishing unverifiable claims.

## Adding Or Removing Maintainers

Maintainer changes should be made by pull request. The pull request should explain the reason, update CODEOWNERS only if real GitHub ownership metadata exists, and record any effect on release authority or security triage coverage.
