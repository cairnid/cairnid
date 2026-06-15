## Summary

-

## Checks

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo check --workspace --locked`
- [ ] `cargo test --workspace --locked`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo deny check`
- [ ] `cargo audit`
- [ ] `bun install --frozen-lockfile`
- [ ] `bun run audit`
- [ ] `bun run check:public-surface`
- [ ] `bun run check`
- [ ] `bun run test`
- [ ] `bun run build`
- [ ] `bun run test:e2e`

## Security and Compatibility

- [ ] No secrets, tokens, private keys, cookies, or sensitive release evidence were committed.
- [ ] Authentication, authorization, OIDC/OAuth, SCIM, MFA, cookies, sessions, audit, or deployment behavior changed.
- [ ] `docs/threat-model.md` was updated when trust boundaries, assets, controls, or residual risks changed.
- [ ] Dependency, threat-model, release-gate, or operations docs were updated when relevant.

## Notes

-
