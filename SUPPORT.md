# Support

Cairn Identity is an open-source project in pre-beta development. Support channels should keep operational, security, and product questions separated so reports are handled safely.

## Before Filing

Check the [RC compatibility and support matrix](docs/release-gates.md#rc-compatibility-and-support-matrix) before opening an issue. It lists the first-RC boundary, required evidence, public install paths, and features that are explicitly unsupported.

Kubernetes is a custom, unsupported deployment target until a Helm/Kubernetes package and release evidence exist. Reports from Kubernetes are useful when they identify a Cairn bug, but maintainers cannot treat a custom cluster setup as a supported deployment surface yet.

## Questions and Usage

Open a repository issue for questions and usage reports. GitHub Discussions are not enabled for this repository. Include:

- The version or commit you are running.
- Deployment target: local, Docker Compose, custom Kubernetes, or another container environment.
- Sanitized configuration names and command output.
- What you expected and what happened.

Do not include passwords, bearer tokens, authorization codes, private keys, database URLs, cookies, or release evidence that contains provider secrets.

## Bugs

Use the bug report issue template. Include reproduction steps, relevant logs with secrets removed, and whether the issue affects authentication, authorization, audit, provisioning, deployment, or UI behavior.

## Security

Do not open public issues for vulnerabilities. Use GitHub private vulnerability reporting as described in [SECURITY.md](SECURITY.md).
