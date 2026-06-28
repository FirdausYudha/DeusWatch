# DeusWatch Security Policy

DeusWatch is a security tool. We take vulnerabilities very seriously and value
responsible reports from the community.

## Supported versions

During the early development phases, only the `main` (latest) branch receives security
fixes. This table will be updated once versioned releases are published.

| Version | Supported |
|---|---|
| `main` (pre-release) | ✅ |

## Reporting a vulnerability

**Do not** open a public GitHub Issue for a security vulnerability.

Instead, use one of these private channels:

1. **GitHub Security Advisory** - the "Report a vulnerability" feature on this repo's
   *Security* tab (the preferred channel).
2. **Email** - `security@deuswatch.example` *(TODO: replace with a real contact before public release)*.

Please include, where possible:

- A description of the vulnerability and its impact.
- Reproduction steps or a proof-of-concept.
- The affected component/file and the version/commit.
- A suggested mitigation (optional).

## What to expect

- **Acknowledgement of receipt** within 72 hours.
- **Initial assessment** within 7 days.
- Regular updates until the issue is resolved.
- Credit to the reporter in the release notes (unless you request anonymity).

## Secure-by-design commitment

These security principles apply from the first commit and are not compromised for convenience:

- **Required mTLS** for all agent-server communication (no plaintext mode, even in dev).
- **RBAC + append-only audit log** from day one.
- **Encrypted secrets** (envelope encryption); never shown in logs, masked in the UI.
- **Parameterized queries** without exception; all incoming logs are treated as hostile data.
- **LLM output is never auto-executed** as a blocking action - log content is a prompt-injection
  vector; recommendations always require human confirmation.
- **Supply chain**: binaries & images are signed (cosign); CI runs `govulncheck`,
  `gosec`, and dependency scanning; an SBOM is generated for each release.

Thank you for helping keep DeusWatch and its users safe.
