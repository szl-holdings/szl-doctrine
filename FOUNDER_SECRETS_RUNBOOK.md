# Governed Secrets Runbook — `secret-health`

The organization-wide `secret-health` workflow audits whether the exact required
GitHub Actions secret **names** are available to each governed repository. It does
not request, receive, print, hash, measure, or persist secret values.

## Authentication order

The workflow no longer consumes the expired `SECRET_HEALTH_TOKEN` PAT.

1. **Preferred:** a short-lived qillqaq GitHub App installation token requesting
   only repository metadata, repository secret-name read, and organization
   secret-name read.
2. **Governed fallback:** the existing organization `SZL_GITHUB_TOKEN`, used only
   when qillqaq cannot mint the requested least-privilege token.
3. **Fail closed:** if neither machine identity is available or an endpoint cannot
   be enumerated authoritatively, the result is `UNAVAILABLE` rather than
   `MISSING` or a fabricated green state.

The receipt records only the selected source label (`qillqaq-app`,
`governed-fallback`, or `UNAVAILABLE`). It never records token content, prefix,
length, digest, expiration, or other token metadata.

## Versioned policy

Required names are defined in:

`.github/data/required_actions_secrets.json`

The current policy checks:

| Repository | Required name |
|---|---|
| `killinchu` | `HF_WRITE_TOKEN` |
| `a11oy` | `HF_TOKEN` |
| `szl-lake` | `HF_TOKEN` |
| `.github` | `HF_TOKEN` |

A name is `PRESENT` when it is configured directly on the repository or supplied
through an organization secret available to that repository. `MISSING` means the
listing succeeded and the required name was absent. Authentication, permission,
network, pagination, or response-shape failures are `UNAVAILABLE`.

## Evidence and enforcement

Every run:

- compiles and executes the network-free auditor regression suite;
- attempts the App-first identity and governed fallback in that order;
- uploads a 90-day JSON receipt;
- fails for any `MISSING` or `UNAVAILABLE` requirement;
- writes no repository, secret, issue, ruleset, deployment, or external-service
  state.

The workflow runs daily at 06:30 UTC, on manual dispatch, and immediately after a
protected-main change to its policy, implementation, tests, or workflow.

## qillqaq permission upgrade

qillqaq currently may not have the repository and organization secret-name read
permissions requested by the workflow. Granting those permissions to the App and
approving the installation update will move the audit from `governed-fallback` to
`qillqaq-app` without another source change. Until then, the explicit fallback is
the governed path; no replacement PAT should be created.

## Safety boundary

- Never commit a token or private key.
- Never print or serialize a token for diagnostics.
- Never infer that a secret is missing when the API could not be read.
- Rotate a credential through the owning provider if there is evidence its value
  was exposed; this workflow proves presence of names, not credential validity.
