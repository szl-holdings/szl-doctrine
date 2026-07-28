# Governed Secrets Runbook

The organization-wide GitHub Actions secret-name audit is owned by the
`szl-holdings/.github` control plane.

Canonical source paths:

- `.github/workflows/secret-health.yml`
- `.github/data/required_actions_secrets.json`
- `.github/scripts/secret_health.py`
- `.github/scripts/test_secret_health.py`

The former `szl-doctrine/.github/workflows/secret-health.yml` lane is retired. It
depended on a long-lived `SECRET_HEALTH_TOKEN` PAT that expired and must not be
restored.

## Authentication contract

The central control tries a short-lived qillqaq GitHub App installation token
first, requesting only repository and organization `Secrets: read`. Until that
installation permission upgrade is approved, it uses the existing governed
`SZL_GITHUB_TOKEN` from the organization control-plane repository.

The fallback was exercised successfully on July 27, 2026. It reported all four
current required names present and zero unavailable or missing requirements.

## Evidence boundary

GitHub's listing endpoints return secret names and timestamps, not encrypted
values. The control records only:

- repository;
- required secret name;
- `PRESENT`, `MISSING`, or `UNAVAILABLE` state;
- the machine-identity source label.

It never requests, receives, prints, hashes, measures, or stores a secret value,
token value, token prefix, token length, token digest, expiration, or other token
metadata.

## Fail-closed semantics

- `PRESENT`: authoritative listing succeeded and the name exists directly or via
  an organization secret available to the repository.
- `MISSING`: authoritative listing succeeded and the required name is absent.
- `UNAVAILABLE`: no governed machine identity exists or the API could not be read
  authoritatively.

Authorization or network failure is never relabeled as a missing secret and never
produces a fabricated green state.

## Operator rules

- Do not create another long-lived replacement PAT for this audit.
- Do not restore the retired Doctrine workflow.
- Approve qillqaq's read-only Secrets permission upgrade when organizationally
  appropriate; no source change is required afterward.
- Rotate a credential through its owning provider only when there is evidence its
  value was exposed. Name presence does not prove credential validity.
