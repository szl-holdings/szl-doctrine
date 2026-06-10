# Founder Secrets Runbook — `secret-health` workflow

This runbook explains the **one founder action** required to make the org-wide
`secret-health` check (`.github/workflows/secret-health.yml`) go green.

## What `secret-health` does
- Runs daily (06:30 UTC) + on manual dispatch.
- For every **active (non-archived)** `szl-holdings` repo, it checks whether the
  repo has the **required Actions secrets** defined by the in-workflow
  `REQUIRED` policy.
- It reports secret **NAMES** and **PRESENT / MISSING** status only. It **never**
  prints secret values — the GitHub API does not return secret values, and the
  job is designed so a leak is structurally impossible here.
- Honesty over checklist: a missing required secret (or a missing audit token)
  is surfaced as a **failed check**, never a silent green.

## Why it is currently RED (root cause + status)
1. **Workflow parse bug (FIXED).** The guard step previously used
   `if: ${{ secrets.SECRET_HEALTH_TOKEN == '' }}`. `secrets.*` is **not** a valid
   named-value in a step-level `if:` expression, so GitHub Actions rejected the
   workflow with `Unrecognized named-value: 'secrets'` and the whole run failed
   to parse (no steps ran). This has been fixed by mapping the secret into `env`
   and testing it in the step's shell. The gate behavior is unchanged.
2. **Missing audit token (FOUNDER ACTION — open).** After the parse fix, the
   workflow runs correctly and now fails *honestly* at the guard step because the
   org secret **`SECRET_HEALTH_TOKEN` is not provisioned**. The audit cannot read
   per-repo Actions secrets without it.

## Founder action to make it green
Create an **organization-level Actions secret** named `SECRET_HEALTH_TOKEN`.

### Token requirements (fine-grained PAT or GitHub App installation token)
- Resource owner: **szl-holdings** organization, all repositories (or all active repos).
- Repository permissions:
  - **Secrets: Read**
  - **Administration: Read** (needed to list per-repo secrets)
  - **Metadata: Read** (implicit)

### Steps
1. Create a fine-grained PAT (GitHub → Settings → Developer settings →
   Fine-grained tokens) scoped to `szl-holdings` with the permissions above,
   **or** install a GitHub App with equivalent permissions and use its token.
2. Org → Settings → Secrets and variables → Actions → **New organization secret**.
3. Name: `SECRET_HEALTH_TOKEN`. Value: the token from step 1.
4. Repository access: **All repositories** (or the active set).
5. Re-run the `secret-health` workflow (Actions → secret-health → Run workflow).

Once provisioned, the guard passes and the audit step runs, producing a
PRESENT/MISSING table per repo. If that table then shows any **MISSING** required
secret, those are *real* gaps to remediate (add the named secret to that repo) —
again a founder action, never auto-fabricated.

## Notes
- Never commit any token/private key to the repo. The PAT lives only as an org secret.
- This workflow is a **presence audit**, not a secret scanner; it is unrelated to
  gitleaks/`gitleaks.yml`, which scans committed content for leaked values.
