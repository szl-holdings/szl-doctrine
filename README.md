<!-- szl-investor-header -->
<div align="center">

# szl-doctrine

### The published source for SZL's locked governance doctrine and repository-scoped guard definitions.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](LICENSE) [![Naming canon](https://github.com/szl-holdings/szl-doctrine/actions/workflows/naming-canon.yml/badge.svg?branch=main)](https://github.com/szl-holdings/szl-doctrine/actions/workflows/naming-canon.yml) [![Doctrine v11](https://img.shields.io/badge/Doctrine-v11_LOCKED-3b82f6?style=flat-square)](https://github.com/szl-holdings/.github/tree/main/doctrine) [![SLSA](https://img.shields.io/badge/SLSA-L1_honest-22c55e?style=flat-square)](https://slsa.dev/spec/v1.0/levels)

[Docs](https://szl-holdings.github.io/docs-site) · [Quickstart](https://szl-holdings.github.io/docs-site/quickstart) · [SZL Holdings](https://a-11-oy.com)

</div>

## 💡 Why it matters

It publishes the locked doctrine contract, a repository-local naming guard, and workflow callers
for overclaim and DCO checks. Downstream repositories must adopt and pass their own checks; this
repository does not prove estate-wide compliance by itself.

## Choose your route

| Audience | Start here | What this repository can establish |
|----------|------------|------------------------------------|
| **Investor** | [What it pins](#what-it-pins) and [Honesty boundary](#honesty-boundary) | The published governance contract and explicit non-claims |
| **Developer** | [Inspect locally](#inspect-locally) and [How a downstream repo consumes it](#how-a-downstream-repo-consumes-it) | The tracked canon and repository-scoped guard and workflow-caller definitions |
| **Evaluator** | [`NAMING_CANON.md`](NAMING_CANON.md), [`CITATION.cff`](CITATION.cff), and [workflow runs](https://github.com/szl-holdings/szl-doctrine/actions) | Source artifacts and recorded CI outcomes; not downstream adoption or deployment |

## KANCHAY evidence states

- **LIVE**: a workflow or runtime result observed at a named source and time.
- **SAMPLE**: example content that is not execution evidence.
- **SIMULATED**: mocked or synthetic execution.
- **UNAVAILABLE**: a source or check cannot return a usable result; preserve the reason.

This repository is a static governance contract, not a product runtime. Its tracked files are
source evidence; GitHub Actions results are execution evidence only for the commit they name.

## ▶️ Live demo

_This is a **public** governance & automation repository — it has no product demo surface of its own. See [docs.szlholdings.com](https://szl-holdings.github.io/docs-site) for the public product walkthrough._

## Inspect locally

```bash
git clone https://github.com/szl-holdings/szl-doctrine.git
cd szl-doctrine
git show HEAD:NAMING_CANON.md
git ls-tree -r --name-only HEAD .github/workflows
```

These commands inspect the canon and the available guard definitions. They do not claim that a
workflow ran, that downstream repositories adopted the contract, or that a product deployed.

## 🔍 How it works

This repository tracks governance constants and CI guard definitions; it does not run product
policy or mint receipts. Product implementations own those runtime behaviors. The mathematical
foundation, formal proofs, and protocol details are documented below and in the
[technical docs](https://szl-holdings.github.io/docs-site).

---

<details>
<summary><strong>📐 Full technical detail, math, and proofs (the proof, not the pitch)</strong></summary>

# szl-doctrine — the published governance contract and repository checks

`szl-doctrine` is the published source for the locked version downstream SZL repositories may
adopt. Its checks and workflow callers evaluate this repository; they do not establish adoption
or enforcement elsewhere. The tracked contract is deliberately small and auditable.

## What it pins

| Constant | Value | Why it is frozen |
|---|---|---|
| Doctrine version | **v11 LOCKED** | the published security/compliance contract |
| Locked kernel commit | [`c7c0ba17`](https://github.com/szl-holdings/lutar-lean/commit/c7c0ba17) | the exact Lean 4 kernel state the locked numbers were measured against |
| Locked numbers | **749 declarations / 14 unique axioms / 163 sorries** | a frozen contract — never edited to track live corpus drift |
| Λ status | **Conjecture 1 (NOT a theorem)** | unconditional uniqueness is machine-checked *false*; only conditional uniqueness is proven |
| Section 889 | exactly **5** banned vendors (Huawei, ZTE, Hytera, Hikvision, Dahua) | no inflation, no omission |
| Supply chain | **SLSA L1 honest**; L2 verified-provenance on roadmap | L3 / FedRAMP / Iron Bank / CMMC are **never** claimed |

> The *locked* numbers are a contract and do not move. The **experimental `main` corpus**
> (≈1323 decls / 23 axioms / CI-green) is reported **separately** and is **never folded into
> the 8 locked-proven formulas** {F1, F4, F7, F11, F12, F18, F19, F22}.

## What it automates

- **Naming-canon check** (`.github/workflows/naming-canon.yml`) — repository-local enforcement
  for the tracked public naming contract.
- **Doctrine overclaim caller** (`.github/workflows/overclaim-guard.yml`) — invokes the org's
  reusable guard from mutable `main`; a run records the resolved remote logic at execution time,
  but this repository does not pin that logic in its own tree.
- **DCO caller** (`.github/workflows/dco.yml`) — invokes the reusable DCO check at an immutable
  revision for pull requests into `main`; a passing run establishes trailers for that pull request,
  not for downstream repositories.

## How a downstream repo consumes it

Product repos reference the locked constants in their README footers and `/healthz` payloads.
When the doctrine is re-locked at a new version, the constants are bumped **here first**, then
propagated; nothing downstream invents its own numbers.

## Honesty boundary

- Λ uniqueness is **Conjecture 1** — the unconditional claim is *false* by machine-checked
  counterexample; only the conditional CUT-2 slice-multiplicativity uniqueness
  (`lambda_unique_of_separable`, axiom-free, 0 sorry) is proven.
- Locked-proven PURIQ formulas = **exactly 8** {F1, F4, F7, F11, F12, F18, F19, F22}; the rest are roadmap.
- **No fabricated metrics, no inflated proof counts, no L2/L3/FedRAMP/Iron Bank/CMMC claims.**

## Limitations

- This repository has no product demo, service endpoint, package build, or deployment surface.
- A workflow definition is not a successful run; use the commit-specific Actions result as evidence.
- Presence of the contract here does not prove estate-wide adoption. Each downstream repository
  must expose its own pinned reference and passing checks.
- Product walkthroughs and responsive public documentation are owned by the
  [active docs site](https://szl-holdings.github.io/docs-site/), not duplicated here.

</details>

## External release boundary

`External release boundary` is doctrine-owned merge authorization for the six
allowlisted Hugging Face publisher repositories. Target pull requests and merge
groups are evaluated by protected doctrine code at the exact required-workflow
source revision. The boundary does not check out or execute target candidate
code; it reads authoritative repository, pull-request, Git tree, and blob data
through the GitHub API with read-only metadata, contents, and pull-request
permissions.

The manifest at `.github/release-boundary/manifest.json` is authoritative. An
`ACTIVE` entry fixes the complete workflow path set and SHA-256 bytes for each
workflow and every file in the secret-bearing publisher closure. Public data is
outside that closure only when the fixed publisher cannot execute it on the CI
host. A `PENDING` entry always fails closed. Refreshing a target requires a
reviewed doctrine change recording one immutable candidate SHA and every exact
hash, followed by exact-target verification.

The stable required checks are `Release boundary enforcement` for pull requests
and `Release boundary merge-group continuation` for merge queues; the
event-inapplicable job is skipped. Passing either check means only that the exact
candidate is authorized for merge under the recorded external boundary. It is
not evidence that a protected-main publisher ran, that Hugging Face accepted a
mutation, or that a public Space serves the candidate revision.

<!-- szl-doctrine-footer -->

---

### Citation & doctrine

Cite this work via [`CITATION.cff`](CITATION.cff). Math foundations: [szl-papers](https://github.com/szl-holdings/szl-papers) · [lutar-lean](https://github.com/szl-holdings/lutar-lean) (kernel `c7c0ba17`).

<sub>Λ Conjecture 1 (not a theorem) · 749/14/163 v11 LOCKED (kernel `c7c0ba17`) · SLSA L1 honest · Section 889 = 5 vendors · [SZL Holdings](https://a-11-oy.com) · Apache-2.0 code · CC-BY-4.0 papers</sub>
