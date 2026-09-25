# Lean count review - September 24, 2026 EDT

**Status: DRAFT / REVIEW REQUIRED. This is not a doctrine release or a new proof total.**

The historical locked doctrine citation remains **749 declarations / 14 axioms / 163 tracked sorries**. This proposal changes none of those locked values, no proof assumptions, and no release authority. The observations below use different predicates and must not be substituted for that citation.

## Original proposal retained in history

The original proposal at `0e16a68ec15a3c4cc815666dfa5f0dd48f5f2ad5` claimed 14 unique declarations from extracted compiler warnings for job `107858425790`, with a heuristic 12/2 classification. The displayed extract contains truncated/misdecoded warning and script text, not a complete source-bound declaration census. Neither completeness nor equivalence to the locked tracked-sorry predicate has been established. The number 14 is therefore an **unqualified diagnostic-subset claim**, not an admitted organization-wide or repository-wide total.

Byte-identical duplicate PR #70 was consolidated into retained PR #69. Original commits and discussions remain available. Do not use the duplicate's existence as a second independent measurement.

## Exact candidate-scoped observation

The separate, source-owned `lean_numbers.measured.json` artifact was downloaded from GitHub and independently checked against GitHub's archive digest. Its original bytes are preserved in [the evidence record](evidence/lean_numbers.a4cc7c4f.json).

- Source repository: `szl-holdings/lutar-lean`.
- Candidate PR: #291, head `f01b4d60fc4bd186f2f041bc31ef8908c16b1722`.
- Tested base: `f2105589ea61769cc46ff4a31a8442dfd05476e5`.
- Actual checkout and artifact SHA: `a4cc7c4f826b52bc15d25aa3ea427870da9d7526`, the prospective PR integration, **not an admitted main revision** at observation.
- Measurement time: `2026-09-25T01:24:17Z` / September 24, 9:24:17 p.m. EDT.
- Workflow run: [36081727641](https://github.com/szl-holdings/lutar-lean/actions/runs/36081727641); producing job: `107904956134`.
- Artifact ID: `10841434806`; archive name: `lean-numbers-a4cc7c4f826b52bc15d25aa3ea427870da9d7526`.
- Archive SHA-256: `3a2b7c644516bd0ee41b75c2008a0c27b6c3be95be6b5c4d2aacb734427dbd5e`.
- Measured JSON SHA-256: `d1c69e8379475a2f7cf2e1c487be059bdc2ceed0d8f6ecaf8efd24f4a35a1b19`.
- Measured JSON Git blob: `4ca3f37e1de815b1cc4f205f2c393d1e3220f910` (1,230 bytes).
- Toolchain observed in the producing build: Lean `v4.18.0`; Mathlib revision `aa936c36e8484abd300577139faf8e945850831a`.
- Archived `lake-manifest.json` SHA-256: `8a2baa1ece45f2f69b96ad872f6d50c0dc03f49f173da0946eb43a91ad1e46c5`.

The ZIP also contains the committed `.github/data/lean_numbers.json`, whose embedded identity is an older pending sampler snapshot. That separate member is **not** the measured candidate record and was not substituted for `lean_numbers.measured.json`.

## Predicate and observed values

The implementation is [the counter at the exact candidate](https://github.com/szl-holdings/lutar-lean/blob/f01b4d60fc4bd186f2f041bc31ef8908c16b1722/.github/scripts/lean_numbers.py), Git blob `126af6cd5f554705bfec8621aeb0dcddb437c80f`. Its `iter_lean_files` scans `Lutar/` plus `Main.lean`, excluding paths matched by its explicit `EXPERIMENTAL_SCOPES`. This is not every Lean file in the repository or every imported Mathlib declaration.

| Artifact field | Value | Actual meaning |
| --- | ---: | --- |
| `declarations` | 1401 | Lines matched by the counter's fixed declaration regex. Not a count of proved theorems. |
| `axioms_raw` | 26 | Lines matched by the fixed axiom-declaration regex. |
| `axioms_unique` | 25 | Distinct names extracted by that regex. Not a proof trust-base certification. |
| `sorries_raw` | 319 | Word-boundary `sorry` tokens within the included file scope. Includes comment/documentation occurrences. |
| `sorries_noncomment` | 266 | Tokens after excluding pure `--` lines only. Block comments, inline comments, and strings are not parsed away; this must not be called a declaration or live-proof-obligation count. |
| `sorries_putnam` | 56 | Raw token occurrences in included paths under `Putnam/`. |
| `sorries_baseline` | 263 | Raw token occurrences in other included paths. Despite the field name, this is not the historical locked tracked-sorry figure. |

The raw path split reconciles: `56 + 263 = 319`. This does not make the other predicates interchangeable. A successful build can also contain explicitly tracked proof placeholders outside separately guarded scopes; build success is not a repository-wide proof-completeness certificate.

## Acceptance before any doctrine update

First define the intended denominator and distinguish lexical tokens, compiler diagnostics, unique declarations, transitive axiom dependencies, experimental scopes, and the historical locked baseline. Bind any new declaration-level census to an admitted source revision, complete enumeration, toolchain, dependency manifest, extraction implementation, and immutable evidence. Reconcile its identities against the governed theorem registry and explain changes rather than comparing unlike counts.

The record above remains a dated candidate observation even if newer source is subsequently merged. It must not be retimestamped or presented as a current-main census. No locked doctrine update, general conjecture closure, runtime guarantee, model qualification, or public-domain deployment is authorized by this document.
