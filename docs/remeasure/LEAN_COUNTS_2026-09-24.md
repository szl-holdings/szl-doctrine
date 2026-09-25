# Lean count re-measurement - 2026-09-24

Locked doctrine v11 states 749 declarations / 14 axioms / 163 tracked sorries.

## Measured (lutar-lean main, CI job 107858425790, lake build strict)

- Unique declarations using sorry (Lean compiler warnings, deduplicated): **14**
- Heuristic triage: {"PROOF_CANDIDATE":12,"ADVISORY_CONJECTURE":2}

## Count lines reported by the CI job

~~~text
955405Z warning: ././././Lutar/Innovations/round5/OuroLoopInputLipschitz.lean:88:0: automatically included section variable(s) unused in theorem 'Lutar.Innovations.Round5.InputLipschitz.InputContraction.contractingWith':
ld (whole library ΓÇö strict)	2026-09-24T22:21:25.5145118Z warning: ././././Lutar/Wave8/DensityMixture.lean:50:0: automatically included section variable(s) unused in theorem 'Lutar.Wave8.DensityMixture.posSemidef_smul':
ild (whole library ΓÇö strict)	2026-09-24T22:21:25.5149776Z warning: ././././Lutar/Wave8/DensityMixture.lean:63:0: automatically included section variable(s) unused in theorem 'Lutar.Wave8.DensityMixture.posSemidef_sum':
ole library ΓÇö strict)	2026-09-24T22:21:25.5153996Z warning: ././././Lutar/Wave8/DensityMixture.lean:84:0: automatically included section variable(s) unused in theorem 'Lutar.Wave8.DensityMixture.density_mixture_trace':
ake build (whole library ΓÇö strict)	2026-09-24T22:21:25.5171009Z warning: ././././Lutar/Wave8/LambdaMono.lean:49:0: automatically included section variable(s) unused in theorem 'Lutar.Wave8.LambdaMono.prod_strict_mono':
umbers	lake build (whole library ΓÇö strict)	2026-09-24T22:21:25.5174555Z warning: ././././Lutar/Wave8/LambdaMono.lean:57:0: automatically included section variable(s) unused in theorem 'Lutar.Wave8.LambdaMono.prod_pos':
trict)	2026-09-24T22:21:25.5197057Z warning: ././././Lutar/Wave9/CovarianceIntersection.lean:65:0: automatically included section variable(s) unused in theorem 'Lutar.Wave9.CovarianceIntersection.PosSemidef.nonneg_smul':
3Z warning: ././././Lutar/Wave24/AdmissibilityCertificate.lean:92:2: The namespace 'AdmissibilityCertificate' is duplicated in the declaration 'Lutar.Wave24.AdmissibilityCertificate.AdmissibilityCertificate.faulty_bound'
4747596Z warning: ././././Lutar/Wave24/AdmissibilityCertificate.lean:90:2: The namespace 'AdmissibilityCertificate' is duplicated in the declaration 'Lutar.Wave24.AdmissibilityCertificate.AdmissibilityCertificate.faulty'
1:26.4751557Z warning: ././././Lutar/Wave24/AdmissibilityCertificate.lean:86:2: The namespace 'AdmissibilityCertificate' is duplicated in the declaration 'Lutar.Wave24.AdmissibilityCertificate.AdmissibilityCertificate.f'
4755343Z warning: ././././Lutar/Wave24/AdmissibilityCertificate.lean:96:2: The namespace 'AdmissibilityCertificate' is duplicated in the declaration 'Lutar.Wave24.AdmissibilityCertificate.AdmissibilityCertificate.honest'
759268Z warning: ././././Lutar/Wave24/AdmissibilityCertificate.lean:88:2: The namespace 'AdmissibilityCertificate' is duplicated in the declaration 'Lutar.Wave24.AdmissibilityCertificate.AdmissibilityCertificate.charter'
.4763064Z warning: ././././Lutar/Wave24/AdmissibilityCertificate.lean:94:2: The namespace 'AdmissibilityCertificate' is duplicated in the declaration 'Lutar.Wave24.AdmissibilityCertificate.AdmissibilityCertificate.votes'
26.4766983Z warning: ././././Lutar/Wave24/AdmissibilityCertificate.lean:84:10: The namespace 'AdmissibilityCertificate' is duplicated in the declaration 'Lutar.Wave24.AdmissibilityCertificate.AdmissibilityCertificate.mk'
21:26.4770669Z warning: ././././Lutar/Wave24/AdmissibilityCertificate.lean:84:10: The namespace 'AdmissibilityCertificate' is duplicated in the declaration 'Lutar.Wave24.AdmissibilityCertificate.AdmissibilityCertificate'
070917Z warning: ././././Lutar/Innovations/round5/OuroLoopInputLipschitz.lean:88:0: automatically included section variable(s) unused in theorem 'Lutar.Innovations.Round5.InputLipschitz.InputContraction.contractingWith':
reference-vectors executables	2026-09-24T22:21:49.7254399Z warning: ././././Lutar/Wave8/DensityMixture.lean:50:0: automatically included section variable(s) unused in theorem 'Lutar.Wave8.DensityMixture.posSemidef_smul':
 reference-vectors executables	2026-09-24T22:21:49.7258871Z warning: ././././Lutar/Wave8/DensityMixture.lean:63:0: automatically included section variable(s) unused in theorem 'Lutar.Wave8.DensityMixture.posSemidef_sum':
nce-vectors executables	2026-09-24T22:21:49.7262884Z warning: ././././Lutar/Wave8/DensityMixture.lean:84:0: automatically included section variable(s) unused in theorem 'Lutar.Wave8.DensityMixture.density_mixture_trace':
heck + reference-vectors executables	2026-09-24T22:21:49.7282924Z warning: ././././Lutar/Wave8/LambdaMono.lean:49:0: automatically included section variable(s) unused in theorem 'Lutar.Wave8.LambdaMono.prod_strict_mono':
rs	Run check + reference-vectors executables	2026-09-24T22:21:49.7287545Z warning: ././././Lutar/Wave8/LambdaMono.lean:57:0: automatically included section variable(s) unused in theorem 'Lutar.Wave8.LambdaMono.prod_pos':
tables	2026-09-24T22:21:49.7314988Z warning: ././././Lutar/Wave9/CovarianceIntersection.lean:65:0: automatically included section variable(s) unused in theorem 'Lutar.Wave9.CovarianceIntersection.PosSemidef.nonneg_smul':
2Z warning: ././././Lutar/Wave24/AdmissibilityCertificate.lean:92:2: The namespace 'AdmissibilityCertificate' is duplicated in the declaration 'Lutar.Wave24.AdmissibilityCertificate.AdmissibilityCertificate.faulty_bound'
6949820Z warning: ././././Lutar/Wave24/AdmissibilityCertificate.lean:90:2: The namespace 'AdmissibilityCertificate' is duplicated in the declaration 'Lutar.Wave24.AdmissibilityCertificate.AdmissibilityCertificate.faulty'
1:50.6951756Z warning: ././././Lutar/Wave24/AdmissibilityCertificate.lean:86:2: The namespace 'AdmissibilityCertificate' is duplicated in the declaration 'Lutar.Wave24.AdmissibilityCertificate.AdmissibilityCertificate.f'
6953590Z warning: ././././Lutar/Wave24/AdmissibilityCertificate.lean:96:2: The namespace 'AdmissibilityCertificate' is duplicated in the declaration 'Lutar.Wave24.AdmissibilityCertificate.AdmissibilityCertificate.honest'
955433Z warning: ././././Lutar/Wave24/AdmissibilityCertificate.lean:88:2: The namespace 'AdmissibilityCertificate' is duplicated in the declaration 'Lutar.Wave24.AdmissibilityCertificate.AdmissibilityCertificate.charter'
.6957367Z warning: ././././Lutar/Wave24/AdmissibilityCertificate.lean:94:2: The namespace 'AdmissibilityCertificate' is duplicated in the declaration 'Lutar.Wave24.AdmissibilityCertificate.AdmissibilityCertificate.votes'
50.6959183Z warning: ././././Lutar/Wave24/AdmissibilityCertificate.lean:84:10: The namespace 'AdmissibilityCertificate' is duplicated in the declaration 'Lutar.Wave24.AdmissibilityCertificate.AdmissibilityCertificate.mk'
21:50.6960984Z warning: ././././Lutar/Wave24/AdmissibilityCertificate.lean:84:10: The namespace 'AdmissibilityCertificate' is duplicated in the declaration 'Lutar.Wave24.AdmissibilityCertificate.AdmissibilityCertificate'
lake build + numbers	Run check + reference-vectors executables	2026-09-24T22:21:53.0513247Z Axioms: A1 monotone, A2 homogeneous, A3 Egyptian-exact, A4 bounded
lake build + numbers	Run check + reference-vectors executables	2026-09-24T22:21:53.0514762Z Theorem 2 (bound): see Lutar/Bound.lean
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	∩╗┐2026-09-24T22:21:54.6854372Z ##[group]Run set -euo pipefail
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6854735Z ^[[36;1mset -euo pipefail^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6855099Z ^[[36;1m# The Theorem-U pack must stay a sound REDUCTION: NO new declared axiom^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6855594Z ^[[36;1m# token, NO proof placeholder, and the kernel-emitted axioms of its^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6856085Z ^[[36;1m# headline results must lie in the Lean/Mathlib trust base only.^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6856756Z ^[[36;1mDIR=Lutar/Uniqueness^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6857223Z ^[[36;1mtest -d "$DIR" || { echo "::error::$DIR missing"; exit 1; }^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6857647Z ^[[36;1m^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6858024Z ^[[36;1m# (1) No `axiom` declaration anywhere in the pack (line-start token).^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6858737Z ^[[36;1mif grep -rnE '^[[:space:]]*(private[[:space:]]+)?axiom[[:space:]]' "$DIR"; then^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6859466Z ^[[36;1m  echo "::error::Theorem-U pack declares an axiom token ΓÇö forbidden"; exit 1^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6859952Z ^[[36;1mfi^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6860222Z ^[[36;1m^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6860570Z ^[[36;1m# (2) No proof placeholders (whole-word) anywhere in the pack.^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6861138Z ^[[36;1mif grep -rnwE '(sorry|admit)' "$DIR"; then^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6861751Z ^[[36;1m  echo "::error::Theorem-U pack contains a proof placeholder ΓÇö forbidden"; exit 1^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6862668Z ^[[36;1mfi^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6862942Z ^[[36;1m^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6863379Z ^[[36;1m# (3) Kernel truth: compile the axiom-hygiene ledger and assert that^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6863925Z ^[[36;1m#     NONE of the Theorem-U declarations pulls in `sorryAx` (which is^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6864360Z ^[[36;1m#     how Lean surfaces an unproven `sorry` in `#print axioms`).^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6864871Z ^[[36;1mlake env lean "$DIR/AxiomCheck.lean" 2>&1 | tee /tmp/axiomcheck.out theorem_u_axiomcheck.out^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6865356Z ^[[36;1mif grep -q 'sorryAx' /tmp/axiomcheck.out; then^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6865781Z ^[[36;1m  echo "::error::#print axioms reports sorryAx in the Theorem-U pack"; exit 1^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6866145Z ^[[36;1mfi^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6866622Z ^[[36;1mecho "axiom-hygiene gate OK: Theorem-U pack is axiom-clean + placeholder-free"^[[0m
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6904379Z shell: /usr/bin/bash -e {0}
lake build + numbers	Axiom-hygiene gate (Theorem-U pack, Lutar/Uniqueness/)	2026-09-24T22:21:54.6904689Z ##[endgroup]
~~~

## Files quoting 749/14/163

- CITATION.cff
- NAMING_CANON.md
- README.md
- SECURITY.md

## Proposal

Re-derive the tracked-sorry figure from Lean compiler warnings and publish doctrine v11.1 through the normal review path. This PR changes no locked numbers.
