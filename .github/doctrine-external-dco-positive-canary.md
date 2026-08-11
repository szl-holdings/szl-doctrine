# External Doctrine DCO controller positive canary

This evidence-only change exercises organization ruleset `20678558` in
Evaluate mode against the protected controller shipped by
`szl-holdings/.github` at exact commit
`265f9f55aaaf2c478fbd72e9545784b2237b545b`.

The canary is accepted only when the candidate commit is signature-verified,
contains an exact author-matching `Signed-off-by` trailer, the external
controller binds source and target identities, and the existing Doctrine gates
remain independently present.

This file introduces no runtime, deployment, secret, provider, or policy
mutation. It may be merged only after the Evaluate and collision canaries have
completed successfully and the new rule has been activated without bypass
actors.
