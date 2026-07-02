# NAMING_CANON.md — the canonical SZL glossary

> **Single source of truth for what every SZL codename means.** If a name appears
> in a README, a diagram, or a commit message and you are not sure what it does,
> this file is the authority. One row per codename: plain-English role + the repo
> that owns it.

## What is SZL?

**Governed AI you can prove — every decision comes with a signed, verifiable receipt, built on public data, running on your own hardware.**

SZL Holdings builds a governed-AI mesh: a set of small, auditable components that
run AI workloads under explicit policy and emit tamper-evident, independently
verifiable receipts for every action. The flagship surface is **a11oy**, the
Command Center that operators actually look at; everything else is a governed
organ that plugs into it. Names below are Quechua/Andean codenames (khipu, amaru,
yarqa, killinchu, hatun, puriq) chosen for the project's "knotted-cord
record-keeping" metaphor — the glossary maps each back to its plain role so a
stranger isn't lost.

## Glossary

| Codename | Plain-English role | Repo |
|---|---|---|
| **a11oy** | Flagship **Command Center** — the operator-facing console that ties the mesh together (dashboards, control, receipt review). | `a11oy` |
| **szl-router** | **Sovereign, OpenAI-compatible LLM gateway** — routes inference to models/hardware and attaches a signed provenance receipt per answer. | `szl-router` |
| **david-leads** | **Lead-generation / outbound product** built on the Command Center. | `david-leads` |
| **killinchu** | **Governed data/ingest product** built on the Command Center (Quechua: *kestrel*). | `killinchu` |
| **anatomy** | **Codebase/system anatomy product** — structural mapping and inspection, built on the Command Center. | `anatomy` |
| **ouroboros** | **Bounded agent runtime** — runs agents under hard limits/policy; home of the Λ spec (`docs/lambda-spec.md`). | `ouroboros` |
| **khipu** / **khipu-consensus** | **Witnessed consensus + receipts** — the knotted-cord record: multi-witness agreement that produces verifiable receipts (Quechua: *khipu*, an Andean recording cord). | `khipu` / `khipu-consensus` |
| **yarqa** | **Compartmentalization** — isolation/segmentation boundaries between organs (Quechua: *irrigation channel*). | `yarqa` |
| **amaru** | **Governed networking / boundary guard** organ (Quechua: *serpent*). | `amaru` |
| **hatun-mcp** | **Governed MCP server** — a Model Context Protocol server that exposes tools under policy (Quechua: *hatun* = great/large). | `hatun-mcp` |
| **szl-lake** | **Receipt store** — the durable lake where emitted receipts are persisted and queried. | `szl-lake` |
| **Λ** / **lambda-gate** | **Non-compensatory scoring gate** — the Lutar Invariant Λ used as an advisory score. **Conjecture 1 (advisory)**, not a theorem. | `szl-lambda-gate` |
| **vsp-otel** | **Observability / OpenTelemetry** integration — verifiable signal/telemetry plumbing for the mesh. | `vsp-otel` |
| **doctrine v11** | The **locked governance contract** — the doctrine version every repo builds against, with frozen numbers (749/14/163), locked kernel commit `c7c0ba17`, and honest SLSA L1 posture. | `szl-doctrine` (pinned in `.github/doctrine`) |

### Supporting terms

| Term | Plain-English role | Repo / location |
|---|---|---|
| **szl-receipt** | Shared **signing library** — DSSE/ECDSA-P256 envelopes for receipts; keyless = UNSIGNED-honest (never fabricates a signature). | `szl-receipt` |
| **lean-kernel** / **lutar-lean** | **Machine-checked proof kernel** — the Lean 4 formalization of the Lutar Invariant Λ that anyone can re-run. | `lean-kernel` / `lutar-lean` |
| **puriq** | The **formula set** governed by doctrine (Quechua: *to walk/proceed*); exactly **8** locked-proven formulas {F1, F4, F7, F11, F12, F18, F19, F22}. | `szl-doctrine` / `szl-papers` |

## Honesty boundary (carried from doctrine v11)

- **Λ is Conjecture 1 (advisory), not a theorem.** The unconditional uniqueness claim is
  machine-checked *false*; only the conditional CUT-2 slice-multiplicativity uniqueness is proven.
- **Keyless = UNSIGNED-honest.** A receipt without a signing key is marked unsigned; a signature
  is never fabricated.
- **Sovereign = true only for owned hardware.** No inflated provenance labels.
- **No fabricated metrics; SLSA L1 honest** (L2 on roadmap; L3 / FedRAMP / Iron Bank / CMMC are never claimed).

---

<sub>Canonical one-liner: **"Governed AI you can prove — every decision comes with a signed, verifiable receipt, built on public data, running on your own hardware."** · Λ Conjecture 1 (advisory) · doctrine v11 LOCKED · [SZL Holdings](https://a11oy.net) · Apache-2.0</sub>
