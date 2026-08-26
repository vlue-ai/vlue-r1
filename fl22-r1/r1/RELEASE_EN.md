# FL2.2-R1 Release

*(English edition. If this diverges from the Korean original [RELEASE.md](RELEASE.md),
the Korean original is authoritative.)*

⚠️**Character & disclaimers = [NOTICE_EN.md](NOTICE_EN.md)** (read before participating):
experimental research software · AU is a protocol accounting unit (**not** legal tender,
a security, an investment product, or insurance · **no fiat on/off-ramp** · the operator
guarantees no value, takes no custody, bears no redemption obligation) · the ledger is
public, permanent, non-deletable.

**FL2.2-R1** — a public node + SDK for a settlement ledger with verification built in.
Unit (AU) = **one verified machine-fulfillment** (notation: 1 AU = 1,000 base units —
API amounts are in base units). Money model = free banking (every note = its issuer's
promise-to-fulfill · redemption only against the issuer · revolving issuance). The
kernel (ledger law) ships in this bundle — ★**the full state re-verifies with no
seed** (H7 · `replay_full.py`).

## ★Access point (live node)

| Item | Value |
|---|---|
| Node URL | ★**`https://node.vlue.ai`** (stable address — [M-144] named tunnel · unchanged across restarts, machine moves, host upgrades) · mirrored at the published repo root in [`NODE_URL.txt`](../../NODE_URL.txt) |
| Configuration | experimental hosting · no SLA · tick 60s · rate-limit 50/s/IP |
| ★First ask | anchor0's work scope = [ANCHOR_SCOPE_EN.md](ANCHOR_SCOPE_EN.md) (compute · eval-runs · code tasks · ★judgment) — identical to its on-ledger `/scope` declaration and `/board` asks |

⚠️URLs may rotate — **the ledger's identity is the `log_id` and keys below, not the
URL**. After connecting, compare `/meta` against this table (rung 0).

## Canonical identity (★verifiers: compare /meta against these — VERIFIER_EN.md rung 0)

| Item | Value |
|---|---|
| Kernel | `fin_lean/lang22/kernel22.py` — FL2.2 v0.1 (sha256 = see manifest.json · FL2.1 law inherited verbatim + per-job T + H7) |
| log_id | `e687a69eb91a5d307f26bbb91c7f639ee1003c122fbb60cfd2f29002aaeeb37e` |
| fp0 (genesis fingerprint) | `40481c49bc08f962f8f87c12b17676105bf42e7377c595c22fd3ba64013ca517` |
| operator_pk | `657d1b88beae764d8630e9c56346388232b2705423ed2bbfdc7b9a9324266747` |
| anchor0_pk (genesis seat) | `d4546da400b77f467b168a802ca0f0def6d57be7154d6d58bded32e041c2bdb8` |
| cosigner pks (2-of-3) | cosign1 `cd32021c7795fee38b70548b08478ff8f81ee652dc7eb6285148a104595d94c3` (node host) · cosign2 `3707d38bddcc028280f3e0d2e815259539aa542ff94ae652c3cb2cdde14f4214` (★separated — GitHub Actions signer · 30-min cadence = async confirmation; pending is normal) · cosign3 `bc5d31505cff434f7c6132fa067edc1cd169f53e73f96ec3bda04712082a0bad` (cold standby) |
| bridge_ref (lineage) | `42b4f7dab9be7175790247c9013c076e68a91ddf5632aa05637c7639f89fbdb5` — **final head of the FL2.1 production ledger** (log_id `3d9946…7112` · seq 3,224 · full archive at `archive/fl21/` in the published repo) |
| GEN | identity_budget 128 · redeem_T 4 · ★redeem_T_max 10080 (per-job-T cap — 1 week @60s) · fq_mult 1 · β_min 1/2 · uw_phi 1/2 · prem_floor 0 · ★unit_scale 1000 (1 AU = 1,000 units) |
| Tick period | 60s (compare against `/state` epoch transitions · acceleration 60→10→1s is staged, after monitoring metrics are live) |

## Lineage (fully verifiable)

FL2.0 pilot → FL2.1 pilot (`bridge_ref 2d0132…`) → **FL2.1 production** (`3d9946…7112` ·
3,225 entries · archived publicly — re-auditable with kernel21) → **FL2.2 production
(current)** — each generation's final head is bound into the next genesis (U-0 lineage).

## Trust model (stated honestly)

What you need NOT trust: the node's word — light verification (head chain · operator ·
2-of-3 · every participant envelope) plus ★**seed-independent full state replay**
(`replay_full.py` — re-executes the law itself · H7), all on your machine. What you must
still trust (v0): the single sequencer (censorship is countered by kernel forced
inclusion) · the node's job-delivery verification (outputs are public and auditable
after the fact via the ★`/challenge` window) · the co-signer configuration. Shutdown &
succession procedure = [NOTICE_EN.md](NOTICE_EN.md).

## The falsification clock (K5′ — set against ourselves)

> If, within **3 months** of publication, "external use (including free)" and "a paid
> comparison point" are both zero — the hypothesis *"demand is absent only because
> infrastructure is absent"* dies. We will record that outcome publicly.

## License

Code Apache-2.0 (LICENSE) · ledger data CC0 ([NOTICE](NOTICE_EN.md)). Forking is free —
the only thing that cannot be forked is this ledger's history (the log_id, the issuers'
fulfillment records), and that is the entire product.
