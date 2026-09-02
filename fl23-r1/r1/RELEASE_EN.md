# FL2.3-R1 Release

*(English edition. If this diverges from the Korean original [RELEASE.md](RELEASE.md),
the Korean original is authoritative.)*

⚠️**Character & disclaimers = [NOTICE_EN.md](NOTICE_EN.md)** (read before participating):
experimental research software · AU is a protocol accounting unit (**not** legal tender,
a security, an investment product, or insurance · **no fiat on/off-ramp** · the operator
guarantees no value, takes no custody, bears no redemption obligation) · the ledger is
public, permanent, non-deletable.

**FL2.3-R1** — a public node + SDK for a settlement ledger with verification built in (FL2.3 = FL2.2 settlement law inherited verbatim + eight "form of completion" deltas — section below).
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
| ★First ask | anchor0's work scope = [ANCHOR_SCOPE_EN.md](ANCHOR_SCOPE_EN.md) (compute · eval-runs · code tasks · ★judgment) — identical to its on-ledger scope declaration (read it at `/stats.scopes`) and `/board` asks |

⚠️URLs may rotate — **the ledger's identity is the `log_id` and keys below, not the
URL**. After connecting, compare `/meta` against this table (rung 0).

## Canonical identity (★verifiers: compare /meta against these — VERIFIER_EN.md rung 0)

| Item | Value |
|---|---|
| Kernel | `fin_lean/lang23/kernel23.py` — **FL2.3 v0.2** (sha256 = manifest.json `kernel_sha256` · FL2.2 settlement law inherited verbatim [golden 9 multiset-identical = machine proof] + 8 deltas · ★v0.2 [M-217] = a performance patch only [`exited` set index] — settlement law, schema and root formula **semantically unchanged**: the shipped `kdiff_check.py` replays two ledgers recorded by v0.1 [coverage fixture 56 entries · production snapshot 1,106 entries] through the current kernel and re-derives every head and state_root **byte-identically** [T-KDIFF]) · archive verifier `fin_lean/lang22/kernel22.py` shipped alongside (`kernel22_sha256`) |
| log_id | `3128a815d8657e0624eb91b81a1dec621cc7674cc7e9e677159268f83e0a6faf` |
| fp0 (genesis fingerprint) | `994c73da8ceb854adbd40a602e0fa2253bd5c2c0057037e58fbaff9d1fa45cea` |
| operator_pk | `175399ae2c7d52d869eac0d709c619b00174c02785120ad0746ec8a54c68a4bd` — ★FL2.3: this value = `/meta.operator_pk0` (the genesis key = your verification starting point and the bundle's manifest-signing key); after a REKEY, `/meta.operator_pk` (current) differs and the key schedule is derived from the log |
| anchor0_pk (genesis seat) | `cd0aff94664e9509763179eeeff6628138fb58adb2c556bebf73e2b93d649d3e` |
| cosigner pks (2-of-3) | cosign1 `cd32021c7795fee38b70548b08478ff8f81ee652dc7eb6285148a104595d94c3` (node host) · cosign2 `3707d38bddcc028280f3e0d2e815259539aa542ff94ae652c3cb2cdde14f4214` (★separated — GitHub Actions signer · 30-min schedule, **best-effort**: the scheduler skips roughly half of its runs, so 2-of-3 confirmation is asynchronous and lags of ~100 entries have been observed; the operator dispatches it manually · pending is normal) · cosign3 `bc5d31505cff434f7c6132fa067edc1cd169f53e73f96ec3bda04712082a0bad` (cold standby — not yet active) |
|  bridge_ref (lineage) | `3274433e7d57a9aaaca42c9c44919bd9f71be2d6dc190d7f56685f28f480cdfd` — **final head of the FL2.2 production ledger** (FL2.2 log_id `e687a69eb91a5d307f26bbb91c7f639ee1003c122fbb60cfd2f29002aaeeb37e` · full archive at `archive/fl22/` · re-verifiable forever with kernel22) · ★Honesty ([M-209]): this head (seq 10,899) carries the operator's and cosign1's (node-host) signatures only; the **last 2-of-3 confirmed head is seq 10,762 `005a5035…`** — the 137-entry tail is all operator TICKs (no balance change), so the imported state is identical (`archive/fl22/README`). |
| ★genesis_head (seq 0) | `5a387eea3aecf6ed86f94f77dc32fb39cacabafeb97e15459c641c3f8a1ebb49` — head of the GENESIS_IMPORT entry (log_id/fp0 do not commit to genesis **content**; this value pins which genesis · cold-read 4 F07) |
| ★snapshot_hash (genesis import) | `acf1f24e71ba37daaf9d6ac9db0949063bf42f91cf3eab4b25f05876f3361844` — hash of the FL2.2 archive's final state (anchor0 40,000 · F 0 · F_uw 0 · exited 0) in J-11 form · re-derivable by replaying `archive/fl22` |
| GEN | identity_budget 128 · redeem_T 4 · redeem_T_max 10080 (per-job-T cap — 1 week @60s) · fq_mult 1 · β_min 1/2 · uw_phi 1/2 · prem_floor 0 · unit_scale 1000 (1 AU = 1,000 units) · ★**notes_per_owner_max 512** (FL2.3 J-6 — per-owner circulating-note cap, voluntary mints only) |
| Tick period | 60s (compare against `/state` epoch transitions · acceleration 60→10→1s is staged, after monitoring metrics are live) |

## Lineage (fully verifiable)

FL2.0 pilot → FL2.1 pilot (`bridge_ref 2d0132…`) → **FL2.1 production** (`3d9946…7112` ·
3,225 entries · archived publicly — head chain, operator signature and co-signatures are re-verifiable by anyone · ⚠️a law replay needs the genesis seed, since kernel21 has no seed-free public replay API) → **FL2.2 production** (log_id `e687a69eb91a5d307f26bbb91c7f639ee1003c122fbb60cfd2f29002aaeeb37e` · archived at `archive/fl22/` · re-auditable with kernel22) → **FL2.3 production (current)** — each generation's final head is bound into the next genesis (U-0 lineage). FL2.3 genesis imports the predecessor's balances in its first entry (★**GENESIS_IMPORT**, J-11 — this time only anchor0's self-IOU: a succession rehearsal).

## ★What FL2.3 changed (the "form of completion" — the law closes over scale, adversaries, key lifetime, consistency)

| Delta | What | What it means for verifiers and participants |
|---|---|---|
| J-5 incremental state | Commits are O(change) (journal · bucketed root · owner index) — write cost independent of note count (measured 200k vs 100 notes = 0.93×) | Responses stay flat as the ledger grows · the `state_root` definition changed (new generation) |
| J-6 state cap | Circulating notes per owner ≤ 512 (voluntary mints) — blocks fragmentation inflation; compensation/change mints are exempt | At the cap you get `note_cap` (MERGE to reclaim slots) |
|  J-7 authenticated rejections | A rejected envelope with a valid signature and current nonce becomes a **REJECT entry** on the ledger (state unchanged · nonce consumed) | The same envelope cannot be replayed · 400 bodies carry `code` and `reject_seq` · verifiers re-derive every REJECT · ★[M-208] **Recording budget**: 16 REJECT rows per principal per 60-epoch window — beyond it the failure is rolled back in a savepoint and answered as an **unrecorded 400** (`code: reject_budget`, nonce not consumed; honest ops still pass). |
| J-4 REKEY | Participants and the operator can pro-actively rotate keys (proof of possession of the new key) | Verification starts from `/meta.operator_pk0`; later keys come from the log itself |
| J-8 schema | Per-op required fields and shape bounds are law | Malformed shape = unrecorded rejection · extension fields (spec_sha256 …) stay opaque |
| J-3 living cap | identity_budget counts living principals (EXIT frees the slot) · names are never reused | — |
| J-9 mint ids | Settlement results name compensation/return/change note ids | Color attribution moves from heuristic to direct reference |
| J-11 GENESIS_IMPORT | Succession snapshot imported in the first entry — the next generation carries participant balances losslessly | — |

## Trust model (stated honestly)

What you need NOT trust: the node's word — light verification (head chain · operator ·
2-of-3 · every participant envelope) plus ★**seed-independent full state replay**
(`replay_full.py` — re-executes the law itself · H7), all on your machine. What you must
still trust (v0): the single sequencer (censorship is countered by kernel forced
inclusion) · the node's job-delivery verification (outputs are public and auditable
after the fact via the ★`/challenge` window) · the co-signer configuration. Shutdown &
succession procedure = [NOTICE_EN.md](NOTICE_EN.md).

## Measurement (the public data page)

> External use, fills and supply-side availability are published at vlue.ai/data as figures re-derived from the ledger — the tape starts empty and operator self-dealing is excluded by rule.

## License

Code Apache-2.0 (LICENSE) · ledger data CC0 ([NOTICE](NOTICE_EN.md)). Forking is free —
the only thing that cannot be forked is this ledger's history (the log_id, the issuers'
fulfillment records), and that is the entire product.
