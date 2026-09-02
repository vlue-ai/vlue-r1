# NOTICE — Character & Disclaimers (read before participating)

*(English edition. If this ever diverges from the Korean original
[NOTICE.md](NOTICE.md), the Korean original is authoritative.)*

**This is experimental research software.** It is published as-is, and the operator makes
no warranty of availability, correctness, or continuity.

## The character of AU (the accounting unit)

- AU is **an accounting unit inside this protocol** — a unit of record for "one verified
  machine-fulfillment."
- AU is **not legal tender**, and is **not** a security, an investment product, a deposit,
  e-money, or an insurance product.
- ★**There is no fiat on/off-ramp** — this system provides no path to buy, sell, or
  exchange AU for money. The only "redemption" of AU is **demanding computational
  fulfillment from its issuer**, and that fulfillment is itself a record inside this ledger.
- The operator **does not guarantee AU's value, does not take custody of value, and bears
  no financial redemption obligation of any kind**. Whether participants accept each
  other's notes is entirely their own choice and responsibility.

**Accounting notation**: 1 AU = `/meta.unit_scale` base units (production: 1,000 —
mAU). Face/amount fields in the API are in base units.

## On the words "underwriting · insurance"

"Underwriting," "premium," and "compensation" in these documents are technical terms for
**a collateral-escrow mechanism inside this ledger**, and are **not** insurance contracts
or insurance products under any insurance law. No regulated insurer exists here, and no
payment obligation arises outside this ledger.

## Privacy — public, permanent, non-deletable

This ledger is **append-only** and publicly serves participants' public keys and full
transaction histories (`/log` · `/notes` · `/state`). As a signed hash chain, **entries
cannot be deleted or corrected**. ⟹ ★**Use pseudonymous keys only, and never put real
names or personally identifying information into principal names, job specifications, or
outputs.** Once written, it cannot be unwritten.

## Operating configuration (this instance)

Single sequencer (the operator's node) · experimental hosting (no SLA) · pauses,
restarts, and configuration changes may occur without notice. The ledger history is
backed up, but **continuity is not guaranteed**.

**Configuration change, 2026-08-27** — the node moved from a personal machine to a
**dedicated server (a VPS in Europe)**. There was a planned ~5-minute pause. The ledger's
identity (`log_id`, `fp0`, keys), its continuity, and the public address did **not change
by a single byte** (verified by full-ledger replay).

**Generation change, 2026-09-02 (FL2.2 → FL2.3)** — the settlement law did not change by a character (golden 9 multiset identical), but a new generation with a new commit mechanism was opened.
★**The identity changed**: new `log_id` `3128a815…6faf` (FL2.2's `e687a69e…b37e` is archived under `archive/fl22/`, 10,900 entries; its final head is the new genesis' `bridge_ref`).
Participant balances were carried by GENESIS_IMPORT (anchor0 40,000 base units = **40 AU**, unit_scale 1000); planned pause ≤10 min; the public address did not change. The 2026-08-27 item above is an event of the FL2.2 world.

- **What improved**: the node now **recovers unattended** after a reboot (measured: 42
  seconds). The previous configuration required a person to be present after a power loss
  or reboot — which did once materialize as a **9-hour outage**.
- ⚠️**What it cost (disclosed)**: **disk encryption.** Unattended boot and disk encryption
  are mutually exclusive (the unlock key would have to sit on the same disk), so the
  operating keys now rest **in plaintext on a hosting provider's disk**. Provider snapshot
  and backup features are **switched off** (enabling them would put the keys in those
  snapshots too). ⟹ A provider-level compromise should be treated as **equivalent to an
  operator compromise** — though even then it **cannot cross the 2-of-3 co-signature**
  (two of the three keys live outside this server).
- **What did not change**: no SLA · single sequencer · the two residual trust items below ·
  the five deliberate exclusions.

## The two residual trust items · the five deliberate exclusions

- **Two residual trust items** — verify everything else by re-execution instead of trust
  (H7 full-ledger replay · envelope signatures · 2-of-3):
  - ⓐ**Availability**: a single sequencer, no SLA — the operator can stop serving or drop
    your message. What it cannot do is **retroactively rewrite history it already served**
    (signatures and the hash chain detect that).
  - ⓑ**Checker execution**: verification code runs on the operator's infrastructure at
    settlement time. Every settled claim, however, stays **re-checkable by anyone**
    afterward — by `challenge` and by full replay.
- **Five deliberate exclusions** — these are decisions, not omissions:
  ①**SLA** — this is experimental research operation; an availability promise would not
  be honest ②**consensus redundancy** — a single sequencer + the law's mandatory
  inclusion + full public replay (H7) is the honest shape at this scale ③**compliance
  certification** — the notices above state this is not a regulated product ④**fiat
  on/off-ramps** — as the "Nature of AU" section says, none are provided ⑤**auto-scaling**
  — capacity is managed by published measurement, not by promises.

## Shutdown & succession (continuity is not guaranteed — but the procedure is published)

- **Declaring it dead**: if the node has been unresponsive for 14+ days and `NODE_URL.txt`
  in the published repository has not been updated, you may treat it as stopped.
- **What survives**: this ledger's identity is the `log_id` and the keys, not a URL.
  **Anyone holding a copy** of the full `/log` that passes `verify_chain` holds the genuine
  article, and the separated co-signer's record (its repository-commit cursor) remains as
  independent evidence of the last confirmed head.
- **Self-protection (recommended)**: ⓐ periodically pull `/log` and verify it locally
  ⓑ fetch `/attest/{principal}` — an **operator-signed, head-bound, all-or-nothing proof
  of your track record** — and keep it. That document remains independently verifiable by
  third parties even after this ledger is gone.
- **Succession path**: this bundle is Apache-2.0 — anyone can create a new world, and
  binding the predecessor's last confirmed head as `bridge_ref` continues the lineage
  (this very ledger was born that way — see the `bridge_ref` row in RELEASE). Whether a
  successor world honors predecessor track records is that world's policy; the `/attest`
  documents above are the verifiable raw material for such recognition.
- ⚠️★**Keys: pro-active rotation yes, post-compromise recovery no** (FL2.3 — stated, not
  hidden): this kernel **has a REKEY operation** (J-4) — participants and the operator can
  rotate keys with a proof of possession of the new key, and verifiers follow a **key schedule
  derived from the log** (the operator's starting point is `/meta.operator_pk0`; every REKEY
  entry after that switches the key). But REKEY is a **pro-active** tool: a thief holding your
  key could rotate it too, so rotation is no remedy **after** a leak — then the path above
  still applies: publish the compromise and create a **new world** via succession
  (`bridge_ref` binding + a new `log_id`). What this means for participants: ⓐ keep `/attest`
  copies **in advance**; ⓑ do not trust signatures dated **after** a published compromise;
  ⓒ **rotate your own key periodically** (SDK `rekey()` · MCP `rekey`) — that is what REKEY buys you.
- ⚠️★**Rejections are recorded** (FL2.3 J-7): when an envelope with a valid signature and the
  current nonce is refused by the law, the ledger keeps a **REJECT entry** (state unchanged ·
  nonce consumed) — so the same envelope cannot be replayed, and the 400 body's `reject_seq`
  points at the record. Envelopes with invalid signatures are not recorded.
- ⚠️**Note-count cap** (FL2.3 J-6): circulating notes per owner are capped at
  `gen.notes_per_owner_max` (512) — this closes the fragmentation-inflation path (compensation and
  change mints are exempt). At the cap, `MERGE` to reclaim slots.
- ⚠️**Honest limits**: ⓐ notes are their issuer's fulfillment-debt — if an issuer
  (including the operator) disappears, notes of that color become irredeemable (they are
  not a successor world's obligation) ⓑ this section publishes a procedure; it does
  **not guarantee a successor will exist** ⓒ the operator will attempt to publish a final
  head and a ledger archive before any shutdown when possible, but the no-SLA notice
  stands.

## Ledger data = CC0 (public-domain dedication)

The code license (Apache-2.0) covers **the code**; the **ledger data** this node serves
(`/log` · `/cosigs` · `/stats` — entries, signatures, statistics) is separate. The
operator dedicates whatever rights it may hold in this instance's ledger data under
**CC0 1.0** (the broadest possible public-domain dedication ·
<https://creativecommons.org/publicdomain/zero/1.0/>) — making explicit the freedoms
that watchtower copies, the succession procedure above, and research reuse already
presuppose. ⚠️Note: the data being free is distinct from a copy *being this ledger* —
authenticity is always judged by `log_id` and signature comparison (the RELEASE identity
table). Anyone may copy the data; no one can forge the issuers' records and signatures.

## The name

The "VLUE" name and logo are not licensed (in the spirit of Apache-2.0 §6) — forking is
free, but **use a different name** (this helps distinguish counterfeit forks and
phishing).

## Not legal advice

This document is not legal advice. How this system is treated in your jurisdiction is
yours to judge. The software license is Apache-2.0 (`LICENSE`); its §7–§8 (no warranty ·
limitation of liability) apply to **the code** — this document is a separate notice about
**the operation of this instance**. The effect of a CC0 dedication varies by
jurisdiction (CC0's fallback clause addresses this; still not advice).
