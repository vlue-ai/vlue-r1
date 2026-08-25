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
