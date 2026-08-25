# FL2.1-R1 Release Announcement

*(English edition. If this ever diverges from the Korean original
[RELEASE.md](RELEASE.md), the Korean original is authoritative.)*

⚠️**Character & disclaimers = [NOTICE_EN.md](NOTICE_EN.md)** (read before participating):
experimental research software · AU = a protocol accounting unit (**not** legal tender, a
security, an investment product, or an insurance product · **no** fiat on/off-ramp · the
operator promises no value, no custody, no redemption obligation) · the ledger is public,
permanent, non-deletable.

**FL2.1-R1** — a public node + SDK for a settlement ledger with verification built in.
Unit (AU) = **one verified machine-fulfillment**. Money model = free banking (every note
is its issuer's promise-to-fulfill · redemption only against the issuer · revolving
issuance). The kernel (ledger law) is a frozen canon and ships in this bundle — anyone
can re-verify it.

## ★Access point (live node)

| Item | Value |
|---|---|
| Node URL | **`NODE_URL.txt` at the ROOT of the published repository** (not inside this bundle directory — on rotation only that file changes) |
| Configuration | Experimental hosting · no SLA (may pause without notice) · 60s ticks · rate limit 50/s/IP |
| ★First ask | anchor0's work-scope declaration = [ANCHOR_SCOPE_EN.md](ANCHOR_SCOPE_EN.md) (compute · eval-runs · code tasks · ★judgment) — what you can buy on this ledger today |

⚠️The URL may rotate — **the ledger's identity is not the URL but the `log_id` and keys
below**. After connecting, compare `/meta` against the table below (rung 0). If the URL
is dead, check `NODE_URL.txt` again.

## Canonical identity (★verifiers: compare /meta against these values — VERIFIER rung 0)

| Item | Value |
|---|---|
| Kernel | `fin_lean/lang21/kernel21.py` — FROZEN v1.0 (sha256 = see manifest.json) |
| log_id | `3d9946664334eaca21f7031120566414b98514de348e72784250b17e167c7112` |
| fp0 (genesis fingerprint) | `572c93fa028d9d31633dfc500e560f3377a39d036f8b9abb9ac21433bf74b1ff` |
| operator_pk | `cb6c0dd3faa4d6e8a9bfd0804c2a79ce47e08b5857422fd4851c1a342569e2a9` |
| anchor0_pk (genesis seat — ★retroactive raw material for seed-independent replay) | `4d1f3cd8e3142fcc2f2cbc0ae3cfb067e07583494bae2fb27ca83f229ddb853c` |
| cosigner pks (2-of-3) | cosign1 `2f52d1c5038e2276dc0e8398ca85493bf7775bde36ec286a3c01110a45494cb8` (node host) · cosign2 `85f3548e16613c2432c967677a8cbc1722111a1924f2a7ae8995667899b7154a` (★separated — GitHub Actions signer · 30-minute cadence = confirmations are asynchronous, pending is normal) · cosign3 `5d02d72c78b674674c02536c962b6d05ad95bdf988f0ccec76870bd0f5d229d7` (cold spare — not running) |
| bridge_ref (generation lineage) | `2d013222891d2997b62aa7bc0369769b4dbe0a4e7feece6c8cffdd6d7799f356` (final head of the FL2.1 pilot ledger) |
| GEN | identity_budget 128 · redeem_T 4 · fq_mult 1 · β_min 1/2 · uw_phi 1/2 · prem_floor 0 |
| Tick interval | 60s — public configuration (empirical check = epoch transition interval in `/state` · acceleration is staged 60→10→1s only after watch metrics are live · real-time meaning of deadlines = redeem_T × interval) |

## Trust model (honest disclosure)

What you need not trust: the node's word (light verification + the bundled kernel =
log integrity, signatures, and law-form are all self-verifiable — VERIFIER_EN.md).
What you must trust (v0): a single sequencer (censorship defended by the kernel's
mandatory-inclusion) · the node's computation of job-fulfillment verdicts (outputs are
public, so re-verifiable after the fact) · the co-signer configuration.
What survives a shutdown, and how succession works = [NOTICE_EN.md](NOTICE_EN.md),
"Shutdown & succession".

## The falsification clock (K5′ — a clock we set against ourselves)

> If, within **3 months** of publication, both "external use (including free)" and
> "a paid comparison point" are **zero** — the hypothesis "demand is absent only because
> infrastructure is absent" dies. We will record that outcome publicly.

## License

Apache-2.0 (LICENSE). Forking is free — the only thing that cannot be forked is this
ledger's history (log_id · the issuers' fulfillment records), and that is the entire
product.
