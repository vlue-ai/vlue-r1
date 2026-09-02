# FL2.1 production ledger — archive (lineage)

This is the complete, final FL2.1 production ledger (log_id
`3d9946664334eaca21f7031120566414b98514de348e72784250b17e167c7112` · 3,225 entries ·
final head `42b4f7dab9be7175790247c9013c076e68a91ddf5632aa05637c7639f89fbdb5`).
That final head is bound as `bridge_ref` in the FL2.2 (itself retired on 2026-09-02 — see `../fl22/`; the live generation is FL2.3) genesis (see RELEASE) —
the lineage is verifiable, not asserted.

To re-verify: recompute the head chain and check the operator signature and co-signatures over
`entries.jsonl`/`cosigs.jsonl` (3,225 entries · final head `42b4f7da…`). `kernel21.py` + `kernel21_selftest.py`
are included for reference, but ⚠️kernel21 has no seed-free public replay API (`audit()` rebuilds the world from the
genesis seed), so a full law replay of FL2.1 is not possible from public material — unlike FL2.2 (`../fl22/`, kernel22
`from_public`). ★Co-signature coverage (honesty): the last entry confirmed by 2-of-3 is seq 3,164; entries 3,165–3,224
(60 operator TICKs) carry only cosign1. The FL2.2 `bridge_ref` binds the final head (seq 3,224).
Ledger data: CC0 (see NOTICE).
