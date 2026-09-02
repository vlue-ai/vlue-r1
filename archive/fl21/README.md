# FL2.1 production ledger — archive (lineage)

This is the complete, final FL2.1 production ledger (log_id
`3d9946664334eaca21f7031120566414b98514de348e72784250b17e167c7112` · 3,225 entries ·
final head `42b4f7dab9be7175790247c9013c076e68a91ddf5632aa05637c7639f89fbdb5`).
That final head is bound as `bridge_ref` in the FL2.2 (itself retired on 2026-09-02 — see `../fl22/`; the live generation is FL2.3) genesis (see RELEASE) —
the lineage is verifiable, not asserted.

To re-audit: `kernel21.py` + `kernel21_selftest.py` are included; the entries/cosigs
files replay against kernel21 exactly as the live ledger replays against kernel22.
Ledger data: CC0 (see NOTICE).
