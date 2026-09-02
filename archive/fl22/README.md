# FL2.2 production ledger — archive (lineage)

This is the complete, final FL2.2 production ledger (log_id
`e687a69eb91a5d307f26bbb91c7f639ee1003c122fbb60cfd2f29002aaeeb37e` · 10,900 entries · final head
`3274433e7d57a9aaaca42c9c44919bd9f71be2d6dc190d7f56685f28f480cdfd` · final epoch 10898). That final head is bound as
`bridge_ref` in the FL2.3 genesis (see RELEASE) — the lineage is verifiable, not asserted (see the co-signature note below).

Re-verify it forever with the FL2.2 kernel shipped here (no secret needed — H7):

```
python3 - <<'PY'
import json, sys; sys.path.insert(0, ".")
from kernel22 import World
m = json.load(open("meta-genesis.json"))
w = World.from_public({"operator": m["operator_pk"], **m["genesis_pks"]}, m["label"], tuple(m["genesis"]), gen=dict(m["gen"]), bridge_ref=m.get("bridge_ref"))
print(w.replay_verify([json.loads(l) for l in open("entries.jsonl")]))
PY
```

Files: `entries.jsonl` (ledger) · `cosigs.jsonl` (2-of-3 co-signature lines) · `cosign_pubs.json` · `board.json` (last
board state — advisory, off-ledger) · `meta-genesis.json` (public genesis material as served by `/meta` before shutdown) ·
`kernel22.py` + `kernel22_selftest.py` (the law that this ledger obeyed). Lineage: FL2.1 archive is at `../fl21/`; the FL2.1
final head is this ledger's `bridge_ref`.

**Co-signature coverage of the tail (honest, cold-read 4 F07-2):** the final head `3274433e…` (seq 10,899) carries the operator's signature and
`cosign1` only; the last head with a full 2-of-3 quorum is seq 10,762 `005a5035…`. The 137 entries in between are all operator `TICK`s
(no balance changes — the imported state equals the state at seq 10,762), so `bridge_ref` binds the operator-signed final head, while the
*confirmed* lineage rests on 10,762. The 30-minute GitHub co-signer had not run in the last 137 minutes before shutdown.
