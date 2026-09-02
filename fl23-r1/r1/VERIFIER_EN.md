# Independent Verifier's Guide — how to trust no one's word

*(English edition. If this ever diverges from the Korean original
[VERIFIER.md](VERIFIER.md), the Korean original is authoritative.)*

With this bundle alone you can re-verify every claim the ledger makes (balances,
fulfillments, accidents, statistics) **on your own machine**. The trust ladder has
four rungs (0 to 3) — trust decreases as you climb.

> ★[M-209] Rung 0 comparison list **extended**: besides `log_id`, `operator_pk0` and `cosigners`, compare **`genesis_head`** (the only value that pins the genesis *content* — `/meta.genesis_head` = head of `/log?since=0` = the RELEASE value), `snapshot_hash`, `fp0`, `anchor0_pk` and `bridge_ref` against the RELEASE table. `verify_chain(expect_genesis_head=…)` and `replay_full.py --genesis-head …` enforce that comparison in tooling — the only way to catch an operator running a different genesis under the same keys and log_id.

## Rung 0 — Out-of-band comparison (removes TOFU · mandatory before starting)

Compare `log_id`, `operator_pk`, the `cosigners` public keys **and `genesis_head`** (plus `snapshot_hash` for an imported genesis) from `GET /meta` against
the **public release announcement** (`r1/RELEASE_EN.md` in this bundle — after publication,
against the copy on the public announcement channel). If you simply accept the first keys
the node hands you (trust-on-first-use), a malicious node can serve you a self-consistent
fake ledger — the announcement comparison closes that door.
★**On a mismatch**: that node is not the announced ledger but a **different world**
(possibly a test instance, possibly an impostor) — its history proves nothing about the
announced ledger.

## Rung 1 — Light verification (SDK only · seconds)

```python
from sdk import Fl21Client
c = Fl21Client(NODE_URL, "verifier", "verifier.key")
print(c.verify_chain())    # recompute head chain + operator signature + 2-of-3 co-signatures
# ★[M-213] Read the result, not just `ok`: **`confirmed`** (entries confirmed 2-of-3 · 0 → `warning`) · `genesis_pin` ("release"|"flag"|null) ·
#   `release_identity` ("match" = the announced ledger · "mismatch" = another deployment · "conflict" = RELEASE file vs embedded pins → update sdk.py) · `pin_note`.
# ★[M-210] pinned by default: if the node claims this bundle's RELEASE log_id, genesis_head is compared against
#   RELEASE_EN.md automatically (result carries the pin). Another deployment → pass expect_genesis_head=... yourself.
```

`ok: true` = the confirmed prefix is intact (tampering, omission, and gaps are detected).
`pending` = the newest tail whose co-signatures have not yet arrived (normal — the signers
are separate asynchronous processes).

## Rung 2 — Envelope-signature & law-form verification (public kernel · partially independent)

**Reach (honest)**: this rung alone (light verification) independently verifies **log
integrity, signatures, and law-form** — "is the derived state (balances, escrow) the
result of the conservation laws" (state_root's law-conformance) lies outside this rung:
a malicious node could sign a state_root that violates conservation law and light
verification (hash chain + signatures) would still pass. ★That gap is closed by the
**H7 full public state replay** below (since FL2.2 — re-executes the law itself **from
`/meta`'s public keys alone**; no master_seed, no secrets). To verify the full state,
run the H7 replay in addition to light verification.

What IS independently verified from outside (performed by rung 1's verify_chain):
- Hash-chain integrity (head_i = sha256(prev ‖ canon({env,fp,w_epoch,state_root}[+_force]))).
- The operator's head signature (every entry) + 2-of-3 co-signatures.
- ★**Participant envelope signatures** — JOIN entries carry each principal's public key in
  the log, so every XFER/REDEEM/UW/… envelope signature can be verified independently
  (who signed what).
- Color (issuer) reconstruction — the rules are deterministic and log-derived, so
  independently reproducible.
- The genesis fingerprint `fp0` compared against the announcement (rung 0).

(Log vocabulary: `TICK` = the epoch settlement event · `TICKMARK` = a signed marker ·
`EXT_IN` = operator-signed inflow · `fp` = state fingerprint · `w_epoch` = world epoch ·
`BLOCK` = an atomic bundle whose legs are individually signed.)

Run the kernel and gates yourself to confirm "this code is that canon":

(These commands write verdict records to `results/*.json` — run them in your own copy.)

```bash
python3 fin_lean/lang23/kernel23_selftest.py     # full kernel self-test (20 inherited + 10 FL2.3 gates, incl. the differential storm)
python3 fin_lean/lang23/frontier_vectors.py      # golden vectors (deterministic reproduction)
python3 fin_lean/lang23/golden_compare.py        # ★settlement multiset identical to the FL2.2 vectors = machine proof of law succession
python3 r1/test_r1.py                            # full service-layer acceptance gates
# the archived FL2.2 ledger re-verifies with the bundled fin_lean/lang22/ — replay_full.py picks the generation from /meta.domain
```

**★Why verdicts are not 0–100 scores (design rationale — [M-157])**: agent-trust
standards (e.g., on-chain Validation Registry designs) record verification as a
**designated validator's 0–100 scalar response**, with evidence URIs optional. This
ledger does not adopt that form — ⓐ a scalar **launders the verdict's grounds** (the
contract assigns no meaning to "87") ⓑ optional evidence returns the trust root to
validator reputation. Here a verdict is **pass/fail + hash-bound evidence** (H2), and
the verdict itself is refutable by anyone's re-execution (H7 · challenge) — if you
need a score, compute it yourself from ledger-derived history (p̂ · tape): then the
formula is yours.
We do ship the **bridge to that ecosystem** — `erc8004_adapter.py` (★[M-159]): it
seats the VLUE node behind an ERC-8004 designated validator, mapping delivered
settlement → 100 · deadline accident → 0 · immature → refusal, and **always attaches**
the full grounds (attest · H7 pointers) in the responseURI document (keccak/ABI are
pure-stdlib and self-tested · on-chain submission is the operator's).

## Remaining trust assumptions (honest disclosure — v0)

| Assumption | Content | Mitigation |
|---|---|---|
| Single sequencer | The node decides write order (censorship defense — the ledger law's REQUEST/FORCE mandatory-inclusion — exists in law but ⚠️is not yet wired to the r1 surface; registered) | Public log · signature binding (reordering is detected) |
| ★**Fork (equivocation)** | A malicious node can build **two different branches** at the same seq and show one to verifier A, the other to B; each branch is internally consistent (hashes·signatures valid), so **a single verifier's verify_chain cannot detect it**. ⚠️The co-signers **do not recompute heads — they sign whatever head they are shown** — so they will sign both branches. What 2-of-3 guarantees is not "law was followed" but **"these keys agreed on this head byte-string"** | ★**Cross-compare heads between verifiers** (two different heads at one seq = proven fork — the signatures themselves are the evidence) · publish your own observed heads (third-party witnessing) · fundamental fix = multiple sequencers / anchor consensus (registered for R3) |
| ★**State-law conformance** | ✅**Resolved by H7 (since FL2.2)** — seed-independent full-state replay is live (`replay_full.py` — `/meta`'s public material only, no secrets · see the H7 section below). ⚠️Honest qualifier that remains: for a verifier using **light verification only**, this stays out of reach (hash chain + signatures alone cannot catch a law-violating issuance) — full-state conformance is no longer a trust assumption but **a check you run** | ★Run the H7 replay (seconds to minutes) · the node's `/audit` is a cross-check |
| Integrity of output verification | Job-path fulfillment verdicts are computed by the node. ✅**H2 binding is LIVE**: from new entries onward, REDEEM carries `spec_sha256` (of the normalized spec) and DELIVER carries `output_sha256` (of the output canon), both **bound into the signed head** — after-the-fact spec/output forgery by the operator is refutable from the log alone (⚠️pre-binding entries keep v0 semantics) | ★Outputs are public at `/job/{ref}` — anyone can re-verify AND compare hashes against the head-bound values in REDEEM/DELIVER (mismatch = proof of forgery) · ★since [M-164] the **randomness of sampling is itself re-verifiable**: sample = PRF(output-commit entry head ‖ ref), so which segments must have been checked is re-derivable from the log alone, and re-roll attempts are publicly counted (`/job.ocommits`) — the traceless-resample path is closed | ★[M-208] Sampled verification (`sha256_chain_sampled`) **accumulates** its sample: a failed delivery followed by a re-commit only **adds** indices, so re-drawing cannot raise the escape probability (the old code checked only the latest draw — cold-read 4 R4-3; re-draws stay publicly counted in `/job.ocommits`).
| 2-of-3 co-signing | Whether signer keys are physically separated is an operational property (whether cosigner daemons are deployed on separate infrastructure) | The release announcement states the actual configuration |


## ★What a verifier additionally checks in FL2.3 (J-7 · J-4 · J-11)

- **REJECT entries** (`kind: "REJECT"`): the law's refusal of an envelope whose signature and nonce were valid. The head binds
  `{env, fp, w_epoch, state_root, kind}`; `state_root` states that the envelope changed **nothing** (except consuming the nonce);
  `reason` is an informational field outside the head. Replay feeds the same envelope to the kernel and checks that **the same
  refusal is re-derived** (acceptance would mean a forged ledger). Operator-seat failures are never recorded.
- **Key schedule**: operator head_sig verification starts from `/meta.operator_pk0` (the genesis key, immutable). On a `REKEY`
  entry (p = operator), **that entry still verifies under the old key; entries after it under the new key**. Participant
  envelopes follow the same rule (registered by JOIN/GENESIS_IMPORT, replaced by REKEY). `sdk.verify_chain`, `replay_full.py`
  and `kernel23.replay_verify` all implement it.
- ★[M-210] **Weak keys**: a JOIN / REKEY / GENESIS_IMPORT that registers a low-order Ed25519 point (identity or the
  other torsion points — under which pyca accepts a universal signature) is rejected by the node, and `sdk.verify_chain`
  and `replay_full.py` fail closed if one ever appears in a served log (`kernel23.replay_verify` does not check this — it
  is the node/verifier layer's rule).
- **GENESIS_IMPORT** (first entry): the succession snapshot (`principals · notes · F · F_uw · exited`) — its `snapshot_hash` is bound
  in the args and conservation holds as `ext_in = Σface + F + F_uw`. A note's `issuer` seeds its color (the kernel does not interpret it).
  ★Recipe (J-11): `snapshot_hash = sha256(canonical_json({principals, notes, F, F_uw, exited}))` with `sort_keys=True`,
  `separators=(",", ":")`, `ensure_ascii=False` — the FL2.3 value `acf1f24e…` re-derives from the FL2.2 archive's final state
  (anchor0 40,000 · F 0 · F_uw 0 · exited []).
  ★[M-213] **Verification procedure** (normative from the next generation on): ① hash the `snapshot.json` shipped in the archive and compare
  it with `snapshot_hash` in the new ledger's seq 0; ② replay the predecessor ledger in full and check **conservation** — per-owner Σface,
  `F`, `F_uw`, `exited` and the registry outside the genesis seats (= `principals`, pk = current key) must equal the snapshot; ③ `notes`
  sorted by nid ascending, `principals` by p (a different order is a different hash) · `issuer` = the color recorded by the retiring node's
  color engine (the archive README ships the color file) · owners holding > 512 notes MERGE before retirement (imported mints obey J-6).
- **Archives**: the FL2.2 ledger (`archive/fl22/`) replays in full with `fin_lean/lang22/kernel22.py`; FL2.1 (`archive/fl21/`) re-verifies down to the head chain and signatures only (kernel21 has no seed-free replay API — last 2-of-3 confirmed seq 3,164 · 60-entry TICK tail) — the
  generation is chosen by the `/meta.domain` prefix (`FL22-` / `FL23-`).

## ★Full public state replay (H7 — since FL2.2 · the top trust rung)

Above light verification: re-execute **the law itself**, with no genesis seed — build a
verify-only world from /meta's public material (operator/genesis public keys, GEN,
label, bridge_ref) and replay the entire log, re-checking every state transition,
settlement waterfall, head binding, and operator signature (re-deriving fp0/log_id =
a genesis-integrity check):

```bash
python3 r1/replay_full.py --url https://NODE_URL          # ★[M-210] pins genesis_head from RELEASE when the node claims its log_id
#   (output "genesis_pin": "release" | "flag" | null) · other deployments: --genesis-head <value>
# expect: {"H7_FULL_REPLAY": true, "identity_rederived": true, ...}
```
