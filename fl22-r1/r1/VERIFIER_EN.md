# Independent Verifier's Guide — how to trust no one's word

*(English edition. If this ever diverges from the Korean original
[VERIFIER.md](VERIFIER.md), the Korean original is authoritative.)*

With this bundle alone you can re-verify every claim the ledger makes (balances,
fulfillments, accidents, statistics) **on your own machine**. The trust ladder has
three rungs — trust decreases as you climb.

## Rung 0 — Out-of-band comparison (removes TOFU · mandatory before starting)

Compare `log_id`, `operator_pk`, and the `cosigners` public keys from `GET /meta` against
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
**H7 full public state replay** below (FL2.2 — re-executes the law itself **from
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
python3 fin_lean/lang22/kernel22_selftest.py     # full kernel self-test
python3 fin_lean/lang22/frontier_vectors.py      # golden vectors (incl. FL2.1 law-succession proof)
python3 r1/test_r1.py                            # full service-layer acceptance gates
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

## Remaining trust assumptions (honest disclosure — v0)

| Assumption | Content | Mitigation |
|---|---|---|
| Single sequencer | The node decides write order (censorship defense — the ledger law's REQUEST/FORCE mandatory-inclusion — exists in law but ⚠️is not yet wired to the r1 surface; registered) | Public log · signature binding (reordering is detected) |
| ★**Fork (equivocation)** | A malicious node can build **two different branches** at the same seq and show one to verifier A, the other to B; each branch is internally consistent (hashes·signatures valid), so **a single verifier's verify_chain cannot detect it**. ⚠️The co-signers **do not recompute heads — they sign whatever head they are shown** — so they will sign both branches. What 2-of-3 guarantees is not "law was followed" but **"these keys agreed on this head byte-string"** | ★**Cross-compare heads between verifiers** (two different heads at one seq = proven fork — the signatures themselves are the evidence) · publish your own observed heads (third-party witnessing) · fundamental fix = multiple sequencers / anchor consensus (registered for R3) |
| ★**State-law conformance** | ✅**Resolved by H7 (FL2.2)** — seed-independent full-state replay is live (`replay_full.py` — `/meta`'s public material only, no secrets · see the H7 section below). ⚠️Honest qualifier that remains: for a verifier using **light verification only**, this stays out of reach (hash chain + signatures alone cannot catch a law-violating issuance) — full-state conformance is no longer a trust assumption but **a check you run** | ★Run the H7 replay (seconds to minutes) · the node's `/audit` is a cross-check |
| Integrity of output verification | Job-path fulfillment verdicts are computed by the node. ✅**H2 binding is LIVE**: from new entries onward, REDEEM carries `spec_sha256` (of the normalized spec) and DELIVER carries `output_sha256` (of the output canon), both **bound into the signed head** — after-the-fact spec/output forgery by the operator is refutable from the log alone (⚠️pre-binding entries keep v0 semantics) | ★Outputs are public at `/job/{ref}` — anyone can re-verify AND compare hashes against the head-bound values in REDEEM/DELIVER (mismatch = proof of forgery) |
| 2-of-3 co-signing | Whether signer keys are physically separated is an operational property (whether cosigner daemons are deployed on separate infrastructure) | The release announcement states the actual configuration |


## ★Full public state replay (H7 — FL2.2 · the top trust rung)

Above light verification: re-execute **the law itself**, with no genesis seed — build a
verify-only world from /meta's public material (operator/genesis public keys, GEN,
label, bridge_ref) and replay the entire log, re-checking every state transition,
settlement waterfall, head binding, and operator signature (re-deriving fp0/log_id =
a genesis-integrity check):

```bash
python3 r1/replay_full.py --url https://NODE_URL
# expect: {"H7_FULL_REPLAY": true, "identity_rederived": true, ...}
```
