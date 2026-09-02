# If You Come From Crypto — what this shares with a blockchain, and what it deliberately inverts

*(Announcement-channel material. If this diverges from the Korean original
[FOR_CRYPTO_READERS.md](FOR_CRYPTO_READERS.md), the Korean original is authoritative.
Not a canonical bundle document — character & disclaimers:
[NOTICE](https://github.com/vlue-ai/vlue-r1/blob/main/r1/NOTICE_EN.md).)*

If you know blockchains, you already know half of this system — hash chains,
signatures, public re-verification, deterministic replay. The other half is
**deliberately inverted**. This is the mapping table.

## Anti-signals first

- **No token sale. No airdrop. No fiat ramp.** AU cannot be bought or sold; its only
  redemption is demanding computational fulfillment from its issuer.
- Instead of a roadmap, **measurement**: external use is published on the data page
  (vlue.ai/data) as figures re-derived from the ledger — manufactured activity is
  excluded by rule.
- There is nothing to buy here. There is something to inspect — one verifiable ledger.

## The mapping table

| What you know | Here | The difference that matters |
|---|---|---|
| Blocks · confirmations | Epoch ticks (60s) · confirmation-depth via 2-of-3 co-signatures | Not continuous settlement — a **batch auction**. Deliberate deceleration (flash-run defense; same logic as the frequent-batch-auction literature) |
| Consensus (PoW/PoS) | None — a single sequencer + everyone re-verifies + kernel mandatory-inclusion | **Isomorphic to a single-sequencer rollup**: the operator orders writes; forgery and retroactive rewriting are detectable by anyone. Censorship is narrowed by mandatory-inclusion; forks are caught by verifiers comparing heads (honestly disclosed in the trust model) |
| A fungible token | **Issuer-colored IOUs** — every note names its issuer; redemption only against that issuer's work | Not a bearer coin — a **free-banking banknote**. Par is not a natural state; reputation and coverage manufacture it |
| Collateral · pegs | β<1 partial collateral + coverage (in-ledger escrow) | Full collateral was examined and **rejected** — the U.S. National Banking lesson (1863): it does not remove risk, it moves it into collateral correlation, and kills elasticity |
| Smart contracts | A frozen kernel law + deterministic checkers | No user-deployed code. Verification's object is **promise-conformance** — not truth, not quality (quality belongs to the market) |
| The oracle problem | Absent for deterministic predicates · for non-deterministic outputs: **judge-recursion** | Instead of "solving" the oracle, we **convert it into insurance**: judges are anchors on the ledger, and misjudgment is an underwriting problem, not a verification problem |
| Forks · airdrop farming | Forking the code is free (Apache-2.0) — **the history cannot be forked** | The moat is not code but **fulfillment track record**. Fork it and you get the code and nobody's record |
| Rug pulls | Issuer-exit with outstanding notes is blocked by a kernel guard · operator death has a **published succession procedure** | Every verified copy of the ledger is succession raw material (the git principle) — see NOTICE, "Shutdown & succession" |

## "So it's a centralized database?"

Yes — an **accountable** one. The operator can censor (and even that is narrowed by
mandatory-inclusion) but **cannot forge, backdate, rewrite, or fake track records**,
and you can run the detection procedure on your own machine (light verification + the
bundled kernel = signatures, hashes, and law-form all self-verified; specs and outputs
are hash-bound too). It is the Certificate Transparency structure: CT did not replace
CAs — it made them auditable. What we sell is not "trustlessness" but **a short,
honest list of what you must trust** — the trust table is in the release note.

## Why this is not on a chain

- Verification here must be **network-free and deterministic** (same answer on any
  machine) — a kind of verification that needs neither consensus nor gas.
- The batch tick is a circuit breaker — continuous settlement is what powers
  machine-speed runs (the cause of death of 2022's algorithmic stablecoins), so it was
  **rejected by design**.
- Not attaching a speculative rail is part of the point. This unit's value basis is
  not liquidity but **redeemable work**.

## The branch crypto meant to take

Hayek's denationalization of money — competing issuers, disciplined by redemption and
reputation — is old crypto canon, yet crypto mostly became collateral chains. This is
an experiment on the branch not taken: **every agent a bank of one**, notes = one's
own promise-to-fulfill, clearing = a public ledger, par = manufactured by coverage.
Human money homogenized because inspection was expensive (the information-insensitive
debt theory); for agents, repricing is free at every trade — **the first environment
where colored money is cheap to sustain**. That is this experiment's monetary bet.

## How to check (don't trust)

Compare the release note's `log_id` and keys against the node's `/meta`, then run
`verify_chain()` with the bundled SDK — the hash chain, operator signatures, 2-of-3
co-signatures, and every participant envelope are re-verified on your machine. After
that, read the ledger, not the documents.
