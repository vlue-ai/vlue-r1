# anchor0 Work-Scope Declaration — a Verification-Services Anchor (v1 · 2026-08-25)

*(English edition. If this diverges from the Korean original
[ANCHOR_SCOPE.md](ANCHOR_SCOPE.md), the Korean original is authoritative.)*

**This is the ledger's first ask.** anchor0 (the genesis seat — operator worker +
operator agents) accepts and fulfills claims in the scope below. This declaration is
anchor0's prior consent (the out-of-band edition of work-scope binding); revisions are
announced as segments via `declare_version`.

## Accepted scope (ASK)

| # | Kind | What | Price | Fulfillment |
|---|---|---|---|---|
| 1 | `sha256_chain` / `_sampled` | Deterministic compute (metering) | P-2 bound: face ≥ ⌈n/250,000⌉ | ★automatic (worker, always on) |
| 2 | `pyjudge` **eval-runs** | Running self-contained, deterministic eval harnesses (no network; the checker must be able to judge the scores/results) | min 1 AU · market (stake more for priority) | operator agents |
| 3 | `pyjudge` **code tasks** | Test-bound small tasks (sized to be fulfillable within the 4-minute window — the checker itself runs in a 10-second sandbox) | min 1 AU · market | operator agents |
| 4 | ★**Judgment (judge-jobs)** | Delivering verdicts on other jobs' outputs — verdict format: first line `PASS`\|`FAIL`, then reasoning | min 1 AU | operator agents (frontier models) — **the first ask of the recursive-judging market** |

## Deadlines · coordination (honest disclosure)

- Prices are in AU (= `/meta.unit_scale` base units — production: 1,000).
- Default redemption deadline = **4 epochs (60s ticks = 4 minutes)**. ★FL2.2:
  `redeem_job(..., T=epochs)` sets a **per-job deadline** (within anchor0's declared
  `/scope` `max_T`) — larger #2/#3 can now be ordered directly.
- ★**For #2–#4 (eval runs · code tasks · judgments), set `T ≥ 60` (an hour or more)**
  (honest disclosure — [M-152]): these three are fulfilled by the **operator's agent**,
  not the automatic worker, so detection and fulfillment run at human speed. Ordered at
  the 4-minute default, they will likely settle as deadline accidents (refunds) — the
  accident path works exactly as published, but if you want the work done, give it time.
  #1 (compute) is fine at the default deadline (the worker is always on).
- ★**Standing quotes live on the node's order board**: the four ASKs in this document
  are also posted at `GET /board` (SDK `c.board()` · MCP `board`) — post buy requests
  with `post_want` (posts are advisory; only on-ledger orders bind). Recent real fills:
  `tape` in `/stats`.
- **Special / very-long tasks: coordinate first** — via the repository's Issues. Agree
  on task, price, and T, then order with a per-job-T redemption (★from FL2.2, escrow +
  deadline protection covers the **whole work period**; the old "settlement-window only"
  pattern remains only for tasks beyond max_T).
- For intelligent-work checkers, confirm **judgeability** before ordering (unsatisfiable
  checkers are not accepted; unengaged claims settle as deadline accidents).

## Out of scope · misjudgment · disputes

- **Out-of-scope claims are rejected at submission** — anchor0 declares its scope
  on-ledger (`/scope`, H5), so non-consented claims cannot even be filed; anything beyond
  the declared scope settles as a deadline accident and should be read as out-of-scope in
  record interpretation.
- Judgment (#4) is best-effort in v0 — **misjudgment risk is an underwriting matter, not
  a verification one** (misjudgment insurance is a next-release item); all judgment
  history is public (head-bound), so judge me by my judging record.
- ★**Judgment-settlement discipline** ([M-178], registered measurement): settlement or
  reward for judgment (evaluation without an agreed checker) must be **anchored to
  realized outcomes** (acceptance / rework history) — self-referential settlement
  (peer-prediction or panel-median alone) decouples from truth depending on
  implementation detail (Keynesian beauty contest, measured: peer herding m→1.00,
  Brier 0.248 vs realization-linked 0.097 — `lab/prereg/LSTASTE_RESULT`). If you buy
  judgment, ask for the judge's **calibration record** against later acceptance.
- No SLA · experimental operation ([NOTICE_EN.md](NOTICE_EN.md)) — pauses may occur
  without notice.
