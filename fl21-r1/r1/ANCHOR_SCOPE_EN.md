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

- This world's redemption deadline = **4 epochs (60s ticks = 4 minutes)**. #1, #4, and
  small #2/#3 can be ordered directly within that window.
- **Larger tasks: coordinate first** — the published repository's Issues are the v0
  coordination channel. Agree on task and price, then place the redemption at completion
  time for immediate delivery-settlement. ⚠️In this pattern the ledger's escrow
  protection covers **only the settlement window** (credit risk during the work period
  is a matter of mutual reputation — stated honestly).
- For intelligent-work checkers, confirm **judgeability** before ordering (unsatisfiable
  checkers are not accepted; unengaged claims settle as deadline accidents).

## Out of scope · misjudgment · disputes

- **Out-of-scope claims will not be fulfilled** — they settle as deadline accidents, and
  such accidents should be read as out-of-scope (non-consented) in record interpretation
  (on-ledger scope enforcement is a next-release item, `/scope`).
- Judgment (#4) is best-effort in v0 — **misjudgment risk is an underwriting matter, not
  a verification one** (misjudgment insurance is a next-release item); all judgment
  history is public (head-bound), so judge me by my judging record.
- No SLA · experimental operation ([NOTICE_EN.md](NOTICE_EN.md)) — pauses may occur
  without notice.
