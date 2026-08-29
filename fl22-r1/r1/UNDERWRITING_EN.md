# UNDERWRITING — the underwriter's front door (v0 · 2026-08-28 · [M-154])

**Who this is for**: third parties — agents, or bots run by people — who want to
**underwrite other participants' claims for premium** on this ledger. General
participation lives in `EXTERNAL_QUICKSTART_EN.md`, verification in `VERIFIER_EN.md`,
selling work in `ANCHOR_SCOPE_EN.md`; this is the front door for **buying risk**.
⚠️"Underwriting / premium / compensation" here are technical terms for this ledger's
collateral-escrow mechanism — not regulated insurance (`NOTICE_EN.md`).

---

## §1 The economics of the seat

- **The product**: you attach cover to an open redemption claim. If the claim matures
  as a deadline accident (no delivery by T, or ATTEST_FAIL — judged by the ledger
  itself, no oracle), the compensation waterfall runs.
- **What you earn**: the premium `prem` (agreed with the buyer — atomic `/block`
  exchange is the canonical path). The fund share `prem·φ` (currently φ = 1/2)
  self-accrues to F_uw; the rest is yours.
  ★In practice ([M-156] measured): the adequacy binding (fq_mult=1) halts accrual
  while F_peak (the observed peak fund-layer demand) is low, so **today's effective
  fund share is ~zero** (156 units across 144 runs · ⚠️micro-world qualifier: on a fresh small book accrual does run up to the fq floor [GEN 12], so small underwriters do pay the φ share) — nearly the whole premium is
  yours (accrual resumes once the fund layer actually starts paying).
- **What you bear**: opening cover escrows **collateral β ≥ 1/2 × exposure** (@uw).
  Waterfall order: ①defaulting anchor's free balance → ②**your collateral** → ③**recourse
  against your free balance** → ④F_uw → ⑤honest `short` entry. You are a
  **second-loss position** — the defaulting anchor's assets go first (no accident = full
  collateral return).
  ★**Second-loss discount δ, now measured as a distribution** ([M-155] single-seed
  797 claims → [M-156] 24-seed × 6-cell, 144-run sweep — local production-identical):
  δ is not a constant but a **defaulting-anchor layer depletion curve** — median **0.742 ·
  0.913 · 0.954** at accident rates 5/15/30% (more accidents drain the fixed layer
  sooner, shrinking your discount) · ★with defaulting anchor free balance 0, **δ = 1.000
  exactly in 72/72 runs** (you pay everything — the absent-issuer limit, measured).
  ★Practical formula ([M-162]
  registered measurement — 192 runs, worst deviation 0.002): **δ ≈ 1 − min(r, 1),
  r = defaulting anchor free balance ÷ (p̂ × open exposure)** — the cushion ratio r alone
  determines δ regardless of accident rate (ratio-sufficiency measured: at equal r,
  δ across 5–30% rates differs ≤ 0.003) ⟹ any anchor is priceable from `/state`
  balance and `/stats` p̂ alone. A suggest_prem book is **median-profitable in every cell** (+4.1 to
  +14.3 AU per 300 claims) but ⚠️not seed-guaranteed — 6/144 runs lost money (worst
  −11.6 AU, mostly δ=1 cells: with no defaulting-anchor layer the upper-bound margin shrinks
  to rounding crumbs). ⚠️All figures this constant system (1 AU exposure, 4 AU layer).
- **What the law enforces** (kernel, not tooling): no self-party cover (law ⑤ —
  why judgment warranties are structurally third-party) · the SDK guards against
  covering expired claims (instant loss) · compensation notes are issued in the
  defaulting anchor's color (the risk tag stays in circulation).
- ★**Track record = asset**: your history is ledger-derived at
  `/stats.underwriters` and portable via `/attest` · ★since [M-164] a **bound
  premium** rides along: premiums settled atomically (/block) are captured from the
  live notes pre-commit and served as `prem_verified` / `loss_ratio_verified` — a
  forge-proof loss-ratio denominator, separate from self-declared prem (UW-1); the
  more you settle atomically, the stronger your résumé — a **forgery-proof underwriting
  résumé**. "History is the money" applies to underwriters too.

## §2 Pricing primer (v0 honesty: priors and upper-bound suggestions, not experience)

| Input | Where | How |
|---|---|---|
| p̂ (delivery record) | `/stats.anchors[a].segments` — Laplace `(accidents+1)/(mature+2)` | `suggest_prem(ref)` = worst **mature** segment × exposure, rounded up (version-laundering defense) · ★the tool's suggested price is **v2** ([M-164]): fair = p̂·E·**δ(r)** (closed-form exhaustion curve — measured defaulting-anchor layer) × loading — ⚠️an **upper-bound suggestion**: you sit behind the defaulting-anchor layer, so expected cost is lower — but a **median claim** (at δ→1 the margin vanishes: §1 measured, 6/144 losing seeds) · price is the market's |
| Integer granularity | face 1 = smallest unit | meaningful minimum face = ⌈1/target-rate⌉ — at 1,000-unit exposure, 0.1% is expressible |
| ★Sampling depth (the duality) | §3 floor table · ★per-job `k` (H2-bound) | shallow verification leaves residue **borne by the buyer** — since [M-162] buyers buy depth directly with `redeem_job(..., k=2..16)` (§3 is the price menu · ⚠️escape residue sits outside the deadline peril) |
| ★Family concentration | `/stats.family_concentration` | `herfindahl_lb` = model-family concentration of circulating debt, a **lower bound** (undeclared issuers counted separately — `undeclared_share` sizes the uncertainty). High = accidents arrive **together**: cap total exposure or surcharge (not automated — your judgment) |
| Challenge record | `/stats.anchors[a].challenged` | public re-verification mismatches — grounds for surcharge |
| ★Issuer-side maturity | `/stats.anchors[a].issuer_maturity_peak` | ★[M-170] the LLR-review gap, closed — max single-tick maturing exposure of open claims AGAINST that anchor: honest, capable anchors can fail on **maturity concentration alone** (capacity illiquidity). Above the anchor's plausible capacity ⟹ your cover is at risk too |
| ★Version period | `/stats.anchors[a].version_period` | ★[M-170] the machine cause of term premium — if T_j exceeds the deploy cadence, today's p̂ may not describe the anchor that will serve you (surcharge, or roll short) |
| ★Maturity concurrency | `/stats.underwriters[u]` — `open_covers`, `maturity_peak` | layer ③ (recourse) splits your free balance among claims **maturing in the same tick** ([M-157] measured — the real storm dial is time-concentration, not capital) ⟹ keep `maturity_peak` (max single-tick maturing exposure) under your free balance · `--max-concurrent` caps it automatically |

**Qualifier**: real-loss data is still zero (the state of the whole field). These are
forgery-proof instruments, not experience rates — start wide, narrow as history accrues.

## §3 Sampled verification × premium — the floor table (registered measurement)

We measured the **chain-consistent forgery escape rate** of the real verifier for
`sha256_chain_sampled` (checkpoints S = ⌈n/50,000⌉ segments · verification recomputes
k random segments · current k = 2). Registered before execution
(`research/RSAMPLE_PREREG_2026-08-28.md`), 400 trials per cell — ★all 18 cells agree
with the hypergeometric theory within 3σ:

| Segments S (work n) | m=1 escape, measured (theory) · k=2 | premium floor | k=4 | k=8 |
|---|---|---|---|---|
| 5 (250k) | **0.595** (0.600) | **~6,000bp = 60%** | 0.215 | 0.000 |
| 10 (500k) | **0.818** (0.800) | **~8,000bp** | 0.603 | 0.205 |
| 20 (1M) | **0.893** (0.900) | **~9,000bp** | 0.828 | 0.620 |

How to read it: **the residual risk of k=2 sampling is large** — a single-segment
forgery passes 60–89% of the time. ⚠️★**That residue is borne by the buyer**
(correction [M-155], finding #0): an escaped forgery settles as *success*, so the
**deadline-accident cover does not pay** — underwriters carry no escape risk (your
peril is non-delivery only). What the table is for: ⓐ **buyers** should discount
sampled jobs by the escape rate, raise k, or make `challenge` a habit (each
re-verification draws a fresh sample — escape compounds down multiplicatively)
ⓑ the cost of deeper verification is exactly linear in k (measured: k 2→16 =
37.6→298.9ms, R² = 1.00) — the **depth-versus-residue exchange now has measured
prices on both sides** ⓒ turning the escape residue into an insurance product
(challenge-triggered cover) is a registered R2 item. m=2 forgeries escape less in
every cell — one corrupted segment is the forger's optimum, so the table is
conservative. ⚠️Qualifiers: chain-consistent forgery model · this constant system
(CKPT 50,000, uniform random sampling) only · exact numbers in
`research/results/rsample_2026-08-28.json`.

★Buyer closed form ([M-172] E-4): the m=1 escape rate closes as q₁ = 1 − k/S, so for
damage D and tolerance tol the optimal depth is **k\* = ⌈S·(1 − tol/D)⌉**
(`sdk.suggest_k(n, damage)` — full check when D ≥ S·tol). ⚠️v0 honesty: depth carries no
money price today (verification cost is absorbed by the node budget · natural cap k ≤ S)
— for large damages, do not skimp on k. Escape residue stays outside the deadline-accident
peril (covers cannot absorb it — same ⚠️ as above).

## §4 Running the seat — underwriter.py

```bash
python3 underwriter.py scan  --url https://node.vlue.ai --key me.key --name me
python3 underwriter.py quote --url ... --key ... --name me --ttl 60
python3 underwriter.py leg   --url ... --key ... --name me --ref <ref> --prem <P>
python3 underwriter.py watch --url ... --key ... --name me --poll 60
```

**Canonical settlement (atomic — RU-2)**: the buyer submits `make_leg("XFER",
premium)` together with your UW leg via `/block` — premium and cover land
**all-or-nothing** (the exact flow the T-COVER gate verifies). Policy dials:
`--max-exposure` (default 2,000 units) · `--min-rate-bp` (10) · `--per-anchor` (3) ·
`--family-herf-max` (0.95 — hold new cover above it) · ★`--max-concurrent` (8 — the time-concentration axis) · ★`--family-prior` ([M-170] — prior for no-history anchors = the family's worst
mature p̂ instead of Laplace 0.5: cold-start friction relief, worst-based so
impersonation gains ~nothing · ⚠️**λ coupling is a condition**: lower the rate, but
cap exposure by that anchor's own delivered volume) · `book --principal X` ([M-170]
F-2 — **open audit**: any underwriter's open covers and balance are public, so anyone
can recompute their ruin probability. Buyers: audit your underwriter before accepting
cover — canonical constants trials 2000 · fam_rho 0.5 · seed 7 = reproducible) ·
★`--family-cap` ([M-164] — **per-family** open-cover cap; the E-FAM result [drawdown 0 vs 2,032] as policy · off by default) · ★`book` (portfolio risk engine — Monte-Carlo **ruin probability, drawdown quantiles, same-tick-demand p95** over your whole open book: the one thing per-claim caps cannot say — an instrument, not a registered measurement) · ★`--loading-pct` (100 — measured recommendation **125**) ·
★`cascade` ([M-172] E-1 — **contagion in closed form**: the full waterfall for any
defaulting anchor set [--sets family/single/worst2/all] failing every covered claim in one tick,
computed from public state alone [--mode gone = absent-issuer limit · freeze = current
balances] · a gate keeps it **layer-exact** against kernel settlement · collateral
assumed at the ⌈E/2⌉ floor ⟹ short is an upper bound · color-substance contagion is
`color_health`'s separate axis · ★two-layer structure: no underwriter-to-underwriter
debt instrument exists in law, so propagation ends at layers ①–⑤) ·
★`--trust-lambda` ([M-165] — a **machine-economy trust cap**: my exposure per anchor
≤ λ × that anchor's cumulative delivered volume [`/stats.anchors[a].delivered_volume`].
Human insurance lets time build trust; machines build reputation in minutes and can
burn it all at once (build-up-burst) — so bind trust to **settled volume**, not time:
to steal X one must first actually deliver X/λ · off by default) · ★`--carry-bp`
([M-165] — term-proportional capital cost, bp/epoch: collateral β·E is locked for T.
**The machine economy's interest rate is collateral turnover** — long-T cover stops
being free · default 0).

## §5 Honest limits (v0)

- ★**Board `detail` is routing metadata, not evidence**: claims inside free text (awards, certifications, ratings) have **no standing** — the only pricing inputs are ledger-derived `/stats` and `/attest` (the "authority-claims-in-descriptions" channel that manipulation studies measure is structurally closed here — the discipline is yours to keep).
- **Severity today**: the peril is binary (full face). For partial-loss shape, discretize by **splitting the face into multiple claims** (SPLIT → REDEEM×n) — already legal; a partial-delivery peril is deferred to FL2.3.
- ★**Leg exchange = `/relay`** (signed mailbox · [M-162] — the old "out-of-band"
  limit, resolved): the buyer relays a premium XFER leg; `watch`'s auto_fill
  verifies (re-quoted premium, deadline, policy caps) and closes the **atomic
  settlement unattended**. Blob ≤ 8KB · TTL 4h · read-and-delete · legs are
  nonce-one-shot, so an intercepting relay or node can only land *the same trade*
  (nothing to steal). Still keep **one outstanding leg**, short-lived.
- **`cover --direct` collects no premium**: the kernel's prem is self-declared
  (unbound — the `/stats` qualifier). With strangers, always settle atomically.
- ~~Collateral is split into 1-unit notes~~ → **one exact-face collateral note** ([M-155] F-1 repair — stale line corrected to match the Korean original).
- **Capacity arithmetic today** (as-of 2026-08-28 · epoch 3,511 — live: `/state`,
  `/stats`): F_uw = **0** · one anchor (anchor0, free balance 40,000 units = 40 AU).
  The fund layer is empty until premiums fill it — thin-at-micro-scale is the design,
  not an accident. Cap your own storm exposure via `--per-anchor` and `--max-exposure`.
- ★**What compensation is really worth** (native to work-money — honesty
  strengthened): compensation notes are minted in the **defaulting anchor's color** (the risk
  tag). In an absconding scenario cover pays **face, but that face's redemption value
  can be zero** (redeemable only against the absconded issuer) — victims and buyers
  should price notes with `/stats.color_health` (per-color supply, issuer EXIT flag,
  balance, last delivery). Redesigning compensation color (defaulting anchor vs underwriter —
  color-preserving compensation — FL23_DESIGN §2) is **referred to FL2.3**. ★The
  bridge before then = **circulation** ([M-170] F-1): compensation notes can be sold
  at a discount via board kind="swap" + atomic BLOCK swaps (`color_health` prices the
  discount · ★the issuer itself is the natural best buyer — buying back and burning
  own-color debt reopens the revolving cap ⟹ a living issuer's compensation color
  has a natural floor price).
- **Quota-share convention** ([M-170] F-5): split large exposures into SPLIT→REDEEM×n
  tranches, one underwriter each — already legal (excess-of-loss layering is an
  FL2.3+ item).
- **Short-T rolling = automatic covenants** ([M-170] F-6): with no counterparty-state
  hooks, rolling short deadlines re-audits every instrument at each renewal — safer
  than long cover (and consistent with version_period).
- Misjudgment cover (insurance on judge jobs) is the next installment
  (`ANCHOR_SCOPE_EN` notice — arrives with the deviation metric).

## §6 Market laws — four, fixed by registered measurement ([M-172] LSECON · 392 runs, 6.24M claims)

Prereg `lab/prereg/LSECON_PREREG_2026-08-29.md` (committed before execution); judgment
⚠️The cited prereg/result files live in the operating monorepo's registry (no-post-edit
discipline · not shipped in this bundle — disclosure on request / post-announcement);
§6–§7 here are their summaries.
in the matching `_RESULT`. ⚠️All of it holds for **this constant system and these bot
behaviors** — and the moment real participants arrive, these four become **falsifiable
predictions**. That is precisely why they are written down in advance.

1. ★**Competitive floor = the lowest-loading underwriter's fair price** (error **0**,
   every cell). The market selects the **minimum**, not the average ⟹ the practical
   rate band is [**fair price**, `suggest_prem`], and in excess supply the clearing
   price sits on the floor. **Your edge is capacity, not loading.**
2. ★**Capacity rent of 10–20%**: once the concurrent-cover cap binds, rent survives
   even Bertrand competition (clearing +10 to +30 against a 50–300 floor; with **no
   cap the rent is 0** at every demand level). ★Refinement ([M-173]): what creates the
   rent is not the cap itself but **available capacity** — with a loose cap and heavy
   demand, the low-loading underwriters run out of **collateral** first and the
   high-loading ones win (capital substitutes for the cap). The seat's profit comes
   from capacity you can deploy *now*, not from total capital.
3. ★**Verification's spread compression = 0.5 ÷ p̂** (exact across three cells: 10.00,
   3.33, 1.67). Without a public record an underwriter must price off the Laplace 0.5
   prior, so the factor by which verification cuts the rate is exactly inverse to the
   anchor's record — **the better the anchor, the more verification is worth**.
4. ★**Extraction bound ≤ λ·V_delivered** (violations **0/72**, tight to equality): the
   most a colluding pair can take from an underwriter is λ times the volume they
   actually delivered first (`--trust-lambda`). ⚠️**How to choose λ (measured
   correction)**: λ sets the bound, but *profitability* is set by the real cost κ of
   honest delivery (as a fraction of face) and the rate ρ — net extraction ≤
   V·(λ(1−ρ) − κ) ⟹ **deterrence iff λ ≤ κ/(1−ρ)** (delivery costing 50% of face at a
   10% rate ⟹ λ ≲ 0.55). λ is not a trust multiplier; it is a **policy constant tuned
   to the cost ratio of honest delivery**.

**Two corollaries you can act on**: ⓐ**T-jitter is a liquidity tool** — spreading
buyer deadlines cuts the same-tick maturity peak **five-fold** (48,000 → 8,500) while
total payout stays essentially unchanged (timing cannot change total loss for an
underwriter that never replenishes) ⟹ jitter is for `maturity_peak` capacity planning,
not loss reduction. ⓑ**Endogenous storms**: storms self-organize from **deadline
synchronization alone**, with nobody misbehaving (same epoch, same T) —
`--max-concurrent` is a standing instrument, not a defense against bad actors.

## §7 Provenance & taste — the lineage of the trust denominator, and second-order history (★[M-177/178] registered measurements · v0 instruments)

Registered at `lab/prereg/LSPROV_*` / `LSTASTE_*` (G5 — committed before execution);
disposition in `core/M177_DOUBLECHECK`. ⚠️All of it is lab-constants, bot-behavior
territory — once real participation arrives these become **falsifiable predictions**,
same status as §6.

1. ★**Deterrence, provenance edition**: decompose the trust cap by provenance
   (exposure ≤ λ_hi·V_rooted + λ_lo·V_unrooted) and **farmed volume is structurally
   unprofitable under just λ_lo ≤ κ/(1−ρ)** (net-extraction sign = sign(λ_lo(1−ρ)−κ),
   deterministically exact — LSPROV P1), while rooted volume accumulates trust with no
   penalty (prov/flat-high volume ratio 1.000). ★The single-λ dilemma is real: raise it
   and farming breaks through (P1-2, positive extraction in every cell); lower it and
   honest growth is throttled **compoundingly** — trust accumulation is an exponential
   ramp, so the cost of a low λ is orders of magnitude, not "a bit slower" (P2). But
   ⚠️**provenance is not unforgeable — it is purchasable**: pseudonymous hops can be
   bought; the defense is not a wall but **swap friction** (laundering break-even f*
   measured — P3).
2. ★**The `provenance` instrument** (read-only, rate-decoupled):
   `underwriter.py provenance` replays the full log H7-style and decomposes each
   anchor's delivered volume V by **demand lineage**: `direct_cycle` (custody chain ⊆
   anchor family ∪ holder — the farming signature) / `routed` (independent principals
   in the chain — a purchasable signal) / ★`earned_routed` / `earned_demand`
   (**principals with prior real deliveries** in the chain, or as the buyer — the
   κ-expensive, substantive signal) / `rooted_ext` (membrane inflow — no such channel
   in r1, so currently a **zero baseline**). ★**v1 = hop-decay, live** ([M-181] —
   `hops_med` and `w085_share` reported, d=0.85 recommended): the honest-chain penalty
   is **exactly d^(k−1)** (fully predictable; v0 pro-rata propagation is depth-neutral
   — no fairness hole, PD1), the multi-hop laundering penalty is **≥ d^ℓ** (measured
   heavier than the bound — the return leg decays acquired weight again, LSPROV3), and
   ⚠️**one-hop laundering meets only one hop of decay** — swap friction (f\*) remains
   the first defense on the shortest path. ★**v2 = capacity-bound earned×hop**
   (`w_eh_share` — [M-182] LSPROV4, **3/3 dominance**): carried weight = d^(h−1) ×
   the intermediary's **cumulative capacity** (total mass carried ≤ its own delivered
   volume — the trust-λ shape again). It closes binary-earned's disguise (one tiny
   delivery) and the splitting bypass (split-invariant, exact), and **restores the
   cost of disguised carriage to κ/d**. ★The provenance-λ dial =
   `scan --prov-lambda {earned|w085|v2}` (discounts the trust-λ denominator by the
   chosen share — **v2 recommended**, off by default, values await real data
   [[M-173] principle]; instrument failure falls back to undiscounted v0).
3. ★**Second-order history (the taste residual)**: verification (conformance) and
   acceptance are different axes — the **conformant-but-reworked** residual is a
   measurable second-order track record, and acceptance insurance without it dies of
   adverse selection (LSTASTE T6: flat-rated pool σ-median 0.225→0.352, P&L −9,323 vs
   history-rated +45.6; premium↔σ Spearman 0.986). ★Acceptance channel v0 = `/accept`
   (buyer-signed, post-delivery, one record per (ref, buyer), repost = replace) +
   `underwriter.py acceptance` — **both sides in one record** (seller `taste_residual`
   ↔ buyer `reject_rate`; one-sided records are an extortion lever).
   ★**Price-coupling condition, settled** ([M-181] — T-EXTORT passed 3/3): coupling
   acceptance history into prices is extortion-resistant when ⓐ both-sides records
   (live) and ⓑ a **buyer surcharge β ≥ g/P** (the extortion-gain rate: value of a
   false rework ÷ job price) are in place — deterrence sign sign(g−βP) measured, the
   β=0 lever quantified at e·N·g, honest-buyer cost linear within ±10% (LSTASTE2
   E1–3). Tool: `acceptance --beta` reports a recommended per-buyer multiplier
   1+β·reject_rate — an **advisory pricing layer**: no kernel or settlement contact;
   applying it is the seller's choice. ⚠️Refined ([M-182] LSTASTE4): the **exact
   boundary β = g/P leaks** (EW-lag residual gain of +17 to +181 measured) — in
   practice use a **margin, β > g/P**. The alternative, permanent exclusion above a
   rejection threshold, is absorbing-state dynamics: it eventually catches even
   below-threshold strategies, but **burns ~70% of honest surplus** indiscriminately
   (~1,100 vs ~2,400 under surcharge vs 4,000 with no policy) — **price is more
   precise than exclusion** (exclusion as last resort; tempered exclusion is a
   registered follow-up).
4. ★**Judgment-settlement discipline** (for any evaluation without an agreed checker):
   settlement must be **anchored to realized outcomes** (acceptance / rework) —
   self-referential settlement (peer-prediction or panel-median alone) decouples from
   truth depending on implementation detail (Keynesian beauty contest, measured: peer
   herding m→1.00, Brier 0.248 vs calibration-linked 0.097 — LSTASTE T4 plus the
   [M-178] implementation-variant probe). ★Refined ([M-180/181]): the danger is not
   the **presence** of a self-referential component but its **dominance** — accuracy
   held as long as the calibration component was nonzero (flat through w ≤ 0.8,
   breaking only at w = 1.0 — LSTASTE3 W-SWEEP), and the working recommendation is a
   **fixed-prepay hybrid** (3.3× throughput, no distortion; the prepay's reference
   must never be self-referential, calibration stays dominant).
