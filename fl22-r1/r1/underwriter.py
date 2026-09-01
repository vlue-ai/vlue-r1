#!/usr/bin/env python3
"""underwriter.py — 제3자 자동-인수자 (P-6 v0 · [M-154] — 인수자 좌석의 실행형).

누구든 자기 키로 인수자가 된다: 열린 미부보 청구를 정책으로 걸러 ⓐ후보와 권고
보험료를 보여주고(scan) ⓑ보드에 커버-호가를 게시하고(quote — 발견층) ⓒ요청 시
서명된 UW 다리(leg)를 만들어 준다(leg). ★체결의 정통 경로 = 매수자가 보험료 XFER
다리와 이 leg 를 /block 으로 **원자 제출**(RU-2 — 게이트 T-COVER 「원자 보험료↔커버」
가 상시 검증하는 그 흐름).

법이 강제하는 것(도구가 아니라 커널): 자기-당사자 인수 금지(법 ⑤) · 담보 β ≥ 1/2
에스크로 · 기금 몫 자기-적립 · 배상 폭포에서 2차-손실 포지션.

★v0 정직 한계(상세 = UNDERWRITING.md §5):
  ⓐ leg 교환은 대역-외다 — 보드 detail 400자 상한·nonce 단조 제약으로 서명-leg 를
    보드에 못 싣는다 ⟹ 미결 leg 는 동시 1건, 소액-노출 권장(담보가 1-단위 노트).
  ⓑ --direct 는 보험료 선-수취 없는 커버다(커널의 prem = 자기-선언·비결박) — 신뢰
    상대 한정. 낯선 상대와는 반드시 원자 /block.
  ⓒ 요율 근거는 상한-제안(suggest_prem)과 사전값이다 — 실손실 데이터 0(분야 전체
    상태). 가계-집중(herfindahl_lb)은 하한 계기다.

사용:
  python3 underwriter.py scan  --url U --key K.key [정책]
  python3 underwriter.py quote --url U --key K.key [정책] [--ttl 60]
  python3 underwriter.py leg   --url U --key K.key --ref R --prem P
  python3 underwriter.py watch --url U --key K.key [정책] [--poll 60]
  python3 underwriter.py cover --url U --key K.key --ref R --prem P --direct
정책: --max-exposure 2000(기본단위) --min-rate-bp 10 --per-anchor 3
      --family-herf-max 0.95
"""
import argparse
import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from sdk import Fl21Client, canon, ACCEPT_DOMAIN, DOMAIN       # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (    # noqa: E402
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.exceptions import InvalidSignature               # noqa: E402


DEFAULT_POLICY = {"max_exposure": 2000, "min_rate_bp": 10,
                  "per_anchor": 3, "family_herf_max": 0.95,
                  # ★[M-189] C-3 — δ 할인 opt-in(기본 끔 = δ=1 보수적). 켜면 δ 가
                  # **움직일 수 있는** 자유잔고를 신용한다(리엔 부재 — 냉독 2차 재현).
                  "delta_from_free_balance": False,
                  # ★U-1([M-157]) — 동시-열린-커버 상한: 층 ③(소구)은 자유 잔고를
                  # 같은 틱 동시-성숙분이 나눠 쓴다([ADR-388] 실측 — 폭풍의 실제 다이얼)
                  "max_concurrent": 8,
                  # ★[M-162] 요율 로딩(% · 100 = 무-로딩): LSFULL 실측 권장 = 125
                  "loading_pct": 100,
                  # ★[M-164] 가계별 열린-커버 상한(None = 끔 · E-FAM 실증 — 상관 축)
                  "family_cap": None,
                  # ★F-10([M-170]) 가계-사전: 무-이력 앵커의 사전을 라플라스 0.5
                  # 대신 **같은 가계의 성숙-최악** p̂로(콜드-스타트 마찰 완화 — 최악-
                  # 기반이라 사칭 이득 최소 · ⚠️노출 상한은 자기 이행-부피에만 결박
                  # 하라[λ 결합] — 요율과 노출의 두 축 분리가 조건). 기본 끔.
                  "family_prior": False,
                  # ★[M-165] C-1 기계-경제 신뢰-상한: 앵커당 내 열린-노출 ≤ λ ×
                  # 그 앵커의 누적 이행-부피(원장-파생). 인간-보험의 「시간이 신뢰를
                  # 만든다」를 기각 — 기계는 명성을 분 단위로 쌓고 한 번에 태울 수
                  # 있으므로(build-up-burst) 신뢰는 시간이 아니라 **정산된 부피**에
                  # 결박한다: X를 털려면 먼저 X/λ를 실제로 이행해야 한다. None = 끔.
                  "trust_lambda": None,
                  # ★[M-165] C-2 기간-비례 자본-비용(bp/에포크 · 0 = 끔): 담보 β·E가
                  # T 동안 잠긴다 — 기계-경제의 이자율 = 담보 회전율. 장기-T 커버가
                  # 공짜가 아니게 하는 항(인간-보험의 기간-보험료의 기계판).
                  "carry_bp_per_epoch": 0,
                  # ★[M-182] 출처-λ: trust_lambda 분모를 출처-몫으로 할인
                  # (earned | w085 | ★v2 = 용량-결박 earned×hop — LSPROV4 지배 ·
                  # 위장-운반 원가 κ/d 복원). 기본 끔 · 값은 실데이터 후.
                  "prov_lambda": None}


def _premium(c, ref, exposure, policy, ctx=None):
    """권고 보험료 v2([M-164]) = max(★δ-반영 공정가 × 로딩, 정책 최저요율).

    v1은 suggest = p̂·E(불이행-층 무시 = 총-기대손실 상한)였다. v2는 측정된 2차-손실
    구조를 쓴다: 공정가 = p̂·E·δ(r) · δ = 1 − min(r,1) · r = 불이행 앵커 자유잔고 ÷
    (p̂ × 열린-노출 + E)(내 커버 선-계상 — LSDELTA2 폐형·이탈 0.0019) · 계기 실패 =
    δ=1 보수 폴백.
    ★로딩([M-162] · LSFULL F2 실측): δ→1 세계에서 p̂-정합 요율은 무-마진이라 경험-요율
    북의 생존은 로딩 몫이다(측정 상수 1.25에서 흑자 실증 — 기본 1.0 = 행동 불변·선택)."""
    floor = -(-exposure * policy["min_rate_bp"] // 10_000)
    sug = c.suggest_prem(ref)
    load = policy.get("loading_pct", 100)
    # ★[M-190] family_prior 는 λ-결합 필수(냉독 최대판 — fam0 는 공격자 자유-텍스트):
    # 무-이력 앵커가 좋은 가계와 **충돌 선언**해 싼 요율을 받는 것을, 문서가 약속한
    # 「노출을 자기 이행-부피에 결박」(λ)으로 막아야 하는데 코드에 없었다. ⟹ trust_lambda
    # 가 설정돼 노출이 자기-부피에 결박될 때만 가계-사전 할인을 준다(결합 강제).
    if policy.get("family_prior") and policy.get("trust_lambda") is not None \
            and ctx and "stats" in ctx:
        try:                                     # ★F-10 — 무-이력 앵커의 가계-사전
            j0 = ctx["job"]
            a0 = j0.get("anchor")
            an0 = (ctx["stats"].get("anchors") or {}).get(a0) or {}
            own_mat = sum(s.get("mature", 0)
                          for s in (an0.get("segments") or {}).values())
            v0 = an0.get("version") or ""
            fam0 = v0.split("/", 1)[0] if "/" in v0 else None
            if own_mat == 0 and fam0:
                fps = []
                for a2, an2 in (ctx["stats"].get("anchors") or {}).items():
                    if a2 == a0:
                        continue
                    v2 = an2.get("version") or ""
                    if v2.split("/", 1)[0] == fam0:
                        fps += [s2["p_hat"] for s2
                                in (an2.get("segments") or {}).values()
                                if s2.get("mature", 0) > 0]
                if fps:
                    sug = min(sug, max(1, -(-int(max(fps) * exposure * 100)
                                            // 100)))
        except Exception:
            pass
    delta_pct = 100
    # ★[M-189] C-3 — δ 는 **움직일 수 있는 자유잔고**를 읽는데(폭포 층①), 커널에
    # 그 잔고를 커버-결속 시 잠그는 리엔이 없다 ⟹ 앵커가 평범한 XFER 로 잔고를 빼면
    # 층①이 증발하고, δ 할인을 받아 싸게 결속한 커버가 층③(인수자)로 떨어진다
    # (냉독 2차 C-3 재현 = 5→500 · loss_ratio 200). ⟹ **기본 = δ 할인 끔**(δ=1 =
    # 총-기대손실 상한 = 보수적·안전). `delta_from_free_balance=True` 로 **명시적
    # 옵트인**해야 옛 동작이 살아난다(그때도 이 위험을 아는 인수자 몫). 근치 = 커널
    # 리엔(⛔FL2.3 회부 — U-LIEN).
    if policy.get("delta_from_free_balance"):
      try:
        j = ctx["job"] if ctx else c.job(ref)
        a = j.get("anchor")
        if ctx is not None and a in ctx.setdefault("bal", {}):
            bal = ctx["bal"][a]
        else:
            bal = c._get(f"/balance/{a}")["balance"]
            if ctx is not None:
                ctx["bal"][a] = bal
        open_exp = (ctx.get("open_exp", {}).get(a, 0) if ctx else 0) + exposure
        p_hat = max(sug / exposure, 1e-9)
        r = bal / (p_hat * open_exp) if open_exp else 0.0
        delta_pct = max(1, round((1 - min(r, 1.0)) * 100))
      except Exception:
        pass
    fair = -(-sug * delta_pct // 100)
    carry = 0
    cbp = policy.get("carry_bp_per_epoch", 0)
    if cbp and ctx and "job" in ctx:
        t_rem = max(0, ctx["job"].get("deadline", 0)
                    - ctx.get("epoch", ctx["job"].get("deadline", 0)))
        carry = -(-(exposure // 2) * t_rem * cbp // 10_000)   # 담보 β·E × T × bp
    return max(-(-fair * load // 100) + carry, floor, 1)


def scan(c, policy=None):
    """정책을 통과하는 열린 미부보 청구 후보 [{ref, anchor, exposure, prem, deadline}].

    필터(전부 앞단 정책 — 법이 아닌 것): ⓐ자기-당사자 아님(커널 법 ⑤가 최종 강제)
    ⓑ노출 ≤ max_exposure ⓒ기한 전 ⓓ앵커당 내 미결 커버 수 < per_anchor
    ⓔ가계-집중 하한 ≤ family_herf_max(초과 시 전면 보류 — 상관 폭풍 노출 억제)
    ⓕ★내 동시-열린-커버 < max_concurrent(U-1 계기 소비 — 시간-집중 상한 · [ADR-388])."""
    policy = {**DEFAULT_POLICY, **(policy or {})}
    st = c.stats()
    herf = (st.get("family_concentration") or {}).get("herfindahl_lb")
    if herf is not None and herf > policy["family_herf_max"]:
        return {"candidates": [], "held": "family_herf_lb %.4f > %.4f — 상관 보류"
                % (herf, policy["family_herf_max"])}
    me = (st.get("underwriters") or {}).get(c.p, {})
    oc = me.get("open_covers", 0)
    if oc >= policy["max_concurrent"]:
        return {"candidates": [], "open_mine": oc,
                "held": "open_covers %d ≥ max_concurrent %d — 동시-집중 보류"
                % (oc, policy["max_concurrent"]),
                "maturity_peak": me.get("maturity_peak")}
    # ★U-B([M-164]) — 가계별 상한(--family-cap): E-FAM 실증(같은-주문열 드로다운
    # 0 vs 2,032)의 정책화 · 앵커→가계 = declare_version("가계/버전") 관례.
    fam_of = {}
    for a2, an in (st.get("anchors") or {}).items():
        v = an.get("version") or ""
        fam_of[a2] = v.split("/", 1)[0] if "/" in v else None
    fam_open = {}
    per_open = {}                  # 앵커별 열린 부보-노출(δ의 r 분모 — R4-2)
    mine_exp = {}                  # 앵커별 내 열린-노출(신뢰-람다 분자)
    # ★[M-182] 출처-λ 다이얼: trust_lambda 분모(delivered_volume)를 출처-몫으로
    # 할인(earned | w085 | ★v2 권장 — LSPROV4 지배). 기본 끔 · 값은 실데이터 후
    # ([M-173] 원칙) · 계기-실패 폴백 = v0 trust-λ(할인 없음 — 조용한 개방 아님).
    prov_share = None
    pl = policy.get("prov_lambda")
    if pl and policy.get("trust_lambda") is not None:
        try:
            key = {"earned": None, "w085": "w085_share",
                   "v2": "w_eh_share"}[pl]
            pv = provenance(c)
            prov_share = {}
            for a3, row in (pv.get("anchors") or {}).items():
                if pl == "earned":
                    prov_share[a3] = min(1.0, row.get("earned_routed_share", 0)
                                         + row.get("earned_demand_share", 0))
                else:
                    prov_share[a3] = row.get(key, 0.0)
        except Exception:
            prov_share = None                    # 폴백 = 무-할인(v0 trust-λ)
    epoch = st["epoch"]
    mine = 0                       # 내 미결 커버(앵커당 계수용 — job 조회로 파악)
    per_anchor = {}
    anchors = set(st.get("anchors", {})) | set(st.get("scopes", {}))
    out = []
    for a in sorted(anchors):
        if a == c.p:
            continue
        try:
            js = c._get(f"/jobs?anchor={a}")["jobs"]
        except Exception:
            continue
        jc = {}                       # ref → job(1회 조회 캐시)
        for ref in sorted(js):
            try:
                jc[ref] = c.job(ref)
            except Exception:
                pass
        # ★[M-192] 2-패스(냉독 라운드3 — 단일-패스 λ 캡이 순서-의존이라 늦게-정렬된
        # 기존 커버를 후보 게이트가 누락했다). 패스1: 기존 부보-노출 전부를 mine_exp·
        # per_open 에 **먼저** 합산(순서 무관). 패스2: 후보 평가. [M-165] R4-2 유지.
        for ref in sorted(jc):
            j = jc[ref]
            if j.get("covered") and not j.get("delivered"):
                per_open[a] = per_open.get(a, 0) + j["exposure"]
                if j.get("uw") == c.p:
                    mine_exp[a] = mine_exp.get(a, 0) + j["exposure"]
        for ref in sorted(jc):
            j = jc[ref]
            if j.get("covered") or j.get("delivered"):
                continue
            if j.get("holder") == c.p:
                continue                        # 자기-당사자(법 ⑤ 선-회피)
            if j["exposure"] > policy["max_exposure"]:
                continue
            if epoch > j["deadline"]:
                continue                        # 기한 경과 = 즉시 손실(RU-1)
            if j.get("uw") == c.p:
                mine += 1
                continue
            if per_anchor.get(a, 0) >= policy["per_anchor"]:
                continue
            lam = policy.get("trust_lambda")
            if lam is not None:
                dv = (st["anchors"].get(a) or {}).get("delivered_volume", 0)
                if prov_share is not None:       # ★출처-λ(분모 할인)
                    dv = dv * prov_share.get(a, 0.0)
                if mine_exp.get(a, 0) + j["exposure"] > lam * dv:
                    continue            # ★C-1 — 이행-부피가 신뢰의 상한
            fam = fam_of.get(a)
            fcap = policy.get("family_cap")
            if fcap is not None and fam is not None and \
                    fam_open.get(fam, 0) >= fcap:
                continue                        # ★U-B 가계-상한(상관 축)
            per_anchor[a] = per_anchor.get(a, 0) + 1
            if fam is not None:
                fam_open[fam] = fam_open.get(fam, 0) + 1
            ctx = {"job": j, "bal": {}, "open_exp": per_open, "epoch": epoch,
                   "stats": st}
            out.append({"ref": ref, "anchor": a, "exposure": j["exposure"],
                        "deadline": j["deadline"],
                        "prem": _premium(c, ref, j["exposure"], policy, ctx)})
            per_open[a] = per_open.get(a, 0) + j["exposure"]
            # ★[M-191] λ 캡 누적(냉독 라운드2 — mine_exp 가 후보마다 안 늘어 캡이
            # 후보 수만큼 뚫렸다). per_open 과 동형으로 이 스캔의 부여분을 합산한다.
            mine_exp[a] = mine_exp.get(a, 0) + j["exposure"]
    return {"candidates": out, "open_mine": mine, "herfindahl_lb": herf,
            "family_open": fam_open}


def quote(c, policy=None, ttl=60):
    """후보에 커버-호가 게시(kind='cover' · detail ≤ 400자 — 조건만·leg 는 대역-외).
    이미 게시한 ref 는 건너뛴다(내용-주소 멱등과 별개로 ref 중복 방지)."""
    res = scan(c, policy)
    if not res["candidates"]:
        return {**res, "posted": []}
    board = c.board()
    already = {r["post"]["detail"].split(" ")[0]
               for r in board.get("asks", [])
               if r["post"]["p"] == c.p and r["post"]["kind"] == "cover"}
    posted = []
    for cand in res["candidates"]:
        tag = f"ref={cand['ref']}"
        if tag in already:
            continue
        c.post_ask("cover", f"cover {cand['ref'][:12]}", cand["prem"],
                   detail=(f"{tag} prem={cand['prem']} "
                           f"· send XFER leg via /relay to {c.p} "
                           "· atomic /block (UNDERWRITING.md)"),
                   ttl=ttl)
        posted.append(cand["ref"])
    return {**res, "posted": posted}


def auto_fill(c, policy=None):
    """★[M-162] 릴레이 자기-서비스 체결: 매수자가 /relay 로 보낸 {"ref","legs":[XFER]}
    를 검증(내 앞 XFER · 보험료 ≥ 재-산정 호가 · 잡 유효 · 정책 상한) 후 내 UW leg 를
    결합해 /block 원자 제출 — 낯선 상대와의 커버가 사람-개입 없이 닫힌다."""
    policy = {**DEFAULT_POLICY, **(policy or {})}
    st = c.stats()
    oc = (st.get("underwriters") or {}).get(c.p, {}).get("open_covers", 0)
    # ★[M-194] scan 과 **진짜 동형**으로(냉독 라운드4: fill_exp 가 매-폴 빈-시작이라 다른
    # 경로[/block RU-2·--direct·이전 폴]로 연 커버를 무시 → λ 캡이 max_concurrent×
    # max_exposure 로만 유계였다). ⓐfill_exp·per_anchor 를 **기존 열린 커버로 시딩**
    # ⓑherf 홀드 ⓒper_anchor 캡을 scan 처럼 건다.
    herf = (st.get("family_concentration") or {}).get("herfindahl_lb")
    if herf is not None and herf > policy["family_herf_max"]:
        return {"filled": [], "skipped": ["herf 홀드 %.4f > %.4f" %
                (herf, policy["family_herf_max"])]}
    fill_exp, per_anchor = {}, {}
    for a in (st.get("anchors") or {}):        # 기존 내 열린-커버 시딩
        try:
            for ref0 in c._get(f"/jobs?anchor={a}")["jobs"]:
                j0 = c.job(ref0)
                if j0.get("uw") == c.p and j0.get("covered") \
                        and not j0.get("delivered"):
                    fill_exp[a] = fill_exp.get(a, 0) + j0["exposure"]
                    per_anchor[a] = per_anchor.get(a, 0) + 1
        except Exception:
            pass
    filled, skipped = [], []
    for m in c.fetch_legs():
        pl = m.get("payload") or {}
        ref, legs = pl.get("ref"), pl.get("legs")
        if not (isinstance(ref, str) and isinstance(legs, list) and legs):
            skipped.append("형식")
            continue
        try:
            if oc + len(filled) >= policy["max_concurrent"]:
                skipped.append(f"{ref[:8]} 동시-상한")
                continue
            j = c.job(ref)
            if j.get("covered") or j.get("delivered") \
                    or st["epoch"] > j["deadline"]:
                skipped.append(f"{ref[:8]} 상태")
                continue
            if j["exposure"] > policy["max_exposure"]:
                skipped.append(f"{ref[:8]} 노출 상한")
                continue
            # ★[M-191] trust_lambda 캡 — scan 과 동형(냉독 라운드2: auto_fill 이
            # λ 를 무시해 --trust-lambda 방어가 이 경로에서 조용히 새었다). 앵커별
            # 이 폴의 누적 노출 + 이 잡 ≤ λ × delivered_volume. ⚠️크로스-폴 누적은
            # open_covers 로만 유계(잔여 한계 — 근치는 노출 상태를 원장-파생화).
            aj = j.get("anchor")
            if per_anchor.get(aj, 0) >= policy["per_anchor"]:
                skipped.append(f"{ref[:8]} per_anchor 상한")
                continue
            lam = policy.get("trust_lambda")
            if lam is not None:
                dv = (st.get("anchors", {}).get(aj) or {}).get("delivered_volume", 0)
                if fill_exp.get(aj, 0) + j["exposure"] > lam * dv:
                    skipped.append(f"{ref[:8]} λ-상한(이행부피 {dv})")
                    continue
            xfer = legs[0]
            if not (xfer.get("typ") == "XFER"
                    and (xfer.get("args") or {}).get("to") == c.p):
                skipped.append(f"{ref[:8]} XFER 아님")
                continue
            face = next((n["face"] for n in
                         c._get(f"/notes/{xfer['args']['frm']}")["notes"]
                         if n["nid"] == xfer["args"]["note"]), 0)
            want = _premium(c, ref, j["exposure"], policy)
            if face < want:
                skipped.append(f"{ref[:8]} 보험료 {face} < {want}")
                continue
            uw_leg = make_cover_leg(c, ref, face)
            r = c.submit_block([xfer, uw_leg])
            filled.append({"ref": ref, "prem": face, "seq": r.get("seq")})
            fill_exp[aj] = fill_exp.get(aj, 0) + j["exposure"]
            per_anchor[aj] = per_anchor.get(aj, 0) + 1
        except Exception as e:
            skipped.append(f"{str(ref)[:8]}:{str(e)[:40]}")
    return {"filled": filled, "skipped": skipped}


def _prorate(avail, needs):
    """정산-법 비례-배분의 재현(kernel22 §5 · fastlaw22 동형 — 정수-정확·ref-정렬 잔여)."""
    tot = sum(needs.values())
    if tot <= avail:
        return dict(needs)
    out = {r: avail * n // tot for r, n in needs.items()}
    left = avail - sum(out.values())
    for r in sorted(needs):
        if left <= 0:
            break
        if out[r] < needs[r]:
            out[r] += 1
            left -= 1
    return out


def cascade(c, mode="gone", sets="family"):
    """★[M-172] E-1 — 전염의 폐형-계산(공개-원장 Eisenberg–Noe의 기계판).

    시나리오 집합 D의 앵커 전원이 **같은 틱에 전-청구 사고**(worst case = 동시-성숙)일
    때의 폭포-연쇄를 공개 상태만으로 계산한다. 인간 거시-건전성이 규제자도 못 갖는
    노출-행렬을 요구하는 자리에서, 이 원장은 그 행렬이 전부 공개다 — 「증언이 아니라
    재계산」의 거시판. mode: gone = 원인-앵커 잔고 0(부재-극한·δ=1) / freeze = 현재
    잔고. sets: family(가계별)·single(앵커별)·worst2(부보-노출 최대 2 — cover2 접점)·
    all. ★2층-전염 정리의 실행형: 전파 = ①불이행 앵커 ②담보 ③소구(같은 틱 비례) ④F_uw
    ⑤short 에서 **끝난다**(인수자-간 부채 계기가 법에 없다 — 증폭 채널은 공유-인수자
    용량뿐). ⚠️정직: 담보 = 법정-최소 ⌈E/2⌉ 가정(실담보 β>½ 이면 short 는 이보다
    작다 = 상한 보고) · 색-실질 전염(배상-노트의 상환-실질)은 이 계산 밖 —
    color_health 가 그 축이다. 계기이지 등록-측정이 아니다."""
    st = c.stats()
    fam_of = {}
    for a2, an in (st.get("anchors") or {}).items():
        v = an.get("version") or ""
        fam_of[a2] = v.split("/", 1)[0] if "/" in v else f"~{a2}"
    claims = []
    for a in sorted(set(st.get("anchors", {})) | set(st.get("scopes", {}))):
        try:
            js = c._get(f"/jobs?anchor={a}")["jobs"]
        except Exception:
            continue
        for ref in sorted(js):
            j = c.job(ref)
            if not j.get("covered") or j.get("delivered")                     or j.get("state") != "open":
                continue
            claims.append({"ref": ref, "anchor": a, "uw": j["uw"],
                           "E": j["exposure"], "coll": -(-j["exposure"] // 2)})
    f_uw0 = st.get("coverage", {}).get("F_uw", 0)
    bal = {}
    for p in sorted({x["anchor"] for x in claims} | {x["uw"] for x in claims}):
        try:
            bal[p] = c._get(f"/balance/{p}")["balance"]
        except Exception:
            bal[p] = 0
    exp_by_a = {}
    for x in claims:
        exp_by_a[x["anchor"]] = exp_by_a.get(x["anchor"], 0) + x["E"]
    if sets == "family":
        groups = {}
        for a in exp_by_a:
            groups.setdefault(fam_of.get(a, f"~{a}"), []).append(a)
    elif sets == "single":
        groups = {a: [a] for a in exp_by_a}
    elif sets == "worst2":
        top = sorted(exp_by_a, key=lambda a: -exp_by_a[a])[:2]
        groups = {"worst2": top} if top else {}
    else:
        groups = {"all": sorted(exp_by_a)} if exp_by_a else {}
    out = []
    for gname in sorted(groups):
        D = set(groups[gname])
        cs = [x for x in claims if x["anchor"] in D]
        if not cs:
            continue
        rem = {x["ref"]: x["E"] for x in cs}
        lay = {"anchor": 0, "cov": 0, "uw": 0, "fund": 0, "short": 0}
        uw_dd = {}
        by_a = {}
        for x in cs:
            by_a.setdefault(x["anchor"], []).append(x)
        for a in sorted(by_a):                       # ① 불이행 앵커(앵커별 비례)
            avail = 0 if mode == "gone" else bal.get(a, 0)
            grp = [x for x in by_a[a] if rem[x["ref"]] > 0]
            if not grp or avail <= 0:
                continue
            alloc = _prorate(avail, {x["ref"]: rem[x["ref"]] for x in grp})
            for x in grp:
                lay["anchor"] += alloc[x["ref"]]
                rem[x["ref"]] -= alloc[x["ref"]]
        for x in cs:                                 # ② 담보(청구 전용 · ⌈E/2⌉ 하한)
            take = min(x["coll"], rem[x["ref"]])
            lay["cov"] += take
            rem[x["ref"]] -= take
            uw_dd[x["uw"]] = uw_dd.get(x["uw"], 0) + take
        by_u = {}
        for x in cs:
            by_u.setdefault(x["uw"], []).append(x)
        for u in sorted(by_u):                       # ③ 소구(같은 틱 비례 — worst)
            grp = [x for x in by_u[u] if rem[x["ref"]] > 0]
            if not grp:
                continue
            alloc = _prorate(bal.get(u, 0), {x["ref"]: rem[x["ref"]] for x in grp})
            for x in grp:
                lay["uw"] += alloc[x["ref"]]
                rem[x["ref"]] -= alloc[x["ref"]]
                uw_dd[u] = uw_dd.get(u, 0) + alloc[x["ref"]]
        grp = [x for x in cs if rem[x["ref"]] > 0]
        if grp:                                      # ④ F_uw(전역 비례)
            alloc = _prorate(f_uw0, {x["ref"]: rem[x["ref"]] for x in grp})
            for x in grp:
                lay["fund"] += alloc[x["ref"]]
                rem[x["ref"]] -= alloc[x["ref"]]
        lay["short"] = sum(rem.values())             # ⑤ 잔여(피해자 부담)
        out.append({"set": gname, "anchors": sorted(D), "claims": len(cs),
                    "need": sum(x["E"] for x in cs), "layers": lay,
                    "uw_drawdown": dict(sorted(uw_dd.items())),
                    "fund_used": lay["fund"], "short": lay["short"]})
    out.sort(key=lambda s2: -s2["short"])
    return {"as_of": {"epoch": st["epoch"]}, "mode": mode, "sets": sets,
            "scenarios": out,
            "note": ("worst-case = 집합 전-청구 같은-틱 사고 · 담보 ⌈E/2⌉ 하한 "
                     "⟹ short 는 상한 · 색-실질 전염은 color_health 별도 축 · "
                     "부보-청구 0이면 빈 표(기준선)")}


def book(c, policy=None, trials=2000, fam_rho=0.5, seed=7, principal=None):
    """★[M-164] U-D 북 위험 엔진 — 내 열린 커버 포트폴리오의 파멸-확률·드로다운 분위.

    개별-청구 규칙(노출·per-anchor·가계·동시 상한)은 각 축의 상한일 뿐 「이 북이 폭풍을
    사는가」를 말하지 않는다 — 이 계기가 그 하나를 말한다. 원료 = 전부 원장-파생:
    내 열린 커버(앵커·노출·기한) · 앵커별 성숙-최악 p̂ · δ(r) 폐형(LSDELTA2) · 가계
    (declare 관례) · 내 자유잔고. 모형(정직 한정): 사고 = 가계-1인자 공통충격(혼합
    fam_rho — 미선언 가계는 독립) · 내 지급 ≈ E×δ(r)(기금-층 0 근사 = 현행 실측) ·
    파멸 = 총지급 > 자유잔고 + 총담보(β·E). ⚠️계기이지 등록-측정이 아니다 — 상수계
    한정·결정론 시드(재현 가능)."""
    import random as _rnd
    policy = {**DEFAULT_POLICY, **(policy or {})}
    subject = principal or c.p                  # ★F-2([M-170]) — 공개-감사: 임의
    st = c.stats()                              #   인수자의 북을 원장에서 재계산
    rng = _rnd.Random(seed)                     #   (바젤의 역전 — 무-감독 감독)
    fam_of = {}
    for a2, an in (st.get("anchors") or {}).items():
        v = an.get("version") or ""
        fam_of[a2] = v.split("/", 1)[0] if "/" in v else f"~{a2}"
    covers, bal_cache, phat = [], {}, {}
    for a in sorted(set(st.get("anchors", {})) | set(st.get("scopes", {}))):
        try:
            js = c._get(f"/jobs?anchor={a}")["jobs"]
        except Exception:
            continue
        for ref in js:
            j = c.job(ref)
            if j.get("uw") != subject or j.get("delivered") \
                    or j.get("state") != "open":
                continue
            covers.append({"ref": ref, "anchor": a, "E": j["exposure"],
                           "dl": j["deadline"], "fam": fam_of.get(a, f"~{a}")})
    my_bal = (c.balance() if subject == c.p
              else c._get(f"/balance/{subject}")["balance"])
    if not covers:
        return {"subject": subject, "self_audit": subject == c.p,
                "open_covers": 0, "balance": my_bal,
                "note": "열린 커버 없음 — 북 위험 0(기준선)"}
    open_exp = {}
    for cv in covers:
        open_exp[cv["anchor"]] = open_exp.get(cv["anchor"], 0) + cv["E"]
    for a in open_exp:
        segs = (st["anchors"].get(a) or {}).get("segments") or {}
        phat[a] = max([s.get("p_hat", 0.5) for s in segs.values()] or [0.5])
        try:
            bal_cache[a] = c._get(f"/balance/{a}")["balance"]
        except Exception:
            bal_cache[a] = 0
    delta = {}
    for a in open_exp:
        r = bal_cache[a] / max(phat[a] * open_exp[a], 1e-9)
        delta[a] = 1.0 - min(r, 1.0)
    coll = sum(-(-cv["E"] // 2) for cv in covers)     # β=1/2 담보(이미 에스크로)
    cap = my_bal + coll
    dds, ruins, tick_peaks = [], 0, []
    fams = sorted({cv["fam"] for cv in covers})
    for _ in range(trials):
        uf = {f: rng.random() for f in fams}
        dd = 0
        tick_demand = {}
        for cv in covers:
            p = phat[cv["anchor"]]
            hit = (uf[cv["fam"]] < p) if (not cv["fam"].startswith("~")
                                          and rng.random() < fam_rho)                 else (rng.random() < p)
            if hit:
                pay = cv["E"] * delta[cv["anchor"]]
                dd += pay
                tick_demand[cv["dl"]] = tick_demand.get(cv["dl"], 0) + pay
        dds.append(dd)
        tick_peaks.append(max(tick_demand.values(), default=0))
        if dd > cap:
            ruins += 1
    dds.sort()
    tick_peaks.sort()
    n = len(dds)
    p95_tick = tick_peaks[int(n * 0.95)]
    hint = []
    if ruins:
        fam_share = {}
        for cv in covers:
            fam_share[cv["fam"]] = fam_share.get(cv["fam"], 0) + cv["E"]
        top = max(fam_share.values()) / sum(fam_share.values())
        if top > 0.5:
            hint.append(f"가계-집중 {top:.0%} — --family-cap 권고")
    if p95_tick > my_bal:
        hint.append("동시-성숙 p95가 자유잔고 초과 — --max-concurrent 권고")
    return {"subject": subject, "self_audit": subject == c.p,
            "as_of": {"epoch": st["epoch"]},
            "open_covers": len(covers), "exposure_total": sum(
                cv["E"] for cv in covers),
            "balance": my_bal, "collateral_escrowed": coll,
            "delta_by_anchor": {a: round(d, 3) for a, d in delta.items()},
            "drawdown": {"p50": dds[n // 2], "p95": dds[int(n * 0.95)],
                         "max": dds[-1]},
            "same_tick_demand_p95": p95_tick,
            "ruin_prob": round(ruins / n, 4),
            "hint": hint or ["ok — 현 정책 상한 안"],
            "model": f"trials={trials} fam_rho={fam_rho} seed={seed} "
                     "(계기 — 등록-측정 아님·δ(r) 폐형·기금-층 0 근사)"}


def provenance(c):
    """★[M-177~182] 출처-계기 v2 — 이행-부피의 수요-혈통 공개-재계산(읽기-전용).

    계보: v0 혈통-분해([M-179]) → v1 hop-감쇠([M-181]) → ★v2 용량-결박([M-182]).

    H7-동형: /meta 공개 재료로 검증-세계를 만들고 /log 전량을 리플레이하며 노트별
    보관-사슬(visited 주체)을 그림자-추적, 앵커별 **이행-부피 V의 혈통 분해**를 낸다.
    r1 에는 막(膜)-유입 채널이 없다(EXT_IN = 자기-IOU 발행 — join·회전-발행) ⟹
    v0 의 뿌리-신호는 「주입-라벨」이 아니라 **보관-사슬의 독립성**이다:
      direct_cycle  = 사슬 ⊆ {앵커·가계·홀더} — 발행자 종이가 곧장 되돌아옴(경작-형)
      routed        = 독립 주체 ≥ 1 경유(의사-신원 홉 — 구매 가능한 신호)
      earned_routed = 경유 독립 주체 중 **선행 실-이행 이력자** 존재(κ-비싼 신호)
      earned_demand = 홀더 자신이 선행 실-이행 이력자(수요가 벌이-있는 주체)
      rooted_ext    = 0 기준선(막-주입 채널 부재 — 유입 생기면 이 칸이 산다)
    ⚠️정직([M-178] R-6): 출처는 위조-불가가 아니라 **유상-이전-가능**하다 — 의사-신원
    홉은 구매 가능하고(비용 = 스왑-마찰 f*), earned-계열이 실질이다. 계기는 요율-비연동
    (기본 끔 동형 — trust_lambda 분모 결합은 별도 재가·v1 = hop-감쇠 등재)."""
    import importlib
    sys.path.insert(0, os.path.join(_HERE, "..", "fin_lean", "lang22"))
    kernel22 = importlib.import_module("kernel22")
    st = c.stats()                               # ★선-인출(v2 가계-지도 — 최종 상태)
    fam = {}
    for a2, an in (st.get("anchors") or {}).items():
        v = an.get("version") or ""
        fam[a2] = v.split("/", 1)[0] if "/" in v else None
    meta = c._get("/meta")
    pks = {"operator": meta["operator_pk"], **(meta.get("genesis_pks") or {})}
    w = kernel22.World.from_public(pks, meta["label"], tuple(meta["genesis"]),
                                   gen=dict(meta["gen"]),
                                   bridge_ref=meta.get("bridge_ref"))
    entries, s = [], 0
    while True:
        page = c._get(f"/log?since={s}")["entries"]
        if not page:
            break
        entries += page
        s = page[-1]["seq"] + 1
    prov = {}                     # nid → {"vis": set, "mix": bool, "hops": n}
    own = {}                      # nid → 마지막 관측 소유자
    pend = {}                     # ref → 상환-대기 혈통 스냅숏
    earned = {}                   # principal → 선행 실-이행(DELIVER·CLOSE 수행) 횟수
    earned_vol = {}               # ★v2 — principal → 실-이행 부피(운반-용량의 원천)
    carried = {}                  # ★v2 — principal → 누적 운반-질량(용량-결박 소진)
    deliv = []
    for e in entries:
        env = e["env"]
        pre_n = set(w.notes)
        pre_p = set(w.redeem_pending)
        r = w._commit(env, replay=True)
        if r["state_root"] != e["state_root"] or r["head"] != e["head"]:
            return {"error": f"결박 불일치 seq {e.get('seq')} — 리플레이 중단"}
        typ = env.get("typ")
        inner = ([lg for lg in (env.get("args") or {}).get("legs", [])]
                 if typ == "BLOCK" else [env])
        consumed = pre_n - set(w.notes)
        minted = set(w.notes) - pre_n
        if minted:
            if len(consumed) == 1:
                b = prov.get(next(iter(consumed)))
                vis0, mix0 = (set(b["vis"]), b["mix"]) if b else (set(), True)
                h0 = b["hops"] if b else 0
            elif consumed:
                vis0 = set().union(*[prov[x]["vis"] for x in consumed
                                     if x in prov]) or set()
                mix0 = True
                h0 = max((prov[x]["hops"] for x in consumed if x in prov),
                         default=0)
            else:
                vis0, mix0, h0 = set(), False, 0
        for nid in minted:
            o = w.notes[nid]["owner"]
            prov[nid] = {"vis": set(vis0) | ({o} if not o.startswith("@")
                                             else set()),
                         "mix": mix0, "hops": h0}
            own[nid] = o
        for nid in consumed:
            prov.pop(nid, None)
            own.pop(nid, None)
        for nid, n in w.notes.items():             # 소유-이동 스캔(BLOCK 내부 포함)
            o = n["owner"]
            if own.get(nid) != o:
                own[nid] = o
                if nid in prov and not o.startswith("@"):
                    prov[nid]["vis"].add(o)
                    prov[nid]["hops"] += 1       # ★v1 — 보관-홉 계수
        for ref in set(w.redeem_pending) - pre_p:
            rp = w.redeem_pending[ref]
            nid = rp["nid"]
            pv = prov.get(nid, {"vis": set(), "hops": 0})
            pend[ref] = {"vis": set(pv["vis"]), "hops": pv.get("hops", 0),
                         "holder": rp["holder"], "anchor": rp["anchor"],
                         "face": w.notes[nid]["face"],
                         "h_earned": earned.get(rp["holder"], 0) > 0}
        gone = pre_p - set(w.redeem_pending)
        if gone:
            dref = {(lg.get("args") or {}).get("ref") for lg in inner
                    if lg.get("typ") == "DELIVER"}
            for ref in gone:
                pd = pend.pop(ref, None)
                if pd is None:
                    continue
                if ref in dref:                    # 이행만 부피 계상(정산·반환 제외)
                    pd["e_snap"] = {q: earned.get(q, 0) for q in pd["vis"]}
                    # ★v2 — 용량-결박 earned×hop([M-182] LSPROV4): 독립 경유-주체의
                    # 운반-총량 ≤ 자기-이행-부피(병목-통과·누적-소진 — 신뢰-λ 동형)
                    A2, H2 = pd["anchor"], pd["holder"]
                    ins = {A2, H2, "operator"} | {a3 for a3, f3 in fam.items()
                                                  if f3 and f3 == fam.get(A2)}
                    indep = {q for q in pd["vis"] if q not in ins}
                    if indep:
                        passed = min([pd["face"]]
                                     + [max(0.0, earned_vol.get(m, 0.0)
                                            - carried.get(m, 0.0))
                                        for m in indep])
                        for m in indep:
                            carried[m] = carried.get(m, 0.0) + passed
                        pd["w_eh"] = (0.85 ** max(pd.get("hops", 0) - 1, 0)
                                      * passed / pd["face"])
                    else:
                        pd["w_eh"] = 0.0
                    deliv.append(pd)
                    earned[pd["anchor"]] = earned.get(pd["anchor"], 0) + 1
                    earned_vol[pd["anchor"]] = \
                        earned_vol.get(pd["anchor"], 0.0) + pd["face"]
        for lg in inner:
            if lg.get("typ") == "CLOSE":
                pf = (lg.get("args") or {}).get("performer")
                if pf:
                    earned[pf] = earned.get(pf, 0) + 1
                    # v2 용량은 DELIVER 부피만 계상(수임-지급은 이진-earned만 —
                    # 보수: CLOSE 지급액을 용량으로 안 세면 위장-여지가 줄 뿐이다)
    per = {}
    for d in deliv:
        A, H = d["anchor"], d["holder"]
        insiders = {A, H} | {a2 for a2, f2 in fam.items()
                             if f2 and f2 == fam.get(A)}
        indep = {q for q in d["vis"]
                 if q not in insiders and q != "operator"}
        cls = ("earned_routed" if any(d["e_snap"].get(q, 0) > 0 for q in indep)
               else "routed") if indep else "direct_cycle"
        row = per.setdefault(A, {"V": 0, "direct_cycle": 0, "routed": 0,
                                 "earned_routed": 0, "earned_demand": 0,
                                 "rooted_ext": 0, "_w085": 0.0, "_hops": [],
                                 "_weh": 0.0})
        row["V"] += d["face"]
        row[cls] += d["face"]
        if d["h_earned"]:
            row["earned_demand"] += d["face"]
        h = d.get("hops", 0)
        row["_hops"].append(h)
        row["_w085"] += d["face"] * (0.85 ** max(h - 1, 0))
        row["_weh"] += d["face"] * d.get("w_eh", 0.0)
    for A, row in per.items():
        v = row["V"] or 1
        row["indep_share"] = round((row["routed"] + row["earned_routed"]) / v, 4)
        row["earned_routed_share"] = round(row["earned_routed"] / v, 4)
        row["earned_demand_share"] = round(row["earned_demand"] / v, 4)
        hs = sorted(row.pop("_hops"))
        row["hops_med"] = hs[len(hs) // 2] if hs else 0
        row["w085_share"] = round(row.pop("_w085") / v, 4)   # ★v1 hop-감쇠
        row["w_eh_share"] = round(row.pop("_weh") / v, 4)    # ★v2 용량-결박
    return {"as_of": {"epoch": st["epoch"], "entries": len(entries)},
            "anchors": dict(sorted(per.items())),
            "note": ("출처-계기 v2(읽기-전용·요율-비연동) — 뿌리 = 보관-사슬 독립성"
                     "(막-채널 부재라 rooted_ext = 0 기준선) · ⚠️의사-신원 홉은 구매"
                     " 가능 — earned-계열이 실질 · ★v1 hop-감쇠(w085_share · d=0.85"
                     " 권고 — [M-180/181]): 정직-벌점 = d^(k−1) 정확 · 다단-세탁 벌점"
                     " ≥ d^ℓ(복귀-다리 추가-감쇠 실측) · ⚠️1-홉 세탁엔 1-홉 감쇠뿐 —"
                     " 최단-경로의 1차 방어 = 스왑-마찰")}


def acceptance(c, tau=None):
    """★[M-177/178/181] 수락-집계 — 일치-후-수락의 **양측** 2차-이력.

    /accept 레코드(매수자-서명·이행-후·(ref,p)당 1건-교체)를 읽어 ⓐ판매자(앵커)별
    taste_residual = 평가-표본 내 재작업-비율 ⓑ매수자별 거절-비율을 같이 낸다 —
    일방 기록은 갈취-레버라 **양측이 한 몸**([M-178] §2 D-5).
    ★결합([M-181] 재가 — T-EXTORT 3/3 통과 후): `tau`를 주면 매수자별 **권고
    가격-승수** 1 + τ·거절률을 병기한다(자문-가격층 — 커널·정산 무접촉). 억지 조건
    = **τ ≥ g/P**(갈취-이득율: 허위-재작업의 이득 ÷ 잡 가격 — LSTASTE2 E2 부호-법
    sign(g−τP) 실측). τ 미지정 = 집계만(record-only 그대로).

    ⚠️★[M-186] 개명 — **τ ≠ β**: 이 계수는 커널 U-1의 **담보비율 β**(β ∈ (0,1] ·
    β_min = 1/2 · 법-강제)와 **전혀 다른 양**이고 1을 넘을 수 있다. 한 글자를 둘이
    쓰던 것을 갈랐다(UNDERWRITING §8-A 기호 사전). 등록서 LSTASTE2~4의 「β」 =
    여기의 τ — 등록물은 사후 편집하지 않으므로 사상표로 잇는다.
    ⚠️★**오조준 과-적재 등재**([M-186] §3-③): 같은 τ가 갈취자와 정직한 고-α 매수자
    (취향이 까다로워 진짜로 재작업을 요구)를 함께 때리는데 — `reject_rate`만으로는
    구분 불가 — 갈취자는 **신원 회전으로 빠져나가고**([M-182] R-2 · 정량 미측정)
    정직 매수자는 못 빠져나간다. 분리 후속 = TE-SPLIT(선행 TE-SYBIL)."""
    rs = c._get("/accept")["records"]
    # ★[M-190] 레코드 **서명 재검증**(냉독 최대판 — acceptance 가 sig 를 안 봤다):
    # provenance 는 서명 사슬을 리플레이하는데 acceptance 는 노드가 준 레코드를 그냥
    # 믿었다 ⟹ 악의 노드의 위조 레코드로 매수자-가격을 오도할 수 있었다. 매수자 pk 는
    # JOIN 항에서 얻어 ACCEPT_DOMAIN 서명을 클라이언트-측에서 검증한다.
    # ⚠️드롭된 레코드는 여전히 탐지 불가(오프-원장 TTL 저장소의 본질 — §7 고지).
    pkmap = {}
    try:
        meta = c.meta
        for k, h in (meta.get("genesis_pks") or {}).items():
            pkmap[k] = Ed25519PublicKey.from_public_bytes(bytes.fromhex(h))
        op_pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(meta["operator_pk"]))
        pkmap["operator"] = op_pk
        chain_prev = None
        # ★[M-192] JOIN pk 를 **operator head_sig 로 결박**(냉독 라운드3: pkmap 이 같은
        # 노드 /log 출처라 완전-악의 노드가 위조 JOIN+위조 레코드로 검증을 무력화했다).
        # 각 엔트리의 head_sig 를 operator 로 검증 — 위조 JOIN 은 operator 서명이 없어
        # 걸러진다(악의 노드는 operator 키가 없다). head_sig 부재/위조 = pkmap 신뢰 철회.
        seq = 0
        while True:
            page = c._get(f"/log?since={seq}")["entries"]
            if not page:
                break
            for e in page:
                if "head_sig" not in e:
                    raise ValueError("head_sig 부재 — pkmap 결박 불가")
                # ★[M-194] env→head 재계산(냉독 라운드4): head_sig 를 head 에 대해서만
                # 검증하고 env 를 안 묶으면, 악의 노드가 **진짜 (head,head_sig) 쌍에 위조
                # env(가짜 JOIN)를 접붙여** 임의 pk 를 등록시킨다(operator 키 불요).
                # sdk.verify_chain(:610) 동형으로 head = sha256(prev‖canon(base)) 재계산·
                # 불일치 거부 → head_sig 가 서명한 head 가 이 env 에서 나온 것임을 결박.
                base = {k: e[k] for k in ("env", "fp", "w_epoch", "state_root")}
                if "_force" in e:
                    base = base | {"_force": e["_force"]}
                rehead = __import__("hashlib").sha256(
                    e["prev"].encode() + canon(base)).hexdigest()
                if rehead != e["head"] or (chain_prev is not None
                                           and e["prev"] != chain_prev):
                    raise ValueError("head≠env 재계산 — 접붙임 거부")
                op_pk.verify(bytes.fromhex(e["head_sig"]),
                             DOMAIN + bytes.fromhex(e["head"]))   # 위조 시 예외
                chain_prev = e["head"]
                env = e.get("env") or {}
                if env.get("typ") == "JOIN":
                    a_ = env.get("args") or {}
                    pkmap[a_.get("principal")] = Ed25519PublicKey.from_public_bytes(
                        bytes.fromhex(a_["pk"]))
            seq = page[-1]["seq"] + 1
    except (OSError, KeyError, ValueError, InvalidSignature, TypeError):
        pkmap = None                         # 로그/메타/서명 실패 = 검증 생략(폴백 표기)
    per_a, per_b = {}, {}
    rejected = 0
    for r in rs:
        rec = r["rec"]
        if pkmap is not None:                # ★서명 재검증(위조 레코드 거부)
            pk = pkmap.get(rec.get("p"))
            sig = r.get("sig")
            if pk is None or not isinstance(sig, str):
                rejected += 1
                continue
            try:
                pk.verify(bytes.fromhex(sig), ACCEPT_DOMAIN + c.log_id + canon(rec))
            except (InvalidSignature, ValueError, TypeError):
                rejected += 1
                continue
        try:
            j = c.job(rec["ref"])
        except Exception:
            continue
        if not j.get("delivered"):
            continue
        A, B, v = j.get("anchor"), rec["p"], rec["verdict"]
        ra = per_a.setdefault(A, {"rated": 0, "rework": 0})
        rb = per_b.setdefault(B, {"rated": 0, "rework": 0})
        ra["rated"] += 1
        rb["rated"] += 1
        if v == "rework":
            ra["rework"] += 1
            rb["rework"] += 1
    for d in per_a.values():
        d["taste_residual"] = round(d["rework"] / d["rated"], 4) \
            if d["rated"] else None
    for d in per_b.values():
        d["reject_rate"] = round(d["rework"] / d["rated"], 4) \
            if d["rated"] else None
        if tau is not None and d["reject_rate"] is not None:
            d["surcharge_mult"] = round(1 + tau * d["reject_rate"], 4)
    return {"anchors": dict(sorted(per_a.items())),
            "buyers": dict(sorted(per_b.items())),
            "tau": tau,
            "sig_verified": pkmap is not None,      # ★[M-190] 서명 재검증 여부
            "sig_rejected": rejected,               # 위조/미검증 레코드 수(>0 = 노드 의심)
            "note": ("수락-집계 — 양측 대칭 기록 = 갈취-레버 차단([M-178] D-5) · "
                     "taste_residual = 일치-후-재작업(검증과 별개 2차-이력) · "
                     "★가격-결합([M-181]): 조건 = 양측-기록 ∧ 매수자-할증 τ ≥ g/P"
                     "(LSTASTE2 E1~3) — surcharge_mult는 권고(자문-가격층·정산 무접촉)"
                     " · ⚠️τ는 담보비율 β와 다른 양이다[M-186 개명 · §8-A] · "
                     "⚠️오조준 과-적재 등재: 갈취자는 신원 회전으로 빠져나간다"
                     "[M-182 R-2 미측정] · ⚠️★오프-원장 record-only: 레코드 서명은 재검증하나"
                     "(위조 거부) **드롭된 레코드는 탐지 불가**(TTL 저장소 본질) ⟹ "
                     "acceptance 수치는 자문이지 온-원장 「위조 불가」 이력이 아니다[M-190]")}


def make_cover_leg(c, ref, prem):
    """서명된 UW 다리 — 매수자가 보험료 XFER 다리와 함께 /block 원자 제출.
    ⚠️nonce 단조·담보 노트-결박 ⟹ 미결 leg 는 동시 1건·짧게 유지(만료 = 무해 실패)."""
    return c.cover(ref, prem=prem, submit=False)


class _RoClient:
    """읽기-전용 명령(provenance·acceptance·cascade)용 무-키 클라이언트 —
    비참여 검증자는 키 없이 공개-재계산만 한다([M-183] 냉독-수리)."""

    def __init__(self, url, name="observer"):
        self.url = url.rstrip("/")
        self.p = name
        self._meta = None

    @property
    def meta(self):                    # ★[M-191] 무-키 경로도 서명 재검증 가능하게
        if self._meta is None:         # (냉독 라운드2 — acceptance 검증이 조용히 스킵됐다)
            self._meta = self._get("/meta")
        return self._meta

    @property
    def log_id(self):
        return bytes.fromhex(self.meta["log_id"])

    def _get(self, path):
        import urllib.request
        req = urllib.request.Request(
            self.url + path,
            headers={"User-Agent": "vlue-underwriter-ro/0.1"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())

    def stats(self):
        return self._get("/stats")

    def job(self, ref):
        return self._get(f"/job/{ref}")


def _mk_client(url, key_path, name):
    cl = Fl21Client.__new__(Fl21Client)
    cl.url = url.rstrip("/")
    cl.p = name
    cl.key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(open(key_path).read().strip()))
    cl.meta = cl._get("/meta")
    cl.log_id = bytes.fromhex(cl.meta["log_id"])
    return cl


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["scan", "quote", "leg", "watch", "cover",
                                    "book", "cascade", "provenance",
                                    "acceptance"])
    ap.add_argument("--url", required=True)
    ap.add_argument("--key", help="서명-키 파일(읽기-전용 명령[provenance·acceptance·"
                                  "cascade]은 생략 가능 — 무-키 공개-재계산)")
    ap.add_argument("--name", help="내 principal 이름(JOIN 완료 전제 · 읽기-전용은 생략 가능)")
    ap.add_argument("--ref")
    ap.add_argument("--prem", type=int)
    ap.add_argument("--direct", action="store_true")
    ap.add_argument("--poll", type=float, default=60)
    ap.add_argument("--ttl", type=int, default=60)
    ap.add_argument("--max-exposure", type=int,
                    default=DEFAULT_POLICY["max_exposure"])
    ap.add_argument("--min-rate-bp", type=int,
                    default=DEFAULT_POLICY["min_rate_bp"])
    ap.add_argument("--per-anchor", type=int, default=DEFAULT_POLICY["per_anchor"])
    ap.add_argument("--family-herf-max", type=float,
                    default=DEFAULT_POLICY["family_herf_max"])
    ap.add_argument("--max-concurrent", type=int,
                    default=DEFAULT_POLICY["max_concurrent"],
                    help="동시-열린-커버 상한(U-1 시간-집중 · 가계-상한과 직교)")
    ap.add_argument("--loading-pct", type=int,
                    default=DEFAULT_POLICY["loading_pct"],
                    help="요율 로딩 %%(100=무-로딩 · LSFULL 실측 권장 125)")
    ap.add_argument("--family-cap", type=int, default=None,
                    help="가계별 열린-커버 상한(상관 축 — E-FAM 실증·기본 끔)")
    ap.add_argument("--trust-lambda", type=float, default=None,
                    help="앵커당 내 노출 ≤ λ×이행-부피(기계-경제 신뢰-상한·기본 끔)")
    ap.add_argument("--carry-bp", type=int, default=0,
                    help="기간-비례 자본-비용 bp/에포크(담보 회전율의 가격·기본 0)")
    ap.add_argument("--principal", default="",
                    help="book: 감사 대상 인수자(공백 = 자기 — F-2 공개-감사)")
    ap.add_argument("--family-prior", action="store_true",
                    help="무-이력 앵커에 가계-최악 사전 적용(F-10 — ⚠️λ 결합 권장)")
    ap.add_argument("--mode", default="gone", choices=["gone", "freeze"],
                    help="cascade: 원인-앵커 잔고 가정(gone=0 · freeze=현재)")
    ap.add_argument("--sets", default="family",
                    choices=["family", "single", "worst2", "all"],
                    help="cascade: 시나리오 집합(E-1)")
    ap.add_argument("--prov-lambda", default=None,
                    choices=["earned", "w085", "v2"],
                    help="trust-λ 분모의 출처-할인(★v2 권장 — 용량-결박 earned×hop"
                         " · 기본 끔 · trust-lambda와 함께만 유효)")
    ap.add_argument("--tau", type=float, default=None,
                    help="acceptance: 매수자-할증 계수(권고 승수 병기 — 억지 조건"
                         " τ ≥ g/P · [M-181] 결합 재가·자문-가격층)"
                         " ⚠️담보비율 β와 다른 양([M-186] 개명)")
    ap.add_argument("--beta", type=float, default=None,
                    help="⚠️구명 별칭 — --tau 를 쓸 것([M-186] 개명 · 등록서"
                         " LSTASTE2~4 호환용으로만 유지)")
    a = ap.parse_args()
    pol = {"max_exposure": a.max_exposure, "min_rate_bp": a.min_rate_bp,
           "per_anchor": a.per_anchor, "family_herf_max": a.family_herf_max,
           "max_concurrent": a.max_concurrent,
           "loading_pct": a.loading_pct, "family_cap": a.family_cap,
           "trust_lambda": a.trust_lambda,
           "prov_lambda": a.prov_lambda,
           "carry_bp_per_epoch": a.carry_bp,
           "family_prior": a.family_prior}
    ro_cmds = ("provenance", "acceptance", "cascade")
    if a.key is None or a.name is None:
        if a.cmd not in ro_cmds:
            sys.exit(f"{a.cmd} 는 --key·--name 필요(서명-명령) — "
                     f"무-키 허용 = {'/'.join(ro_cmds)}")
        c = _RoClient(a.url, a.name or "observer")
    else:
        c = _mk_client(a.url, a.key, a.name)
    if a.cmd == "cascade":
        print(json.dumps(cascade(c, mode=a.mode, sets=a.sets),
                         ensure_ascii=False, indent=1))
        return
    if a.cmd == "provenance":                     # ★[M-178] 출처-계기(읽기-전용)
        print(json.dumps(provenance(c), ensure_ascii=False, indent=1))
        return
    if a.cmd == "acceptance":                     # ★[M-178/181] 수락-집계(+β 결합)
        _tau = a.tau if a.tau is not None else a.beta
        if a.beta is not None and a.tau is None:
            print("⚠️--beta 는 구명이다 — --tau 를 쓸 것([M-186] 개명: 담보비율 β와"
                  " 다른 양). 이번엔 별칭으로 처리한다.", file=sys.stderr)
        print(json.dumps(acceptance(c, tau=_tau), ensure_ascii=False,
                         indent=1))
        return
    if a.cmd == "book":
        print(json.dumps(book(c, pol, principal=(a.principal or None)),
                         ensure_ascii=False, indent=1))
    elif a.cmd == "scan":
        print(json.dumps(scan(c, pol), ensure_ascii=False, indent=1))
    elif a.cmd == "quote":
        print(json.dumps(quote(c, pol, ttl=a.ttl), ensure_ascii=False, indent=1))
    elif a.cmd == "leg":
        if not (a.ref and a.prem):
            sys.exit("leg 는 --ref --prem 필요")
        print(json.dumps(make_cover_leg(c, a.ref, a.prem), ensure_ascii=False))
    elif a.cmd == "cover":
        if not (a.ref and a.prem):
            sys.exit("cover 는 --ref --prem 필요")
        if not a.direct:
            sys.exit("⚠️직접-커버는 보험료 선-수취가 없다(prem = 자기-선언·비결박) — "
                     "낯선 상대와는 원자 /block(leg). 알고도 하려면 --direct.")
        print(json.dumps(c.cover(a.ref, prem=a.prem), ensure_ascii=False))
    elif a.cmd == "watch":
        print(f"underwriter watch — {a.url} poll {a.poll}s 정책 {pol}", flush=True)
        while True:
            try:
                r = quote(c, pol, ttl=a.ttl)
                if r.get("posted"):
                    print(f"커버-호가 게시: {r['posted']}", flush=True)
                elif r.get("held"):
                    print(r["held"], flush=True)
                f = auto_fill(c, pol)             # ★[M-162] 릴레이 자기-서비스
                if f["filled"]:
                    print(f"★원자-체결: {f['filled']}", flush=True)
            except Exception as e:
                print(json.dumps({"watch_error": str(e)[:120]}), flush=True)
            time.sleep(a.poll)


if __name__ == "__main__":
    main()
