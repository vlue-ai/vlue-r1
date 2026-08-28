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
from sdk import Fl21Client                                         # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (    # noqa: E402
    Ed25519PrivateKey)


DEFAULT_POLICY = {"max_exposure": 2000, "min_rate_bp": 10,
                  "per_anchor": 3, "family_herf_max": 0.95,
                  # ★U-1([M-157]) — 동시-열린-커버 상한: 층 ③(소구)은 자유 잔고를
                  # 같은 틱 동시-성숙분이 나눠 쓴다([ADR-388] 실측 — 폭풍의 실제 다이얼)
                  "max_concurrent": 8,
                  # ★[M-162] 요율 로딩(% · 100 = 무-로딩): LSFULL 실측 권장 = 125
                  "loading_pct": 100}


def _premium(c, ref, exposure, policy):
    """권고 보험료 = max(suggest × 로딩, 정책 최저요율) — 정수-입도 상향.
    ★로딩([M-162] · LSFULL F2 실측): δ→1 세계에서 p̂-정합 요율은 무-마진이라 경험-요율
    북의 생존은 로딩 몫이다(측정 상수 1.25에서 흑자 실증 — 기본 1.0 = 행동 불변·선택)."""
    floor = -(-exposure * policy["min_rate_bp"] // 10_000)
    sug = c.suggest_prem(ref)
    load = policy.get("loading_pct", 100)
    return max(-(-sug * load // 100), floor, 1)


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
        for ref in sorted(js):
            j = c.job(ref)
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
            per_anchor[a] = per_anchor.get(a, 0) + 1
            out.append({"ref": ref, "anchor": a, "exposure": j["exposure"],
                        "deadline": j["deadline"],
                        "prem": _premium(c, ref, j["exposure"], policy)})
    return {"candidates": out, "open_mine": mine, "herfindahl_lb": herf}


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
            if j.get("covered") or j.get("delivered") or                     st["epoch"] > j["deadline"]:
                skipped.append(f"{ref[:8]} 상태")
                continue
            if j["exposure"] > policy["max_exposure"]:
                skipped.append(f"{ref[:8]} 노출 상한")
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
        except Exception as e:
            skipped.append(f"{str(ref)[:8]}:{str(e)[:40]}")
    return {"filled": filled, "skipped": skipped}


def make_cover_leg(c, ref, prem):
    """서명된 UW 다리 — 매수자가 보험료 XFER 다리와 함께 /block 원자 제출.
    ⚠️nonce 단조·담보 노트-결박 ⟹ 미결 leg 는 동시 1건·짧게 유지(만료 = 무해 실패)."""
    return c.cover(ref, prem=prem, submit=False)


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
    ap.add_argument("cmd", choices=["scan", "quote", "leg", "watch", "cover"])
    ap.add_argument("--url", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--name", required=True, help="내 principal 이름(JOIN 완료 전제)")
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
    a = ap.parse_args()
    pol = {"max_exposure": a.max_exposure, "min_rate_bp": a.min_rate_bp,
           "per_anchor": a.per_anchor, "family_herf_max": a.family_herf_max,
           "max_concurrent": a.max_concurrent,
           "loading_pct": a.loading_pct}
    c = _mk_client(a.url, a.key, a.name)
    if a.cmd == "scan":
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
