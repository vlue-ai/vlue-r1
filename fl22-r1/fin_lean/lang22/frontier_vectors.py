#!/usr/bin/env python3
"""frontier_vectors.py — R-FRONT 법 정합 골든 벡터 생성기 ([RFRONT_PREREG §6 C1]).

지위: ⛔**정합 기준물 생성 — 측정 아님 · 세계 판정 0**. kernel22(정본 폭포 의미론 — FL2.1 문언-동일 승계 · FL2.2 재생성)을
9개 정준 시나리오로 실행해 ★**기판-중립 정산 벡터**를 추출한다. lab-측 β 사이드카는
이 벡터를 **배분-동일**하게 재현해야 측정에 착수할 수 있다(프로토콜 = 등록서 §6).

★계약(벡터의 읽는 법 — results/frontier_vectors.json `contract`에 동봉):
  정산은 (claims[need·cov·anchor·uw], anchor_free, uw_free, fund)의 순수 함수다 —
  β는 개설(UW 인가) 규칙이지 정산 인자가 아니다. 층 순서 = ①가해자(앵커) 자유 잔고
  [앵커별 비례] → ②담보 에스크로[청구 전용 · ★미사용분은 즉시 인수자 자유 잔고로 반환] →
  ③인수자 소구[인수자별 비례 · ②의 반환분 포함] → ④기금[전역 비례] → 잔여 = 지급불능
  기입(배상 ≤ need · 청구 소멸). 층-내 비례 = 바닥 나눗셈 + 잔여를 청구 정렬 순(c1 < c2 <
  …)으로 1씩. 트리거(시한/ATTEST_FAIL)는 성숙 시점만 바꾸고 배분 규칙은 동일하다.
"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from kernel22 import World, derive_key                             # noqa: E402


def _in(w, who, amt):
    w.submit(w.sign_env("operator", "EXT_IN", {"to": who, "amount": amt}))


def _ln(w, owner):
    return max((nid for nid, n in w.notes.items() if n["owner"] == owner), key=int)


def _byface(w, owner, face):
    return [x for x, n in w.notes.items()
            if n["owner"] == owner and n["face"] == face]


def _split(w, owner, nid, parts):
    w.submit(w.sign_env(owner, "SPLIT", {"owner": owner, "note": nid,
                                         "parts": parts}))


def _redeem(w, holder, nid, anchor):
    w.submit(w.sign_env(holder, "REDEEM", {"holder": holder, "note": nid,
                                           "anchor": anchor}))
    return [r for r, rp in w.redeem_pending.items() if rp["nid"] == nid][0]


def _uw(w, uw, ref, cov, prem, fund=()):
    w.submit(w.sign_env(uw, "UW", {"uw": uw, "ref": ref,
                                   "cov_notes": list(cov), "prem": prem,
                                   "prem_fund_notes": list(fund)}))


def _join(w, principal):
    k = derive_key(2, principal)
    w._keys[principal] = k
    w.submit(w.sign_env("operator", "JOIN",
                        {"principal": principal,
                         "pk": k.public_key().public_bytes_raw().hex()}))


def _fail(w, ref):
    w.submit(w.sign_env("operator", "ATTEST_FAIL",
                        {"ref": ref, "reason": "att_missing"}))


# ── 시나리오(각각 (World, trigger, desc) 반환 — 상태는 정산 직전) ──

def v1():
    """전 층 폭포 단일 청구 — 가해자 7 → 담보 60 → 소구 15 → 기금 5 → 부족 13."""
    w = World()
    _in(w, "a1", 100)
    ref = _redeem(w, "a1", _ln(w, "a1"), "a0")
    _in(w, "a2", 80)
    _split(w, "a2", _ln(w, "a2"), [60, 20])
    _split(w, "a2", _byface(w, "a2", 20)[0], [5, 15])
    _uw(w, "a2", ref, _byface(w, "a2", 60), 10, _byface(w, "a2", 5))
    _in(w, "a0", 7)
    return w, "timeout", "전 층 폭포(가해자 우선→담보→소구→기금→지급불능 기입)"


def v2():
    """공유 인수자 비례 소구 — 자유 잔고 10을 두 청구가 5/5로 나눈다."""
    w = World()
    _in(w, "a1", 40)
    _redeem(w, "a1", _ln(w, "a1"), "a0")
    _in(w, "a3", 40)
    _redeem(w, "a3", _ln(w, "a3"), "a0")
    _in(w, "a2", 50)
    _split(w, "a2", _ln(w, "a2"), [20, 10, 10, 10])
    refs = sorted(w.redeem_pending)
    _uw(w, "a2", refs[0], _byface(w, "a2", 20), 0)
    tens = _byface(w, "a2", 10)
    _uw(w, "a2", refs[1], tens[:2], 0)
    return w, "timeout", "인수자-층 비례(공유 자유 잔고 · 잔여 정렬-순)"


def v3():
    """[정리 U] 경계 — β=1(완전 담보)이면 기금 무접촉."""
    w = World(gen={"beta_min_num": 1, "beta_min_den": 1})
    _in(w, "a1", 30)
    ref = _redeem(w, "a1", _ln(w, "a1"), "a0")
    _in(w, "a2", 40)
    _split(w, "a2", _ln(w, "a2"), [30, 9, 1])
    _uw(w, "a2", ref, _byface(w, "a2", 30), 2, _byface(w, "a2", 1))
    return w, "timeout", "[정리 U] 경계 — 완전 담보 = 기금·소구 무접촉"


def v4():
    """가해자 전액 흡수(법 ⑥) — 앵커가 부유하면 보험층 무접촉·담보 전량 반환."""
    w = World()
    _in(w, "a1", 40)
    ref = _redeem(w, "a1", _ln(w, "a1"), "a0")
    _in(w, "a2", 40)
    _split(w, "a2", _ln(w, "a2"), [20, 20])
    _uw(w, "a2", ref, _byface(w, "a2", 20)[:1], 0)
    _in(w, "a0", 100)
    return w, "timeout", "가해자 전액 흡수 — 담보·소구·기금 0(초과손해 구조)"


def v5():
    """기금 비례 자기적용 — 서로 다른 인수자 둘·소구 0·기금 10을 5/5로."""
    w = World()
    _in(w, "a1", 40)
    _redeem(w, "a1", _ln(w, "a1"), "a0")
    _in(w, "a3", 40)
    _redeem(w, "a3", _ln(w, "a3"), "a0")
    refs = sorted(w.redeem_pending)
    _join(w, "a4")
    _in(w, "a2", 30)
    _split(w, "a2", _ln(w, "a2"), [20, 10])
    _uw(w, "a2", refs[0], _byface(w, "a2", 20), 20, _byface(w, "a2", 10))
    _in(w, "a4", 20)
    _uw(w, "a4", refs[1], [_ln(w, "a4")], 0)
    return w, "timeout", "기금-층 전역 비례(G2-7c-ⓒ 자기적용) · 인수자 간 무교차"


def v6():
    """ATTEST_FAIL 조기 성숙 — 배분 규칙은 시한-사고와 동일."""
    w = World()
    _in(w, "a1", 40)
    ref = _redeem(w, "a1", _ln(w, "a1"), "a0")
    _in(w, "a2", 40)
    _split(w, "a2", _ln(w, "a2"), [20, 20])
    _uw(w, "a2", ref, _byface(w, "a2", 20)[:1], 0)
    _fail(w, ref)
    return w, "attest_fail", "발화-성숙(S-2) — 트리거만 다르고 폭포 동일"


def v7():
    """미부보 시간초과 — 배상 없음·노트 반환(시간초과-반환)."""
    w = World()
    _in(w, "a1", 50)
    _redeem(w, "a1", _ln(w, "a1"), "a0")
    return w, "timeout", "미부보 = 시간초과-반환(FL2.0 잔여의 해소)"


def v8():
    """앵커-층 비례 — 같은 앵커의 두 청구가 잔고 10을 5/5로 · 인수자-층 독립."""
    w = World()
    _in(w, "a1", 40)
    _redeem(w, "a1", _ln(w, "a1"), "a0")
    _in(w, "a3", 40)
    _redeem(w, "a3", _ln(w, "a3"), "a0")
    refs = sorted(w.redeem_pending)
    _join(w, "a4")
    _in(w, "a2", 35)
    _split(w, "a2", _ln(w, "a2"), [20, 15])
    _uw(w, "a2", refs[0], _byface(w, "a2", 20), 0)
    _in(w, "a4", 20)
    _uw(w, "a4", refs[1], [_ln(w, "a4")], 0)
    _in(w, "a0", 10)
    return w, "timeout", "가해자-층 앵커별 비례 · 인수자-층 무교차(한쪽만 소구 가능)"


def v9():
    """다중 앵커 + 교차-청구 유동성 — 미사용 담보 반환분이 소구 풀에 들어간다."""
    w = World()
    _in(w, "a1", 30)
    _redeem(w, "a1", _ln(w, "a1"), "a0")
    _join(w, "a4")
    _in(w, "a4", 30)
    _redeem(w, "a4", _ln(w, "a4"), "a3")
    _in(w, "a2", 39)
    _split(w, "a2", _ln(w, "a2"), [15, 15, 5, 4])
    r_by_anchor = {rp["anchor"]: r for r, rp in w.redeem_pending.items()}
    f15 = _byface(w, "a2", 15)
    _uw(w, "a2", r_by_anchor["a0"], [f15[0]], 8, _byface(w, "a2", 4))
    _uw(w, "a2", r_by_anchor["a3"], [f15[1]], 0)
    _in(w, "a0", 50)
    return w, "timeout", "앵커별 그룹 정산 · ②층 반환분이 ③층 소구 풀에 포함"


# ── 추출(기판-중립화) ──

def extract(build):
    w, trigger, desc = build()
    refs = sorted(w.redeem_pending)
    cmap = {r: f"c{i + 1}" for i, r in enumerate(refs)}
    amap, umap = {}, {}
    claims = []
    for r in refs:
        rp = w.redeem_pending[r]
        amap.setdefault(rp["anchor"], f"A{len(amap) + 1}")
        c = w.uw_open.get(r)
        if c:
            umap.setdefault(c["uw"], f"U{len(umap) + 1}")
        claims.append({
            "c": cmap[r], "need": w.notes[rp["nid"]]["face"],
            "anchor": amap[rp["anchor"]],
            "uw": umap[c["uw"]] if c else None,
            "cov": sum(w.notes[n]["face"] for n in c["cov"]) if c else 0})
    inputs = {"claims": claims,
              "anchor_free": {amap[a]: w.bal(a) for a in amap},
              "uw_free": {umap[u]: w.bal(u) for u in umap},
              "fund": w.F_uw}
    ticks = 1 if trigger == "attest_fail" else w.GEN["redeem_T"]
    for _ in range(ticks):
        w.tick()
    ev = [e for e in w.log if e["env"]["typ"] == "TICK" and "_force" in e]
    assert len(ev) == 1, "정산 TICK은 정확히 한 번이어야 한다"
    fo = ev[-1]["_force"]
    expect = [{**{"c": cmap[s["ref"]]},
               **{k: s[k] for k in ("anchor", "cov", "uw", "fund",
                                    "comp", "short")}}
              for s in fo["settled"]]
    a = w.audit()
    assert a["ok"], f"audit 실패: {a}"
    return {"desc": desc, "trigger": trigger, "inputs": inputs,
            "expect": sorted(expect, key=lambda x: x["c"]),
            "expect_returned": sorted(cmap[r] for r in fo["returned"])}


CONTRACT = {
    "함수": "정산 = f(claims[c·need·cov·anchor·uw], anchor_free, uw_free, fund) — "
          "β는 개설 규칙이지 정산 인자가 아니다",
    "층 순서": ["1 가해자(앵커) 자유 잔고 — 앵커별 비례",
              "2 담보 에스크로 — 청구 전용 · ★미사용분 즉시 인수자 자유 잔고로 반환",
              "3 인수자 소구 — 인수자별 비례 · ★2의 반환분 포함",
              "4 기금 — 전역 비례(자기적용)",
              "5 잔여 = short 기입(배상 ≤ need · 청구 소멸)"],
    "비례": "바닥 나눗셈 후 잔여를 청구 정렬 순(c1<c2<…)으로 1씩",
    "트리거": "timeout·attest_fail은 성숙 시점만 다르고 배분 규칙 동일",
    "미부보": "배상 없음 · 노트 보유자 반환(expect_returned)",
    "정합 판정": "lab-측 β 사이드카가 9 벡터 전부에서 expect와 배분-동일이어야 "
             "측정 착수 가능(RFRONT_PREREG §6 C1)",
}


def main():
    builders = {"V1": v1, "V2": v2, "V3": v3, "V4": v4, "V5": v5,
                "V6": v6, "V7": v7, "V8": v8, "V9": v9}
    vectors = {vid: extract(b) for vid, b in builders.items()}
    # 자기검사 — V1은 셀프테스트 T-TO-COV의 손계산과 일치해야 한다(커널 표류 가드)
    assert vectors["V1"]["expect"] == [{"c": "c1", "anchor": 7, "cov": 60,
                                       "uw": 15, "fund": 5, "comp": 87,
                                       "short": 13}], "V1 손계산 불일치"
    assert vectors["V3"]["expect"][0]["fund"] == 0, "V3 정리 U 경계 불일치"
    assert vectors["V7"]["expect_returned"] == ["c1"], "V7 반환 불일치"
    out = {"contract": CONTRACT, "vectors": vectors}
    os.makedirs(os.path.join(_HERE, "results"), exist_ok=True)
    path = os.path.join(_HERE, "results", "frontier_vectors.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=1)
    print(json.dumps({vid: {"expect": v["expect"],
                            "returned": v["expect_returned"]}
                      for vid, v in vectors.items()},
                     ensure_ascii=False, indent=1))
    print(f"→ {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
