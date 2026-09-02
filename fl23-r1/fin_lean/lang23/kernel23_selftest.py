#!/usr/bin/env python3
"""kernel23_selftest.py — FL2.2 커널 v0.1 게이트 ([M-127] — FL2.1 셀프테스트 18종 전량 승계 + 신설 2).

★신설: T-JOBT(잡별 시한 J-1 — 조기/기본/조항 거부) · T-PUBREPLAY(H7 공개-리플레이 J-2 —
시드-독립 전-상태 재검증·변조 검출·fp0 재유도 대조).

의무: 「기계가 법을 강제하는가」까지 — 세계 판정 0. 술어는 설계 v0.2 문언 그대로.
게이트:
  T-INHERIT FL2.0 흐름 승계(EXT_IN→SPLIT→XFER→QUAL_BUY→OPEN→CLOSE + 보존 · F/F_uw 분리).
  T-UW 인수 개설(β 결박 · 담보 에스크로 · F_uw 보험료 몫).
  T-UW-NEG 적대: β_min 미달·과담보·미소유 담보·자기-당사자·자기-상환·중복 인수·실패
     청구 인수·미지 ref = 전부 거부.
  T-FLOOR 요율 하한 다이얼(GEN prem_floor — §3 v0.2 요율 축의 커널 몫).
  T-TO-UNCOV ★시한-사고(S-1) 미부보 = 시간초과-반환(FL2.0 자인 잔여 해소) + 결과 결박.
  T-TO-COV ★부보 폭포(U-2 소구 순서): 가해자 우선→에스크로→소구→F_uw→지급불능 기입 —
     손계산 정확값(7/60/15/5 · comp 87 · short 13) + ★정산 결과 head 결박(변조 검출).
  T-ATTFAIL ★S-2 발화: 조기 성숙 + 좌석·중복·미지 거부 + ATTEST_OK 무상태 기록.
  T-DELIVER / T-CANCEL 커버리지 정상 종결(에스크로 반환 · 보험료 잔류).
  T-PRORATA 동시 청구 비례 청산(공유 소구 층 5/5 · 지급불능 둘 기입).
  T-BETA1 ★[정리 U] 경계(RG-8ⓑ 술어): β=1 세계에서 배상이 F_uw에 닿지 않는다.
  T-EXIT 유출 문·EXIT의 인수판(obl 확장 — 커버리지 중 퇴장·유출 거부).
  T-OFF redeem_T=0(사고 채널 OFF) = FL2.0 의미론(정산·UW·ATTEST 없음).
  T-K0E 경로 밖 기입(F_uw·uw_open) audit 검출 + 미지 타입 거부.
  T-DET 결정론 · T-CLK 시계.
  ★T-THROTTLE(v0.2 · [M-74]) 적정성-결박 흡입: cap 도달 시 prem_f=0(기금 노트 제공 = 거부 ·
     [] = 수리) · 정산이 F_peak(F-층 수요 지평 최대)를 관측 · cap 확장 후 흡입 재개.
  ★T-LENS(v0.3 · [M-80] 큰 그림 리뷰 렌즈 봉합): F1 담보∩기금 겹침 거부 · F2 부정형 릴레이
     inner 강등(크래시·audit 파손 아님) · F3 ATTEST_FAIL 후 DELIVER 거부(판정 내구성) ·
     F5 BLOCK 부정형 다리 원자 롤백(audit 청결) · F6 흡입-결박 단발 초과 없음(F_uw ≤ cap) ·
     ④ F_uw 다중청구 비례(잔여-재분배) · epoch 롤백 원자성 · role 선택 검증.
"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from kernel23 import World, Fl21Error   # ★FL2.3 이식: 정산 레코드는 FL2.2 키 부집합으로 비교(J-9 가 comp_nid 를 더함) · 라벨 fl23-ref                              # noqa: E402


def _in(w, who, amt):
    return w.submit(w.sign_env("operator", "EXT_IN", {"to": who, "amount": amt}))


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
    return w.submit(w.sign_env(uw, "UW", {"uw": uw, "ref": ref,
                                          "cov_notes": list(cov), "prem": prem,
                                          "prem_fund_notes": list(fund)}))


def _settle_recs(w):
    out = []
    for e in w.log:
        if e["env"]["typ"] == "TICK" and "_force" in e:
            out.append(e)
    return out


def gate_TINHERIT():
    w = World()
    _in(w, "a0", 200)
    _split(w, "a0", _ln(w, "a0"), [40, 160])
    w.submit(w.sign_env("a0", "XFER", {"frm": "a0", "to": "a1",
                                       "note": _byface(w, "a0", 40)[0]}))
    _in(w, "a1", 40)
    w.submit(w.sign_env("a1", "QUAL_BUY", {"a": "a1",
                                           "notes": _byface(w, "a1", 40)[:1]}))
    _split(w, "a0", _byface(w, "a0", 160)[0], [34, 126])
    w.submit(w.sign_env("a0", "OPEN", {"owner": "a0", "rid": "r1",
                                       "notes": _byface(w, "a0", 34)}))
    w.submit(w.sign_env("a0", "CLOSE", {"rid": "r1", "owner": "a0",
                                        "performer": "a2"}))
    a = w.audit()
    return {"pass": a["ok"] and w.Q["a1"] == 1 and w.Q["a2"] == 0
            and w.bal("a2") == 32 and w.S == 40 and w.F == 2 and w.F_uw == 0,
            "S": w.S, "F": w.F, "F_uw": w.F_uw}


def _uw_world():
    """공용 시나리오: a1의 100 상환 청구를 a2가 β=0.6·prem 10으로 인수(F_uw 몫 5)."""
    w = World()
    _in(w, "a1", 100)
    ref = _redeem(w, "a1", _ln(w, "a1"), "a0")
    _in(w, "a2", 80)
    _split(w, "a2", _ln(w, "a2"), [60, 20])
    _split(w, "a2", _byface(w, "a2", 20)[0], [5, 15])
    _uw(w, "a2", ref, _byface(w, "a2", 60), 10, _byface(w, "a2", 5))
    return w, ref


def gate_TUW():
    w, ref = _uw_world()
    out = {"F_uw 몫 적립": w.F_uw == 5,
           "담보 에스크로": all(w.notes[n]["owner"] == f"@uw:{ref}"
                           for n in w.uw_open[ref]["cov"]),
           "의무 파생": w.obl("a2") == 1,
           "선언 가격 기록": w.uw_open[ref]["prem"] == 10,
           "audit": w.audit()["ok"]}
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TUWNEG():
    w = World(); out = {}
    _in(w, "a1", 40)
    ref = _redeem(w, "a1", _ln(w, "a1"), "a0")
    _in(w, "a2", 49)
    _split(w, "a2", _ln(w, "a2"), [19, 30])
    n19, n30 = _byface(w, "a2", 19)[0], _byface(w, "a2", 30)[0]
    for name, uw, cov, tgt in [
            ("β_min 미달", "a2", [n19], ref),
            ("과담보 β>1", "a2", [n19, n30], ref),
            ("미지 ref", "a2", [n30], "nope")]:
        try:
            _uw(w, uw, tgt, cov, 0); out[name] = False
        except Fl21Error:
            out[name] = True
    _in(w, "a3", 20)
    try:
        _uw(w, "a2", ref, [_ln(w, "a3")], 0); out["미소유 담보"] = False
    except Fl21Error:
        out["미소유 담보"] = True
    _in(w, "a1", 20)
    try:
        _uw(w, "a1", ref, [_ln(w, "a1")], 0); out["자기-당사자(holder)"] = False
    except Fl21Error:
        out["자기-당사자(holder)"] = True
    _in(w, "a0", 20)
    try:
        _uw(w, "a0", ref, [_ln(w, "a0")], 0); out["자기-당사자(anchor)"] = False
    except Fl21Error:
        out["자기-당사자(anchor)"] = True
    _uw(w, "a2", ref, [n30], 0)                       # 정상 인수 성립
    try:
        _uw(w, "a2", ref, [n19], 0); out["중복 인수"] = False
    except Fl21Error:
        out["중복 인수"] = True
    ref2 = _redeem(w, "a3", _ln(w, "a3"), "a0")
    w.submit(w.sign_env("operator", "ATTEST_FAIL", {"ref": ref2,
                                                    "reason": "att_missing"}))
    try:
        _uw(w, "a2", ref2, [n19], 0); out["실패 청구 인수"] = False
    except Fl21Error:
        out["실패 청구 인수"] = True
    _in(w, "a1", 10)
    ref3 = _redeem(w, "a1", _ln(w, "a1"), "a1")       # 자기-상환(FL2.0 허용 승계)
    try:
        _uw(w, "a2", ref3, [n19], 0); out["자기-상환 인수 금지"] = False
    except Fl21Error:
        out["자기-상환 인수 금지"] = True
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TFLOOR():
    w = World(gen={"prem_floor_num": 1, "prem_floor_den": 10})
    out = {}
    _in(w, "a1", 40)
    ref = _redeem(w, "a1", _ln(w, "a1"), "a0")
    _in(w, "a2", 40)
    _split(w, "a2", _ln(w, "a2"), [20, 20])
    n_cov = _byface(w, "a2", 20)[0]
    try:
        _uw(w, "a2", ref, [n_cov], 3); out["하한 미달 거부"] = False
    except Fl21Error:
        out["하한 미달 거부"] = True
    _split(w, "a2", [x for x in _byface(w, "a2", 20) if x != n_cov][0], [2, 18])
    _uw(w, "a2", ref, [n_cov], 4, _byface(w, "a2", 2))
    out["하한 충족 수리"] = w.F_uw == 2
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TTOUNCOV():
    w = World(); out = {}
    _in(w, "a1", 50)
    ref = _redeem(w, "a1", _ln(w, "a1"), "a0")
    for _ in range(w.GEN["redeem_T"]):
        w.tick()
    out["시간초과-반환"] = w.bal("a1") == 50 and not w.redeem_pending
    recs = _settle_recs(w)
    out["결과 결박(returned)"] = bool(recs) and recs[-1]["_force"]["returned"] == [ref]
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TTOCOV():
    w, ref = _uw_world()
    _in(w, "a0", 7)                                   # 가해자(앵커) 자산
    for _ in range(w.GEN["redeem_T"]):
        w.tick()
    out = {}
    rec = _settle_recs(w)[-1]["_force"]["settled"][0]
    out["폭포 손계산 일치"] = {k: rec[k] for k in ("ref", "comp", "short", "anchor", "cov", "uw", "fund")} == \
        {"ref": ref, "comp": 87, "short": 13, "anchor": 7, "cov": 60, "uw": 15, "fund": 5}
    out["★J-9 배상 민트-nid 명시"] = w.notes.get(rec["comp_nid"], {}) == {"owner": "a1", "face": 87}
    out["배상 발행"] = w.bal("a1") == 87
    out["가해자·소구·기금 소진"] = (w.bal("a0"), w.bal("a2"), w.F_uw) == (0, 0, 0)
    out["청구 소각(종결성)"] = w.S == 100 and not w.redeem_pending and not w.uw_open
    out["audit"] = w.audit()["ok"]
    e = _settle_recs(w)[-1]                           # ★정산 결과 head 결박(변조 검출)
    orig = e["_force"]["settled"][0]["comp"]
    e["_force"]["settled"][0]["comp"] = orig + 1
    out["정산 변조 검출"] = not w.audit()["ok"]
    e["_force"]["settled"][0]["comp"] = orig
    out["복구"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TATTFAIL():
    w = World(); out = {}
    _in(w, "a1", 40)
    ref = _redeem(w, "a1", _ln(w, "a1"), "a0")
    _in(w, "a2", 40)
    _split(w, "a2", _ln(w, "a2"), [20, 20])
    _uw(w, "a2", ref, _byface(w, "a2", 20)[:1], 0)
    w.submit(w.sign_env("operator", "ATTEST_OK", {"ref": ref, "reason": "probe"}))
    try:
        w.submit(w.sign_env("a1", "ATTEST_FAIL", {"ref": ref, "reason": "x"}))
        out["비-좌석 거부"] = False
    except Fl21Error:
        out["비-좌석 거부"] = True
    try:
        w.submit(w.sign_env("operator", "ATTEST_FAIL", {"ref": "nope", "reason": "x"}))
        out["미지 ref 거부"] = False
    except Fl21Error:
        out["미지 ref 거부"] = True
    w.submit(w.sign_env("operator", "ATTEST_FAIL", {"ref": ref,
                                                    "reason": "att_missing"}))
    try:
        w.submit(w.sign_env("operator", "ATTEST_FAIL", {"ref": ref, "reason": "y"}))
        out["중복 FAIL 거부"] = False
    except Fl21Error:
        out["중복 FAIL 거부"] = True
    w.tick()                                          # 조기 성숙 — 시한 전 정산
    rec = _settle_recs(w)[-1]["_force"]["settled"][0]
    out["조기 성숙 정산"] = rec["comp"] == 40 and rec["short"] == 0 \
        and rec["cov"] == 20 and rec["uw"] == 20
    out["배상"] = w.bal("a1") == 40 and w.bal("a2") == 0
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TDELIVER():
    w = World(); out = {}
    _in(w, "a1", 40)
    ref = _redeem(w, "a1", _ln(w, "a1"), "a0")
    _in(w, "a2", 40)
    _split(w, "a2", _ln(w, "a2"), [20, 20])
    _uw(w, "a2", ref, _byface(w, "a2", 20)[:1], 0)
    w.submit(w.sign_env("a0", "DELIVER", {"anchor": "a0", "ref": ref}))
    out["소각·종결"] = w.S == 40 and not w.redeem_pending and not w.uw_open
    out["에스크로 반환"] = w.bal("a2") == 40 and w.obl("a2") == 0
    for _ in range(5):
        w.tick()
    out["잔여 정산 없음"] = not _settle_recs(w)
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TCANCEL():
    w = World(); out = {}
    _in(w, "a1", 40)
    ref = _redeem(w, "a1", _ln(w, "a1"), "a0")
    _in(w, "a2", 40)
    _split(w, "a2", _ln(w, "a2"), [20, 20])
    _uw(w, "a2", ref, _byface(w, "a2", 20)[:1], 0)
    w.submit(w.sign_env("a1", "REDEEM_CANCEL", {"ref": ref}))
    out["노트 반환"] = w.bal("a1") == 40
    out["에스크로 반환"] = w.bal("a2") == 40 and not w.uw_open
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TPRORATA():
    w = World(); out = {}
    _in(w, "a1", 40)
    ra = _redeem(w, "a1", _ln(w, "a1"), "a0")
    _in(w, "a3", 40)
    rb = _redeem(w, "a3", _ln(w, "a3"), "a0")
    _in(w, "a2", 50)
    _split(w, "a2", _ln(w, "a2"), [20, 10, 10, 10])
    n20 = _byface(w, "a2", 20)[0]
    tens = _byface(w, "a2", 10)
    _uw(w, "a2", ra, [n20], 0)
    _uw(w, "a2", rb, tens[:2], 0)                     # a2 자유 잔고 = 10 하나
    for _ in range(w.GEN["redeem_T"]):
        w.tick()
    recs = {r["ref"]: r for r in _settle_recs(w)[-1]["_force"]["settled"]}
    out["비례 소구(5/5)"] = all(recs[r]["uw"] == 5 and recs[r]["cov"] == 20
                            and recs[r]["short"] == 15 for r in (ra, rb))
    out["배상 각 25"] = w.bal("a1") == 25 and w.bal("a3") == 25
    out["지급불능 기입 둘"] = sum(1 for r in recs.values() if r["short"] > 0) == 2
    out["소각 80"] = w.S == 80 and w.bal("a2") == 0
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TBETA1():
    """★[정리 U] 경계(RG-8ⓑ 술어): 완전 담보(β=1)면 배상 폭포가 F_uw에 닿지 않는다."""
    w = World(gen={"beta_min_num": 1, "beta_min_den": 1})
    out = {}
    _in(w, "a1", 30)
    ref = _redeem(w, "a1", _ln(w, "a1"), "a0")
    _in(w, "a2", 40)
    _split(w, "a2", _ln(w, "a2"), [30, 10])
    _split(w, "a2", _byface(w, "a2", 10)[0], [1, 9])
    _uw(w, "a2", ref, _byface(w, "a2", 30), 2, _byface(w, "a2", 1))
    f0 = w.F_uw
    for _ in range(w.GEN["redeem_T"]):
        w.tick()
    rec = _settle_recs(w)[-1]["_force"]["settled"][0]
    out["F_uw 무접촉"] = w.F_uw == f0 == 1 and rec["fund"] == 0
    out["에스크로 전액 배상"] = rec["cov"] == 30 and rec["comp"] == 30 \
        and rec["short"] == 0
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TEXIT():
    w = World(); out = {}
    _in(w, "a1", 40)
    ref = _redeem(w, "a1", _ln(w, "a1"), "a0")
    _in(w, "a2", 40)
    _split(w, "a2", _ln(w, "a2"), [20, 20])
    n_free = _byface(w, "a2", 20)[1]
    _uw(w, "a2", ref, [_byface(w, "a2", 20)[0]], 0)
    try:
        w.submit(w.sign_env("a2", "EXIT", {"a": "a2"})); out["커버리지 중 EXIT 거부"] = False
    except Fl21Error:
        out["커버리지 중 EXIT 거부"] = True
    try:
        w.submit(w.sign_env("a2", "EXT_OUT", {"frm": "a2", "note": n_free}))
        out["커버리지 중 유출 거부"] = False
    except Fl21Error:
        out["커버리지 중 유출 거부"] = True
    w.submit(w.sign_env("a0", "DELIVER", {"anchor": "a0", "ref": ref}))
    w.submit(w.sign_env("a2", "EXT_OUT", {"frm": "a2", "note": n_free}))
    out["종결 후 유출 수리"] = w.ext_out == 20
    w.submit(w.sign_env("a2", "XFER", {"frm": "a2", "to": "a0",
                                       "note": _ln(w, "a2")}))
    w.submit(w.sign_env("a2", "EXIT", {"a": "a2"}))
    out["종결 후 EXIT 수리"] = "a2" in w.exited
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TOFF():
    w = World(gen={"redeem_T": 0})
    out = {}
    _in(w, "a1", 40)
    ref = _redeem(w, "a1", _ln(w, "a1"), "a0")
    for _ in range(6):
        w.tick()
    out["정산 없음(FL2.0 의미론)"] = ref in w.redeem_pending and not _settle_recs(w)
    _in(w, "a2", 40)
    try:
        _uw(w, "a2", ref, [_ln(w, "a2")], 0); out["UW 거부"] = False
    except Fl21Error:
        out["UW 거부"] = True
    try:
        w.submit(w.sign_env("operator", "ATTEST_FAIL", {"ref": ref, "reason": "x"}))
        out["ATTEST 거부"] = False
    except Fl21Error:
        out["ATTEST 거부"] = True
    w.submit(w.sign_env("a1", "REDEEM_CANCEL", {"ref": ref}))
    out["명시 CANCEL 잔존"] = w.bal("a1") == 40
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TK0E():
    w, ref = _uw_world()
    out = {}
    w.F_uw = 999
    out["F_uw 위조 검출"] = not w.audit()["ok"]
    w.F_uw = 5
    w.uw_open["XX"] = {"uw": "a3", "cov": [], "prem": 0}
    out["uw_open 위조 검출"] = not w.audit()["ok"]
    del w.uw_open["XX"]
    out["복구"] = w.audit()["ok"]
    try:
        w.submit(w.sign_env("a2", "UNDERWRITE", {})); out["미지 타입 거부"] = False
    except Fl21Error as e:
        out["미지 타입 거부"] = "경로 밖" in str(e)
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TTHROTTLE():
    """★v0.2 적정성-결박 흡입 — 도관-저수지 배타([정리 FR-1])의 병목 축."""
    w = World(gen={"fq_mult": 1, "fq_base": 2})
    out = {}
    _in(w, "a1", 24)
    _split(w, "a1", _ln(w, "a1"), [12, 12])
    tw = _byface(w, "a1", 12)
    r1, r2 = _redeem(w, "a1", tw[0], "a0"), _redeem(w, "a1", tw[1], "a0")
    _in(w, "a2", 30)
    _split(w, "a2", _ln(w, "a2"), [6, 6, 1, 1, 16])
    sixes, ones = _byface(w, "a2", 6), _byface(w, "a2", 1)
    _uw(w, "a2", r1, [sixes[0]], 2, [ones[0]])
    _uw(w, "a2", r2, [sixes[1]], 2, [ones[1]])
    out["흡입(cap 미만)"] = w.F_uw == 2
    _in(w, "a1", 12)
    r3 = _redeem(w, "a1", _ln(w, "a1"), "a0")
    _split(w, "a2", _byface(w, "a2", 16)[0], [6, 10])
    _split(w, "a2", _byface(w, "a2", 10)[0], [1, 9])
    n6, n1 = _byface(w, "a2", 6)[0], _byface(w, "a2", 1)[0]
    try:
        _uw(w, "a2", r3, [n6], 2, [n1]); out["결박 시 기금 노트 거부"] = False
    except Fl21Error:
        out["결박 시 기금 노트 거부"] = True
    _uw(w, "a2", r3, [n6], 2, [])
    out["결박 시 prem_f=0 수리"] = w.F_uw == 2
    for nid in (_byface(w, "a2", 9) + _byface(w, "a2", 1)):
        w.submit(w.sign_env("a2", "XFER", {"frm": "a2", "to": "a3", "note": nid}))
    w.submit(w.sign_env("operator", "ATTEST_FAIL", {"ref": r2,
                                                    "reason": "att_missing"}))
    w.tick()
    rec = _settle_recs(w)[-1]["_force"]["settled"][0]
    out["F_peak 관측"] = w.F_peak == 6
    out["폭포(부족 = F-자기적용)"] = {k: rec[k] for k in ("ref", "comp", "short", "anchor", "cov", "uw", "fund")} == \
        {"ref": r2, "comp": 8, "short": 4, "anchor": 0, "cov": 6, "uw": 0, "fund": 2}
    _in(w, "a2", 20)
    _split(w, "a2", _ln(w, "a2"), [6, 1, 13])
    _in(w, "a1", 12)
    r4 = _redeem(w, "a1", _ln(w, "a1"), "a0")
    _uw(w, "a2", r4, _byface(w, "a2", 6)[:1], 2, _byface(w, "a2", 1)[:1])
    out["cap 확장 후 흡입 재개"] = w.F_uw == 1
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TLENS():
    """★[M-80] 큰 그림 리뷰 렌즈 발견의 봉합 게이트 — F1·F2·F3·F5·F6·④층·epoch·role."""
    out = {}

    # F1 — 담보∩기금 노트 겹침 거부(구 KeyError 크래시·audit 파손)
    w = World(); _in(w, "a1", 10)
    ref = _redeem(w, "a1", _ln(w, "a1"), "a0")
    _in(w, "a2", 5)
    X = _ln(w, "a2")
    try:
        _uw(w, "a2", ref, [X], 10, [X]); out["F1 담보∩기금 거부"] = False
    except Fl21Error:
        out["F1 담보∩기금 거부"] = w.audit()["ok"]      # ★파손 없이 롤백

    # F2 — REQUEST 부정형 inner가 강제-포함에서 크래시 대신 강등(audit 청결)
    w2 = World(); _in(w2, "a0", 5)
    w2.request({"garbage": 1})
    for _ in range(w2.GEN["window_L"] + 1):
        w2.tick()
    forced = [e for e in w2.log if e["env"]["typ"] == "FORCE"]
    out["F2 부정형 inner 강등"] = (bool(forced)
                               and forced[-1]["_force"]["included"] is False
                               and not w2.pending and w2.audit()["ok"])

    # F3 — ATTEST_FAIL 후 앵커 DELIVER 거부(판정 내구성) · 부보 청구로 배상 발동 확인
    w3 = World(); _in(w3, "a1", 40)
    ref3 = _redeem(w3, "a1", _ln(w3, "a1"), "a0")
    _in(w3, "a2", 40)
    _split(w3, "a2", _ln(w3, "a2"), [20, 20])
    _uw(w3, "a2", ref3, _byface(w3, "a2", 20)[:1], 0)
    w3.submit(w3.sign_env("operator", "ATTEST_FAIL",
                          {"ref": ref3, "reason": "att_missing", "role": "producer"}))
    try:
        w3.submit(w3.sign_env("a0", "DELIVER", {"anchor": "a0", "ref": ref3}))
        out["F3 FAIL후 DELIVER 거부"] = False
    except Fl21Error:
        out["F3 FAIL후 DELIVER 거부"] = ref3 in w3.redeem_pending
    w3.tick()                                          # 판정이 살아 정산으로 배상
    rec = _settle_recs(w3)[-1]["_force"]["settled"][0]
    out["F3 판정 내구·배상 발동"] = rec["comp"] > 0 and w3.bal("a1") == rec["comp"]

    # F5 — BLOCK 부정형 다리(비-Fl21Error) 원자 롤백
    w5 = World(); _in(w5, "a1", 10)
    good = w5.sign_env("a1", "XFER", {"frm": "a1", "to": "a2", "note": _ln(w5, "a1")})
    bad = w5.sign_env("a1", "SPLIT", {"owner": "a1"}, nonce=1)   # parts 없음
    b2 = w5.bal("a2")
    try:
        w5.submit(w5.sign_env("operator", "BLOCK", {"legs": [good, bad]}))
        out["F5 부정형 다리 롤백"] = False
    except Fl21Error:
        out["F5 부정형 다리 롤백"] = w5.bal("a2") == b2 and w5.audit()["ok"]

    # F6 — 흡입-결박 단발 초과 없음(F_uw ≤ cap) · 넘길 적립은 정지(fund=[]로 수리)
    w6 = World(gen={"fq_mult": 1, "fq_base": 2})       # cap = 2
    _in(w6, "a1", 40)
    r6 = _redeem(w6, "a1", _ln(w6, "a1"), "a0")
    _in(w6, "a2", 20)                                  # cov 20 / exp 40 = β 0.5 ✓
    _uw(w6, "a2", r6, [_ln(w6, "a2")], 20, [])         # prem_f=10 ≫ cap 2 → 결박 0
    out["F6 단발 초과 없음"] = w6.F_uw == 0 and w6.audit()["ok"]   # 넘길 적립 정지

    # ④ F_uw 다중청구 비례(잔여-재분배) — 서로 다른 인수자가 F_uw 층에서 나눔
    w4 = World(genesis_agents=("a0", "a1", "a2", "a3", "a4", "a5"))
    for h in ("a1", "a3"):
        _in(w4, h, 40); _redeem(w4, h, _ln(w4, h), "a0")
    refs = sorted(w4.redeem_pending)
    _in(w4, "a4", 30)
    _split(w4, "a4", _ln(w4, "a4"), [20, 10])
    _uw(w4, "a4", refs[0], _byface(w4, "a4", 20), 20, _byface(w4, "a4", 10))
    _in(w4, "a5", 20)
    _uw(w4, "a5", refs[1], [_ln(w4, "a5")], 0)
    for _ in range(w4.GEN["redeem_T"]):
        w4.tick()
    recs4 = {r["ref"]: r for r in _settle_recs(w4)[-1]["_force"]["settled"]}
    out["④ F_uw 다중 배분 보존"] = (sum(r["fund"] for r in recs4.values()) <= 20
                              and w4.audit()["ok"])

    # epoch 롤백 원자성 — epoch가 _STATE에 결박(state_root)
    out["epoch 상태 결박"] = "epoch" in World._STATE

    # role 선택 검증
    w7 = World(); _in(w7, "a1", 10)
    r7 = _redeem(w7, "a1", _ln(w7, "a1"), "a0")
    try:
        w7.submit(w7.sign_env("operator", "ATTEST_OK",
                              {"ref": r7, "reason": "x", "role": "bogus"}))
        out["role 부정값 거부"] = False
    except Fl21Error:
        out["role 부정값 거부"] = True
    w7.submit(w7.sign_env("operator", "ATTEST_OK", {"ref": r7, "reason": "x"}))
    out["role 생략 허용"] = w7.audit()["ok"]

    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TDET():
    w, _ = _uw_world()
    for _ in range(w.GEN["redeem_T"]):
        w.tick()
    a1, a2 = w.audit(), w.audit()
    return {"pass": a1 == a2 and a1["ok"]}


def gate_TCLK():
    w = World()
    _in(w, "a0", 10)
    for _ in range(3):
        w.tick()
    return {"pass": w.audit()["ok"]}


def gate_TJOBT():
    """★FL2.2 J-1 — 잡별 시한: 짧은-T 조기 성숙 · 긴-T 지연 성숙 · 무지정 = GEN 기본 ·
    조항 거부(T ≤ window_L · 상한 초과 · OFF-세계) · rp["T"] 결박(state_root)."""
    out = {}
    w = World(gen={"redeem_T": 6, "redeem_T_max": 20})
    _in(w, "a1", 30)
    _split(w, "a1", _ln(w, "a1"), [10, 10, 10])
    ns = _byface(w, "a1", 10)
    w.submit(w.sign_env("a1", "REDEEM", {"holder": "a1", "note": ns[0],
                                         "anchor": "a0", "T": 4}))
    w.submit(w.sign_env("a1", "REDEEM", {"holder": "a1", "note": ns[1],
                                         "anchor": "a0", "T": 12}))
    w.submit(w.sign_env("a1", "REDEEM", {"holder": "a1", "note": ns[2],
                                         "anchor": "a0"}))          # 기본 T=6
    for _ in range(4):
        w.tick()
    recs = _settle_recs(w)
    out["짧은-T 조기 성숙(4틱)"] = bool(recs) and         len(recs[-1]["_force"]["returned"]) == 1
    for _ in range(2):
        w.tick()                                    # epoch 6 — 기본-T 성숙
    out["기본-T 성숙(6틱)"] = len(_settle_recs(w)[-1]["_force"]["returned"]) == 1
    out["긴-T 미성숙(6틱)"] = len(w.redeem_pending) == 1
    for _ in range(6):
        w.tick()                                    # epoch 12 — 긴-T 성숙
    out["긴-T 성숙(12틱)"] = not w.redeem_pending and w.bal("a1") == 30
    for bad, why in ((3, "T ≤ window_L"), (21, "상한 초과"), (0, "비양수"),
                     ("x", "비정수")):
        try:
            _in(w, "a2", 10)
            w.submit(w.sign_env("a2", "REDEEM", {"holder": "a2",
                                                 "note": _ln(w, "a2"),
                                                 "anchor": "a0", "T": bad}))
            out[f"조항 거부({why})"] = False
        except Fl21Error:
            out[f"조항 거부({why})"] = True
    woff = World(gen={"redeem_T": 0})
    _in(woff, "a1", 10)
    try:
        woff.submit(woff.sign_env("a1", "REDEEM", {"holder": "a1",
                                                   "note": _ln(woff, "a1"),
                                                   "anchor": "a0", "T": 5}))
        out["OFF-세계 거부"] = False
    except Fl21Error:
        out["OFF-세계 거부"] = True
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TPUBREPLAY():
    """★FL2.2 J-2 — H7 공개-리플레이: 시드-독립 세계가 로그 전량을 재검증(전-상태·
    head_sig 포함) · fp0/log_id 재유도 일치 · 변조(항목·서명) 검출 · 부보-정산 포함."""
    out = {}
    w = World(gen={"redeem_T": 4})
    _in(w, "a1", 40)
    ref = _redeem(w, "a1", _ln(w, "a1"), "a0")
    _in(w, "a2", 40)
    _split(w, "a2", _ln(w, "a2"), [20, 20])
    _uw(w, "a2", ref, _byface(w, "a2", 20)[:1], 0)
    _in(w, "a0", 7)
    for _ in range(w.GEN["redeem_T"]):
        w.tick()                                    # 폭포 정산 포함 로그
    pks = {p: w.reg.pk(p).hex() for p in ("operator", "a0", "a1", "a2", "a3")}
    pub = World.from_public(pks, "fl23-ref", ("a0", "a1", "a2", "a3"),
                            gen={"redeem_T": 4})
    out["fp0 재유도 일치"] = pub.fp0 == w.fp0
    out["log_id 재유도 일치"] = pub.log_id == w.log_id
    r = pub.replay_verify(w.log)
    out["★전-상태 공개 재검증"] = r["ok"] is True and         r["state_root"] == w.state_root()
    # 변조 검출 — 항목·서명·상태
    import copy as _c
    bad = _c.deepcopy(w.log)
    bad[3]["state_root"] = "00" * 32
    pub2 = World.from_public(pks, "fl23-ref", ("a0", "a1", "a2", "a3"),
                             gen={"redeem_T": 4})
    out["결박-변조 검출"] = pub2.replay_verify(bad)["ok"] is False
    bad2 = _c.deepcopy(w.log)
    bad2[2]["head_sig"] = "00" * 64
    pub3 = World.from_public(pks, "fl23-ref", ("a0", "a1", "a2", "a3"),
                             gen={"redeem_T": 4})
    out["서명-변조 검출"] = pub3.replay_verify(bad2)["ok"] is False
    try:
        World.from_public({"operator": pks["operator"]}, "x", ("a0",))
        out["공개키 누락 거부"] = False
    except Fl21Error:
        out["공개키 누락 거부"] = True
    out["pass"] = all(v is True for v in out.values())
    return out


def main():
    out = {"T-INHERIT 승계": gate_TINHERIT(), "T-UW 인수": gate_TUW(),
           "T-UW-NEG 적대": gate_TUWNEG(), "T-FLOOR 요율하한": gate_TFLOOR(),
           "T-TO-UNCOV 시한반환": gate_TTOUNCOV(),
           "T-TO-COV 폭포": gate_TTOCOV(), "T-ATTFAIL 발화": gate_TATTFAIL(),
           "T-DELIVER 종결": gate_TDELIVER(), "T-CANCEL 종결": gate_TCANCEL(),
           "T-PRORATA 비례": gate_TPRORATA(), "T-BETA1 정리U": gate_TBETA1(),
           "T-EXIT 인수판": gate_TEXIT(), "T-OFF 사고OFF": gate_TOFF(),
           "T-K0E 위조": gate_TK0E(), "T-THROTTLE 흡입결박": gate_TTHROTTLE(),
           "T-LENS 리뷰봉합": gate_TLENS(),
           "T-DET 결정론": gate_TDET(), "T-CLK 시계": gate_TCLK(),
           "T-JOBT 잡별시한": gate_TJOBT(),
           "T-PUBREPLAY 공개리플레이": gate_TPUBREPLAY()}
    import kernel23_gates_fl23 as _G                 # ★FL2.3 신설 게이트 10(델타 8 + F-K1 + 치환·차등)
    out.update(_G.run_all())
    out["verdict"] = {k: v["pass"] for k, v in out.items()}
    out["verdict"]["K23_SELFTEST_PASS"] = all(out["verdict"].values())
    os.makedirs(os.path.join(_HERE, "results"), exist_ok=True)
    with open(os.path.join(_HERE, "results", "kernel23_selftest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=1, default=str)
    print(json.dumps(out["verdict"], ensure_ascii=False, indent=1))
    return 0 if out["verdict"]["K23_SELFTEST_PASS"] else 1


if __name__ == "__main__":
    sys.exit(main())
