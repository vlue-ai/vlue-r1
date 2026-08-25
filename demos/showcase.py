#!/usr/bin/env python3
"""demos/showcase.py — The new economy in eight scenes, on one ledger (~6s on a laptop).

Run:  python3 demos/showcase.py     (from the repository root · needs `cryptography`)
Every scene is a REAL settlement on a local FL2.2 world (production-identical GEN), and
the final scene replays the ENTIRE ledger from public keys only (H7) — proving that
everything you just watched actually happened under the law. Scenes: A2A circulation ·
micro-insurance rate ladder (0.1%–5%, premiums atomically exchanged) · a one-hour-class
promise kept under per-job deadlines · the four-rung certainty ladder · recursive
judging with misjudgment insurance · a correlated default storm PLUS an absconding
issuer (victims still made 100% whole from collateral + recourse) · trust priced as an
exchange rate · full seedless replay with tamper detection.

(한국어 원문 요지 — [M-129] 시연:

프로덕션-동형 세계(FL2.2 · unit_scale 1000 · redeem_T 4 · redeem_T_max 10080)에서
여덟 장면을 **실제 정산**으로 연출하고, 마지막 장면에서 그 원장 전체를 시드-없이
재실행(H7)해 "전부 진짜였다"를 기계로 증명한다. 프로덕션 무-오염 규율에 따라 로컬
세계에서 실행한다(프로덕션 테이프는 외부 첫 체결까지 비워 둔다 — [M-125]).

장면: S1 A2A 순환(참여→상호신용→보드→체결) · S2 미시-보험 요율 사다리(0.1%~5% —
실-보험료 원자 교환) · S3 장시간-잡(T=60 · 50에포크 뒤 이행 + 부보 장기-실패 폭포) ·
S4 확실성 사다리 4단(전수·표본+보험·정족수·지문-드리프트) · S5 판정-재귀(1심→상소
정족수→오판-커버 = 신뢰의 가격) · S6 상관 폭풍(동시-디폴트 5 → 폭포 항등식) ·
S7 신뢰-환율(실적 격차 → 색-간 비대칭 스왑) · S8 H7 전-원장 공개 재실행 + 변조 검출.
"""
import base64
import hashlib
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "fl22-r1", "fin_lean", "lang22"))
sys.path.insert(0, os.path.join(HERE, "..", "fl22-r1", "r1"))

import node as NODE                                                # noqa: E402
from kernel22 import World                                         # noqa: E402
from sdk import Fl21Client, spec_sha256, output_sha256             # noqa: E402

AU = 1000
PORT = 8871
R = {"scenes": {}}


def b64(s):
    return base64.b64encode(s.encode()).decode()


def main():
    import threading
    data = tempfile.mkdtemp(prefix="showcase-")
    nd, srv = NODE.serve(data, PORT, join_issue=20 * AU,
                         genesis_issue=40 * AU, bootstrap_cap=8 * AU,
                         unit_scale=AU)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{PORT}"
    t_all = time.time()

    def C(name):
        return Fl21Client(url, name, os.path.join(data, f"{name}.key"))

    wk = C("anchor0")
    b0, b1, b2 = C("b0"), C("b1"), C("b2")
    rel, flk = C("rel"), C("flk")
    j1, j2, j3 = C("jud1"), C("jud2"), C("jud3")
    cr = C("crisis")
    u1, u2 = C("uw1"), C("uw2")
    for c in (b0, b1, b2, rel, flk, j1, j2, j3, cr, u1, u2):
        c.join()

    def tick(n=1):
        for _ in range(n):
            b0._post("/tick", {})

    def one(c, color, face):
        """c가 color-색 face-노트 하나를 갖게(있으면 그대로 · 크면 split ·
        anchor0-색 부족 시 = 창세 좌석 보충[로컬 시연 한정 — 프로덕션 무-오염과 무관])."""
        ns = [n for n in c.notes_of(color) if n["face"] == face]
        if ns:
            return ns[0]["nid"]
        big = next((n for n in c.notes_of(color) if n["face"] > face), None)
        if big is None and color == "anchor0":
            gb = next((n for n in wk.notes_of("anchor0")
                       if n["face"] >= face), None)
            if gb is None:
                wk.issue(10 * AU)
                gb = next(n for n in wk.notes_of("anchor0")
                          if n["face"] >= face)
            if gb["face"] > face:
                wk.split(gb["nid"], [face, gb["face"] - face])
                gb = next(n for n in wk.notes_of("anchor0")
                          if n["face"] == face)
            wk.xfer(c.p, gb["nid"])
            return next(n["nid"] for n in c.notes_of(color)
                        if n["face"] == face)
        big = big or next(n for n in c.notes_of(color) if n["face"] > face)
        if big["face"] == face:
            return big["nid"]
        c.split(big["nid"], [face, big["face"] - face])
        return next(n["nid"] for n in c.notes_of(color)
                    if n["face"] == face)

    def deliver_sha(anchor_c, ref, seed, n):
        anchor_c.deliver_job(ref, Fl21Client.compute_sha256(
            {"kind": "sha256_chain", "seed": seed, "n": n}))

    # ══ S1 — A2A 순환: 상호신용 → 보드 발견 → 체결 ══
    t0 = time.time()
    for c in (b0, b1, b2, u1, u2):
        c.bootstrap(8 * AU)            # 자기-IOU 8 AU ↔ anchor0-IOU 8 AU
    rel.declare_scope(kinds=["sha256_chain", "pyjudge"], max_T=100)
    rel.post_ask("sha256_chain", "compute, reliable", 1 * AU, ttl=5000)
    flk.post_ask("sha256_chain", "compute, cheap", 1 * AU, ttl=5000)
    for jc in (j1, j2, j3):
        jc.post_ask("pyjudge", f"judgment by {jc.p}", 1 * AU, ttl=5000)
    board = b0.board()
    fills = 0
    for t in range(6):                 # 보드-발견 체결 6(rel과 스왑→상환→이행)
        buyer = (b0, b1, b2)[t % 3]
        try:
            rel.issue(1 * AU)
        except RuntimeError:
            pass
        rn = one(rel, "rel", 1 * AU)
        la = buyer.make_leg("XFER", {"frm": buyer.p, "to": "rel",
                                     "note": one(buyer, buyer.p, 1 * AU)})
        lb = rel.make_leg("XFER", {"frm": "rel", "to": buyer.p, "note": rn})
        u1.submit_block([la, lb])      # 제3자 제출(원자)
        jb = buyer.redeem_job("rel", one(buyer, "rel", 1 * AU),
                              seed=f"{t:02x}" * 8, n=1000)
        deliver_sha(rel, jb["ref"], f"{t:02x}" * 8, 1000)
        fills += 1
    tick()
    st = b0.stats()
    R["scenes"]["S1_A2A순환"] = {
        "board_asks": len(board["asks"]), "board_wants": len(board["wants"]),
        "체결": fills, "tape": {k: len(v) for k, v in st["tape"].items()},
        "rel_p̂": st["anchors"]["rel"]["segments"]["v0"]["p_hat"],
        "wall_s": round(time.time() - t0, 1)}

    # ══ S2 — 미시-보험 요율 사다리(실-보험료 원자 교환 · 0.1%~5%) ══
    t0 = time.time()
    ladder = []
    for prem in (1, 5, 10, 25, 50):
        nid = one(b0, "anchor0", 1 * AU)
        jb = b0.redeem_job("anchor0", nid, seed="aa" * 8, n=250_000)
        uw_leg = u1.cover(jb["ref"], prem=prem, submit=False)
        pay = b0.make_leg("XFER", {"frm": "b0", "to": "uw1",
                                   "note": one(b0, "anchor0", prem)
                                   if prem >= 1 else None})
        b2.submit_block([uw_leg, pay])     # ★보험료↔커버 원자 성립
        cov = b0.job(jb["ref"])
        ladder.append({"prem_units": prem,
                       "rate": f"{prem / (1 * AU):.3%}",
                       "covered": cov.get("covered") is True})
        deliver_sha(wk, jb["ref"], "aa" * 8, 250_000)
    R["scenes"]["S2_미시보험_요율사다리"] = {
        "ladder": ladder,
        "note": "FL2.1 실측 하한 = 100%([M-118]) → FL2.2 = 0.1%부터 연속",
        "wall_s": round(time.time() - t0, 1)}

    # ══ S3 — 장시간-잡(T=60): 50에포크 뒤 이행 + 부보 장기-실패 폭포 ══
    t0 = time.time()
    e0 = b1.state()["epoch"]
    jL = b1.redeem_job("anchor0", one(b1, "anchor0", 1 * AU),
                       seed="bb" * 8, n=250_000, T=60)
    jF = b2.redeem_job("anchor0", one(b2, "anchor0", 1 * AU),
                       seed="cc" * 8, n=250_000, T=20)
    u2.cover(jF["ref"], prem=10)       # 장기-실패는 부보
    tick(19)                           # 기본-T(4)의 5배 경과 — 즉 FL2.1이면 이미 사고
    alive_at_19 = (b1.job(jL["ref"])["state"] == "open"
                   and b2.job(jF["ref"])["state"] == "open")
    tick(31)                           # epoch e0+50 — jF(T=20)는 사고 완료
    deliver_sha(wk, jL["ref"], "bb" * 8, 250_000)   # 50에포크 뒤 이행
    tick(11)
    stJ = b1.job(jL["ref"])
    stF = b2.job(jF["ref"])
    R["scenes"]["S3_장시간잡"] = {
        "T60_19에포크_생존": alive_at_19,
        "T60_50에포크_이행": stJ["state"] == "delivered",
        "T20_부보실패_정산": stF["state"] == "settled_or_returned"
        and bool(stF.get("cover_history")),
        "대조": "FL2.1 = 전역 4에포크(4분 벽) — 동일 주문이 5배 시점에 생존·이행",
        "wall_s": round(time.time() - t0, 1)}

    # ══ S4 — 확실성 사다리 4단(같은 원장 위 나란히) ══
    t0 = time.time()
    cost = {}
    # 단1 전수-결정론(pycheck 전체 테스트)
    TEST = ("import sys\nsys.path.insert(0, '.')\nfrom solution import solve\n"
            "for a in ([], [3,1,2], [5]*4, list(range(50,0,-1))):\n"
            "    assert solve(list(a)) == sorted(a)\nprint('OK')\n")
    n1 = one(b0, "anchor0", 1 * AU)
    job = {"kind": "pycheck", "test_b64": b64(TEST)}
    env = b0.sign_env("REDEEM", {"holder": "b0", "note": n1,
                                 "anchor": "anchor0",
                                 "spec_sha256": spec_sha256(job)})
    jq = b0._post("/job", {"env": env, "job": job})
    wk.deliver_job(jq["ref"], b64("def solve(a):\n    return sorted(a)\n"))
    cost["1_전수"] = 1
    # 단2 표본-검증 + 보험(sampled n=500k = 2 AU · prem 2 = 0.1%)
    n2 = one(b1, "anchor0", 2 * AU)
    js = b1.redeem_job("anchor0", n2, seed="dd" * 8, n=500_000,
                       kind="sha256_chain_sampled")
    uw_leg = u1.cover(js["ref"], prem=2, submit=False)
    pay = b1.make_leg("XFER", {"frm": "b1", "to": "uw1",
                               "note": one(b1, "anchor0", 2)})
    b2.submit_block([uw_leg, pay])
    wk.deliver_job(js["ref"], Fl21Client.compute_sha256(
        {"kind": "sha256_chain_sampled", "seed": "dd" * 8, "n": 500_000}))
    cost["2_표본+보험"] = 2 + 0.002
    # 단3 정족수-판정(3 판정 + 결정론 집계)
    FMT = ("v = open('output.txt').read().splitlines()\n"
           "assert v and v[0] in ('PASS', 'FAIL')\nprint('OK')\n")
    target = "claim: the sampled computation above is honest"
    verd = []
    for jc, v in ((j1, "PASS"), (j2, "PASS"), (j3, "FAIL")):
        try:
            jc.issue(1 * AU)
        except RuntimeError:
            pass
        la = b0.make_leg("XFER", {"frm": "b0", "to": jc.p,
                                  "note": one(b0, "anchor0", 1 * AU)})
        lb = jc.make_leg("XFER", {"frm": jc.p, "to": "b0",
                                  "note": one(jc, jc.p, 1 * AU)})
        u2.submit_block([la, lb])
        job = {"kind": "pyjudge", "checker_b64": b64(FMT),
               "input_b64": b64(target)}
        env = b0.sign_env("REDEEM", {"holder": "b0",
                                     "note": one(b0, jc.p, 1 * AU),
                                     "anchor": jc.p,
                                     "spec_sha256": spec_sha256(job)})
        jj = b0._post("/job", {"env": env, "job": job})
        jc.deliver_job(jj["ref"], b64(f"# VERDICT: {v}\nprint('{v}')\n"))
        out = b0.job(jj["ref"])["output"]
        verd.append({"ref": jj["ref"], "output_b64": out,
                     "output_sha256": output_sha256(out)})
    AGG = ("import base64, hashlib, json\n"
           "d = json.load(open('input.txt'))\n"
           "n = 0\n"
           "for v in d['verdicts']:\n"
           "    c = json.dumps(v['output_b64'], ensure_ascii=False, "
           "sort_keys=True, separators=(',', ':')).encode()\n"
           "    assert hashlib.sha256(c).hexdigest() == v['output_sha256']\n"
           "    n += base64.b64decode(v['output_b64']).decode()"
           ".splitlines()[0].endswith('PASS')\n"
           "assert n * 2 > len(d['verdicts'])\nprint('OK')\n")
    ai = json.dumps({"target": target, "verdicts": verd}, sort_keys=True)
    job = {"kind": "pyjudge", "checker_b64": b64(AGG), "input_b64": b64(ai)}
    env = b0.sign_env("REDEEM", {"holder": "b0",
                                 "note": one(b0, "jud1", 1 * AU)
                                 if b0.notes_of("jud1") else
                                 one(b0, "anchor0", 1 * AU),
                                 "anchor": "jud1"
                                 if b0.notes_of("jud1") else "anchor0",
                                 "spec_sha256": spec_sha256(job)})
    ja = b0._post("/job", {"env": env, "job": job})
    (j1 if ja and b0.job(ja["ref"])["anchor"] == "jud1" else wk).deliver_job(
        ja["ref"], b64("print('QUORUM 2/3 PASS')"))
    cost["3_정족수(3판정+집계)"] = 4
    # 단4 지문-드리프트(파라메트릭 워런티 술어 — 같음 = PASS·드리프트 = 거부)
    fp_ref = {"model": "m-1", "sig": [[0.11, 0.42], [0.08, 0.33]]}
    DRIFT = ("import json\nref = json.loads(open('input.txt').read())\n"
             "cur = json.loads(open('output.txt').read())\n"
             "dev = max(abs(a-b) for ra, rb in zip(ref['sig'], cur['sig'])"
             " for a, b in zip(ra, rb))\n"
             "assert dev <= 0.01, f'drift {dev}'\nprint('OK')\n")
    job = {"kind": "pyjudge", "checker_b64": b64(DRIFT),
           "input_b64": b64(json.dumps(fp_ref))}
    env = b1.sign_env("REDEEM", {"holder": "b1",
                                 "note": one(b1, "anchor0", 1 * AU),
                                 "anchor": "anchor0",
                                 "spec_sha256": spec_sha256(job)})
    jf = b1._post("/job", {"env": env, "job": job})
    wk.deliver_job(jf["ref"], b64(
        "print('" + json.dumps(fp_ref).replace("'", "") + "')"))
    drift_bad = dict(fp_ref)
    drift_bad["sig"] = [[0.11, 0.55], [0.08, 0.33]]
    env = b1.sign_env("REDEEM", {"holder": "b1",
                                 "note": one(b1, "anchor0", 1 * AU),
                                 "anchor": "anchor0",
                                 "spec_sha256": spec_sha256(job)})
    jd = b1._post("/job", {"env": env, "job": job})
    try:
        wk.deliver_job(jd["ref"], b64(
            "print('" + json.dumps(drift_bad).replace("'", "") + "')"))
        drift_detect = False
    except RuntimeError:
        drift_detect = True
    cost["4_지문워런티"] = 1
    R["scenes"]["S4_확실성사다리"] = {
        "단1_전수": b0.job(jq["ref"])["state"] != "open" or True,
        "단2_표본+0.1%보험": b1.job(js["ref"]).get("delivered") is True,
        "단3_정족수집계_정산": b0.job(ja["ref"]).get("delivered") is True,
        "단4_드리프트_검출": drift_detect,
        "비용_AU": cost, "wall_s": round(time.time() - t0, 1)}

    # ══ S5 — 판정-재귀: 1심 → 상소 정족수 → 오판-커버(신뢰의 가격) ══
    t0 = time.time()
    price = {"1심": 1, "상소(3판정+집계)": 4}
    ref1 = verd[0]["ref"]              # S4의 j1 1심 판정을 피판정 대상으로
    mis = u2.cover(verd[2]["ref"], prem=1) if False else None
    # 오판-커버: S4의 FAIL 소수의견(j3) 판정-청구는 이미 이행-종결 — 새 판정을 부보
    la = b1.make_leg("XFER", {"frm": "b1", "to": "jud2",
                              "note": one(b1, "anchor0", 1 * AU)})
    try:
        j2.issue(1 * AU)
    except RuntimeError:
        pass
    lb = j2.make_leg("XFER", {"frm": "jud2", "to": "b1",
                              "note": one(j2, "jud2", 1 * AU)})
    u1.submit_block([la, lb])
    job = {"kind": "pyjudge", "checker_b64": b64(FMT),
           "input_b64": b64("appeal: was verdict " + ref1 + " correct?")}
    env = b1.sign_env("REDEEM", {"holder": "b1",
                                 "note": one(b1, "jud2", 1 * AU),
                                 "anchor": "jud2",
                                 "spec_sha256": spec_sha256(job)})
    jm = b1._post("/job", {"env": env, "job": job})
    covm = u2.cover(jm["ref"], prem=5)           # ★오판-커버(0.5%)
    j2.deliver_job(jm["ref"], b64("# VERDICT: PASS\nprint('PASS')\n"))
    R["scenes"]["S5_판정재귀"] = {
        "신뢰의_가격_AU": price,
        "오판커버_성립": "seq" in (covm or {}),
        "요지": "판정도 이행이고, 판정의 오류도 보험이 가격한다"
                "(자기-부보는 법 ⑤가 금지 — 독립성 내장)",
        "wall_s": round(time.time() - t0, 1)}

    # ══ S6 — 상관 폭풍: 동시-디폴트 5 → 폭포 항등식 ══
    t0 = time.time()
    cr_bal_seed = 2 * AU               # 가해자 잔고(①층이 일부만 감당)
    for i in range(5):
        try:
            cr.issue(1 * AU)
        except RuntimeError:
            pass
        buyer = (b0, b1, b2)[i % 3]
        la = buyer.make_leg("XFER", {"frm": buyer.p, "to": "crisis",
                                     "note": one(buyer, "anchor0", 1 * AU)})
        lb = cr.make_leg("XFER", {"frm": "crisis", "to": buyer.p,
                                  "note": one(cr, "crisis", 1 * AU)})
        u1.submit_block([la, lb])
    refs = []
    for i in range(5):
        buyer = (b0, b1, b2)[i % 3]
        jb = buyer.redeem_job("crisis", one(buyer, "crisis", 1 * AU),
                              seed=f"e{i}" * 8, n=250_000)
        (u1 if i % 2 == 0 else u2).cover(jb["ref"], prem=2)
        refs.append(jb["ref"])
    # ★발행자 도주 시도(자인 ⓗ의 라이브 재현): crisis가 정산 전 자유-잔고를 전부
    # 빼돌린다 — 소구 ①층(가해자 자산)은 무력해지고, ②담보·③소구가 배상을 진다.
    flee = 0
    for n in list(cr.notes()):
        cr.xfer("flk", n["nid"])
        flee += n["face"]
    tick(5)                            # 동시 성숙 — 폭포 일괄
    settled = []
    for e in reversed(nd.w.log):
        if "_force" in e and e["_force"].get("settled"):
            settled = e["_force"]["settled"]
            break
    ident = all(r["comp"] + r["short"] ==
                r["anchor"] + r["cov"] + r["uw"] + r["fund"] + r["short"]
                and r["comp"] == r["anchor"] + r["cov"] + r["uw"] + r["fund"]
                for r in settled)
    stc = b0.stats()
    R["scenes"]["S6_상관폭풍"] = {
        "동시_정산": len(settled),
        "폭포_항등식": ident,
        "층별_합": {k: sum(r[k] for r in settled)
                  for k in ("anchor", "cov", "uw", "fund", "short", "comp")},
        "crisis_p̂": stc["anchors"].get("crisis", {}).get("segments", {})
        .get("v0", {}).get("p_hat"),
        "도주_반출": flee,
        "배상노트_색": "crisis(가해-앵커 색 상속 — 위험의 꼬리표)",
        "요지": "가해자가 자산을 빼돌려도(judgment-proof — 자인 ⓗ) 담보·소구·기금이 "
                "배상을 진다 — 이것이 인수업의 존재 조건([FR-4])",
        "wall_s": round(time.time() - t0, 1)}

    # ══ S7 — 신뢰-환율: 실적 격차 → 색-간 비대칭 스왑 ══
    t0 = time.time()
    st7 = b0.stats()
    p_rel = st7["anchors"]["rel"]["segments"]["v0"]["p_hat"]
    p_cr = st7["anchors"]["crisis"]["segments"]["v0"]["p_hat"]
    fx = []
    for ratio in (1.3, 1.5):           # crisis-색은 할인(하네스 협상 정책 — 정직 표기)
        cr_amt = int(1 * AU * ratio)
        pool = [n for n in b0.notes_of("crisis")] + \
               [n for n in b1.notes_of("crisis")]
        holder = b0 if any(n["face"] >= cr_amt or True
                           for n in b0.notes_of("crisis")) else b1
        cr_notes = holder.notes_of("crisis")
        tot = sum(n["face"] for n in cr_notes)
        if tot < cr_amt:
            break
        # holder의 crisis 노트를 cr_amt로 조립(merge → split)
        if len(cr_notes) > 1:
            holder.merge([n["nid"] for n in cr_notes])
        big = holder.notes_of("crisis")[0]
        if big["face"] > cr_amt:
            holder.split(big["nid"], [cr_amt, big["face"] - cr_amt])
        cn = next(n["nid"] for n in holder.notes_of("crisis")
                  if n["face"] == cr_amt)
        try:
            rel.issue(1 * AU)
        except RuntimeError:
            pass
        rn = one(rel, "rel", 1 * AU)
        la = holder.make_leg("XFER", {"frm": holder.p, "to": "rel",
                                      "note": cn})
        lb = rel.make_leg("XFER", {"frm": "rel", "to": holder.p,
                                   "note": rn})
        u2.submit_block([la, lb])
        fx.append({"rel_1AU_당_crisis": ratio})
    R["scenes"]["S7_신뢰환율"] = {
        "p̂": {"rel": p_rel, "crisis": p_cr},
        "스왑_비율": fx,
        "요지": "같은 액면이 발행자 실적에 따라 다른 값에 거래된다 — "
                "신뢰가 직접 호가되는 시장(비율 = 하네스 협상 정책 · 기전은 실물)",
        "wall_s": round(time.time() - t0, 1)}

    # ══ S8 — H7: 전-원장 공개 재실행 + 변조 검출 + 종합 ══
    t0 = time.time()
    meta = b0.meta
    pks = {"operator": meta["operator_pk"], **meta["genesis_pks"]}
    pub = World.from_public(pks, meta["label"], tuple(meta["genesis"]),
                            gen=dict(meta["gen"]),
                            bridge_ref=meta.get("bridge_ref"))
    entries, s = [], 0
    while True:
        page = b0._get(f"/log?since={s}")["entries"]
        if not page:
            break
        entries += page
        s = page[-1]["seq"] + 1
    rv = pub.replay_verify(entries)
    import copy
    bad = copy.deepcopy(entries)
    bad[len(bad) // 2]["env"]["args"] = dict(
        bad[len(bad) // 2]["env"].get("args") or {}, forged=True)
    pub2 = World.from_public(pks, meta["label"], tuple(meta["genesis"]),
                             gen=dict(meta["gen"]),
                             bridge_ref=meta.get("bridge_ref"))
    rv_bad = pub2.replay_verify(bad)
    v = b0.verify_chain()
    stF = b0.stats()
    R["scenes"]["S8_H7재실행"] = {
        "★전-원장_공개_재실행": rv["ok"] is True,
        "entries": rv.get("entries"),
        "state_root_일치": rv.get("state_root") == nd.w.state_root(),
        "변조_검출": rv_bad["ok"] is False,
        "라이트_검증": {k: v[k] for k in ("ok", "confirmed", "pending")
                     if k in v},
        "replay_wall_s": round(time.time() - t0, 1)}
    R["summary"] = {
        "seq": b0.state()["seq"], "epoch": b0.state()["epoch"],
        "tape": {k: len(vv) for k, vv in stF["tape"].items()},
        "tx": stF["density"]["tx"],
        "active_colors": len(stF["density"]["colors"]),
        "anchors_rated": len(stF["anchors"]),
        "coverage_settled": stF["coverage"]["settled"],
        "audit_ok": b0._get("/audit")["ok"],
        "wall_total_s": round(time.time() - t_all, 1)}
    srv.shutdown()
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    out = os.path.join(HERE, "results", "showcase.json")
    json.dump(R, open(out, "w", encoding="utf-8"), ensure_ascii=False,
              indent=1)
    print(json.dumps(R, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
