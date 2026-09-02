#!/usr/bin/env python3
"""diff_storm23.py — ★술어 3 차등 시험: 같은 (typ,args,p) 열을 kernel22·kernel23 에 각자-서명으로 흘려
수용/거부 열 · 최종 잔고 멀티셋 · 회계 스칼라 · _force 결과(공통 필드) 가 **동일**한지 단언한다.
head·state_root 는 비교 제외(세대 정의 차이) · nonce 는 세계별 sign_env 가 각자 관리(J-7 로 실패 후 갈린다).
상한(J-6)은 0(끔)으로 — 법-동치 검사이고 상한은 T-NOTECAP 이 따로 잰다. 「치환은 assert」: 직접 대입 잔존 0 도 여기서.
실행: python3 diff_storm23.py [seeds=11,22,33] [ops=200]"""
import os, random, re, sys, json
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "lang22")); sys.path.insert(0, _HERE)
import kernel22 as K22, kernel23 as K23                                # noqa: E402

AGENTS = ("a0", "a1", "a2", "a3")
GEN22 = {"identity_budget": 16, "window_L": 3, "redeem_T": 4, "redeem_T_max": 40, "fq_mult": 1}
GEN23 = {**GEN22, "notes_per_owner_max": 0}

def sign(w, typ, args, p):
    return w.sign_env(p, typ, args)

def _resolve(w, args):
    """★ref 는 log_id 를 담아 세대마다 다르다 — 생성기는 ("REF_BY_NID", nid) 표식을 쓰고 세계별로 푼다."""
    if args is None:
        return None
    out = {}
    for k, v in args.items():
        if isinstance(v, tuple) and v and v[0] == "REF_BY_NID":
            hit = [r for r, rp in w.redeem_pending.items() if rp["nid"] == v[1]]
            out[k] = hit[0] if hit else "0000000000000000"
        else:
            out[k] = v
    return out

def run_one(w, K, typ, args, p, legs=None):
    """한 세계에 적용 — (accepted, reason)"""
    args = _resolve(w, args)
    try:
        if typ == "BLOCK":
            lg = [w.sign_env(lp, lt, la) for (lt, la, lp) in legs]
            env = w.sign_env("operator", "BLOCK", {"legs": lg})
        else:
            env = sign(w, typ, args, p)
        if typ == "TICK":
            w.tick()
        else:
            w.submit(env)
        return True, ""
    except K.Fl21Error as e:
        return False, str(e)

def gen_op(rng, w):
    """참조 세계(kernel22)의 상태로 다음 op 를 뽑는다 — ~25% 는 의도적 무효."""
    notes = [(nid, n) for nid, n in w.notes.items() if not n["owner"].startswith("@")]
    live = [a for a in AGENTS if a not in w.exited]
    r = rng.random()
    if r < 0.12 or not notes:
        a = rng.choice(live); return "EXT_IN", {"to": a, "amount": rng.randint(1, 60)}, "operator", None
    if r < 0.30:
        nid, n = rng.choice(notes); o = n["owner"]
        k = rng.randint(2, 4)
        if n["face"] >= k and rng.random() > 0.2:
            cuts = sorted(rng.sample(range(1, n["face"]), k - 1)) if n["face"] > k else list(range(1, k))
            parts = [b - a for a, b in zip([0] + cuts, cuts + [n["face"]])]
        else:
            parts = [1, n["face"]]                       # 합 불일치(무효)
        return "SPLIT", {"owner": o, "note": nid, "parts": parts}, (o if rng.random() > 0.1 else rng.choice(live)), None
    if r < 0.40:
        o = rng.choice(live); mine = [nid for nid, n in notes if n["owner"] == o]
        if len(mine) >= 2:
            ids = rng.sample(mine, min(len(mine), rng.randint(2, 3)))
            if rng.random() < 0.15: ids.append(rng.choice(notes)[0])   # 타인 노트 섞기(무효 가능)
            return "MERGE", {"owner": o, "notes": ids}, o, None
        return "TICK", {}, "operator", None
    if r < 0.52:
        nid, n = rng.choice(notes); to = rng.choice(live)
        return "XFER", {"frm": n["owner"], "to": to, "note": nid}, (n["owner"] if rng.random() > 0.15 else rng.choice(live)), None
    if r < 0.60:
        nid, n = rng.choice(notes); anchor = rng.choice(live)
        args = {"holder": n["owner"], "note": nid, "anchor": anchor}
        if rng.random() < 0.3: args["T"] = rng.choice([2, 5, 8, 50])   # 일부 무효(≤window_L · >max)
        if rng.random() < 0.3: args["spec_sha256"] = "ab" * 32           # r1 확장 필드(스펙-불투명)
        return "REDEEM", args, n["owner"], None
    if r < 0.68 and w.redeem_pending:
        ref = rng.choice(sorted(w.redeem_pending)); rp = w.redeem_pending[ref]
        who = rp["anchor"] if rng.random() > 0.2 else rng.choice(live)
        return "DELIVER", {"anchor": who, "ref": ("REF_BY_NID", rp["nid"])}, who, None
    if r < 0.76 and w.redeem_pending:
        ref = rng.choice(sorted(w.redeem_pending)); rp = w.redeem_pending[ref]
        cands = [a for a in live if a not in (rp["holder"], rp["anchor"])]
        if cands:
            u = rng.choice(cands); mine = [nid for nid, n in notes if n["owner"] == u]
            exp = w.notes[rp["nid"]]["face"]
            cov, tot = [], 0
            for nid in sorted(mine, key=int):
                f = w.notes[nid]["face"]
                if tot + f <= exp: cov.append(nid); tot += f
            if cov:
                return "UW", {"uw": u, "ref": ("REF_BY_NID", rp["nid"]), "cov_notes": cov, "prem": rng.randint(0, 3)}, u, None
        return "TICK", {}, "operator", None
    if r < 0.80 and w.redeem_pending:
        ref = rng.choice(sorted(w.redeem_pending)); rp = w.redeem_pending[ref]
        return "ATTEST_FAIL", {"ref": ("REF_BY_NID", rp["nid"]), "reason": "storm"}, "operator", None
    if r < 0.84 and w.redeem_pending:
        ref = rng.choice(sorted(w.redeem_pending)); rp = w.redeem_pending[ref]
        return "REDEEM_CANCEL", {"ref": ("REF_BY_NID", rp["nid"])}, (rp["holder"] if rng.random() > 0.2 else rng.choice(live)), None
    if r < 0.87:
        nid, n = rng.choice(notes)
        return "BURN", {"owner": n["owner"], "note": nid}, n["owner"], None
    if r < 0.93 and len(notes) >= 2:
        (n1, a), (n2, b) = rng.sample(notes, 2)
        if a["owner"] != b["owner"]:
            legs = [("XFER", {"frm": a["owner"], "to": b["owner"], "note": n1}, a["owner"]),
                    ("XFER", {"frm": b["owner"], "to": a["owner"], "note": n2}, b["owner"])]
            return "BLOCK", None, "operator", legs
    if r < 0.95:
        a = rng.choice(live); return "EXIT", {"a": a}, a, None
    return "TICK", {}, "operator", None

def _norm_owner(w, o):
    if o.startswith("@redeem:"):
        return "@redeem:" + w.redeem_pending[o[8:]]["nid"]
    if o.startswith("@uw:"):
        return "@uw:" + w.redeem_pending[o[4:]]["nid"]
    return o

def snapshot(w):
    bal = {}
    for nid, n in w.notes.items():
        bal.setdefault(_norm_owner(w, n["owner"]), []).append(n["face"])
    forces = []
    for e in w.log:
        if "_force" in e and e["env"]["typ"] == "TICK":
            fo = e["_force"]
            forces.append({"returned_n": len(fo["returned"]),
                           "settled": sorted(json.dumps({k: s[k] for k in ("comp", "short", "anchor", "cov", "uw", "fund")}, sort_keys=True) for s in fo["settled"])})
    return {"bal": {o: sorted(v) for o, v in bal.items()},
            "F": w.F, "F_uw": w.F_uw, "S": w.S, "ext_in": w.ext_in, "ext_out": w.ext_out,
            "epoch": w.epoch, "rp": sorted(rp["nid"] for rp in w.redeem_pending.values()),
            "uw": sorted(w.redeem_pending[r]["nid"] for r in w.uw_open),
            "exited": list(w.exited), "forces": forces}

def prim_audit():
    """「치환은 assert」 — kernel23 의 _apply/_settle/헬퍼에 직접 대입 잔존 0."""
    src = open(os.path.join(_HERE, "kernel23.py"), encoding="utf-8").read()
    body = src[src.index("    def _mint("):src.index("    # ── 정준 상태·서명 ──")] + \
           src[src.index("    def _apply("):src.index("    # ── ★J-2 승계")]
    bad = re.findall(r"self\.notes\[[^\]]+\]\s*(?:=|\[\"owner\"\]\s*=)|del self\.notes|self\.(?:F|F_uw|F_peak|S|ext_in|ext_out|epoch|note_ctr)\s*[+-]?=|self\.(?:redeem_pending|uw_open|locked_rooms|room_owner|nonces|Q|qual_burn)\[[^\]]+\]\s*=|self\.(?:exited|pending)\.(?:append|pop)", body)
    return bad

def main():
    seeds = [int(x) for x in (sys.argv[1] if len(sys.argv) > 1 else "11,22,33").split(",")]
    n_ops = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    bad_prim = prim_audit()
    print(f"[prim] 직접 대입 잔존: {len(bad_prim)} {bad_prim[:3]}")
    all_ok = not bad_prim
    for seed in seeds:
        rng = random.Random(seed)
        w22 = K22.World(master_seed=seed, gen=GEN22); w23 = K23.World(master_seed=seed, gen=GEN23)
        acc = rej = mism = 0
        for i in range(n_ops):
            typ, args, p, legs = gen_op(rng, w22)
            ok22, why22 = run_one(w22, K22, typ, args, p, legs)
            ok23, why23 = run_one(w23, K23, typ, args, p, legs)
            if ok22 != ok23:
                mism += 1
                if mism <= 5:
                    print(f"  seed {seed} op {i} {typ} p={p}: k22={'ok' if ok22 else why22[:50]} | k23={'ok' if ok23 else why23[:50]}")
            acc += ok22; rej += (not ok22)
        s22, s23 = snapshot(w22), snapshot(w23)
        same = s22 == s23
        a23 = w23.audit(); a22 = w22.audit()
        root_ok = w23._root_full() == w23.state_root()
        rej_entries = sum(1 for e in w23.log if e.get("kind") == "REJECT")
        print(f"seed {seed}: ops {n_ops} · 수용 {acc} · 거부 {rej} · 결정 불일치 {mism} · 최종상태 {'동일' if same else '★불일치'} · "
              f"audit22 {a22['ok']} audit23 {a23['ok']} · root 증분==전량 {root_ok} · REJECT 항 {rej_entries} · k23 log {len(w23.log)}")
        if not same:
            for k in s22:
                if s22[k] != s23[k]: print(f"    diff {k}: {str(s22[k])[:120]} | {str(s23[k])[:120]}")
        all_ok &= (mism == 0 and same and a22["ok"] and a23["ok"] and root_ok)
    print(json.dumps({"DIFF_STORM_PASS": all_ok}))
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
