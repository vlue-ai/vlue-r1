#!/usr/bin/env python3
"""★T-KDIFF — 커널 성능 패치의 「의미 불변」 차등 리플레이 검사([M-217] Phase B).

고정 재료(fixture) = 이전 커널이 기록한 원장(meta + entries). 현재 커널로 공개 세계(from_public)를 만들어
전량 리플레이하고, 매 항의 head·state_root·prev·w_epoch·_force 결박(_replay_into 내부)이 **바이트 동일**한지,
종단 전량-root == 증분-root, 맵 다이제스트 == sha256(canon(맵)), exited 색인 == 리스트, 불변식이 성립하는지를 본다.
하나라도 어긋나면 성능 패치는 의미를 바꾼 것이므로 반입 불가(FL2.4 재창세 후보로 격하).

사용: python3 kdiff_check.py <fixture.json> [...]   → JSON 한 줄/파일 · 전부 통과 시 exit 0
      import kdiff_check; kdiff_check.check(path) → dict
"""
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kernel23 import World, Fl23Error, _canon   # noqa: E402

FIXTURES = ("kdiff_fixture_v01.json", "kdiff_live_fl23_2026-09-03.json")
_HERE = os.path.dirname(os.path.abspath(__file__))


def fixture_paths():
    """모노레포(results/ 아래) · 공개 번들(스크립트 옆 동봉) 두 배치 모두에서 픽스처를 찾는다."""
    out = []
    for f in FIXTURES:
        for cand in (os.path.join(_HERE, "results", f), os.path.join(_HERE, f)):
            if os.path.exists(cand):
                out.append(cand)
                break
        else:
            raise FileNotFoundError(f"T-KDIFF 픽스처 부재: {f}")
    return out


def check(path):
    d = json.load(open(path, encoding="utf-8"))
    meta, entries = d["meta"], d["entries"]
    out = {"fixture": os.path.basename(path), "entries": len(entries)}
    pks = {"operator": meta.get("operator_pk0") or meta["operator_pk"], **meta["genesis_pks"]}
    w = World.from_public(pks, meta["label"], tuple(meta["genesis"]),
                          gen=dict(meta["gen"]), bridge_ref=meta.get("bridge_ref"))
    t0 = time.perf_counter()
    r = w._replay_into(entries, verify_sig=True)
    out["replay_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    out["replay_ok"] = r["ok"] is True
    if not r["ok"]:
        out["why"] = r.get("why")
        out["pass"] = False
        return out
    # _replay_into 는 매 항의 head·state_root 결박을 이미 대조했다(어긋나면 ok:false). 종단을 다시 못 박는다.
    out["head_identical"] = r["head"] == entries[-1]["head"] and len(w.log) == len(entries) \
        and all(a["head"] == b["head"] and a["state_root"] == b["state_root"] for a, b in zip(w.log, entries))
    out["state_root_identical"] = r["state_root"] == entries[-1]["state_root"]
    out["full_root_eq_incremental"] = w._root_full() == r["state_root"]
    # 맵 다이제스트 캐시 == 전량 canon(캐시 무효화 규율의 종단 증명)
    md = {}
    for name in World._MAPS:
        m = getattr(w, name)
        md[name] = w._map_digest(name) == hashlib.sha256(_canon(m)).hexdigest()
    out["map_digest_eq_canon"] = all(md.values())
    if not out["map_digest_eq_canon"]:
        out["map_digest_bad"] = [k for k, v in md.items() if not v]
    out["exited_index_eq_list"] = set(w.exited) == w._exited_set and len(w.exited) == len(set(w.exited))
    try:
        w._invariants()
        out["invariants"] = True
    except Fl23Error as ex:
        out["invariants"] = False
        out["why"] = f"불변식: {ex}"
    out["reason_warn"] = r["reason_warn"]
    out["log_id_match"] = r["log_id"] == meta["log_id"]
    out["pass"] = all(out[k] is True for k in ("replay_ok", "head_identical", "state_root_identical",
                                                "full_root_eq_incremental", "map_digest_eq_canon",
                                                "exited_index_eq_list", "invariants", "log_id_match"))
    return out


def main(argv):
    paths = argv[1:] or fixture_paths()
    res = [check(p) for p in paths]
    for r in res:
        print(json.dumps(r, ensure_ascii=False))
    ok = all(r["pass"] for r in res)
    print(json.dumps({"T_KDIFF_PASS": ok, "fixtures": len(res)}, ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
