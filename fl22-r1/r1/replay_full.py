#!/usr/bin/env python3
"""replay_full.py — ★H7([M-127] FL2.2 J-2) 시드-독립 전-상태 공개 재검증.

라이트 검증(sdk.verify_chain)이 head-사슬·서명을 재는 것 위에, 이 도구는 **법 자체를
재실행**한다: /meta의 공개 재료(operator_pk·genesis_pks·gen·label·bridge_ref)만으로
검증-전용 세계(`World.from_public`)를 만들고 /log 전량을 리플레이해 ⓐ모든 상태 전이가
법을 지켰는지 ⓑstate_root·head·_force 결박 ⓒ운영자 head_sig ⓓ★fp0·log_id 재유도가
발표문 값과 일치하는지를 판정한다 — 창세-시드는 필요 없다(신뢰표의 「replay from
zero」 잔여 해소).

실행: python3 replay_full.py --url https://NODE  (번들의 fin_lean/lang22 옆에서)
"""
import argparse
import json
import os
import sys
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "fin_lean", "lang22"))

from kernel22 import World                                         # noqa: E402


UA = "vlue-replay/0.1 (+https://vlue.ai)"   # ★[M-144] 기본 urllib UA는 WAF 봇 차단 대상


def _get(url, path):
    req = urllib.request.Request(url + path, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--batches", type=int, default=10_000)
    a = ap.parse_args()
    url = a.url.rstrip("/")
    meta = _get(url, "/meta")
    pks = {"operator": meta["operator_pk"], **(meta.get("genesis_pks") or {})}
    w = World.from_public(pks, meta["label"], tuple(meta["genesis"]),
                          gen=dict(meta["gen"]),
                          bridge_ref=meta.get("bridge_ref"))
    ok_id = (w.log_id.hex() == meta["log_id"] and w.fp0 == meta["fp0"])
    entries, s = [], 0
    for _ in range(a.batches):
        page = _get(url, f"/log?since={s}").get("entries")
        if not isinstance(page, list) or not page:
            break
        entries += page
        # ★[M-194] 악의 노드의 비정형 페이지(마지막 항 seq 부재·비-int)가 페이지네이션을
        # 크래시하지 못하게(냉독 라운드4 · 검증-도구 견고성 부류). 진전 없으면 중단.
        last = page[-1]
        nxt = last.get("seq") if isinstance(last, dict) else None
        if not isinstance(nxt, int) or nxt + 1 <= s:
            break
        s = nxt + 1
    # ★[M-189] C-1 — 커널 호출 **전에** head_sig 부재를 선-거부한다(벨트: 커널
    # replay_verify 도 부재-거부로 고쳤지만, 이 층이 도구의 계약을 명시적으로 문다).
    miss = next((e.get("seq") for e in entries if "head_sig" not in e), None)
    if miss is not None:
        print(json.dumps({"H7_FULL_REPLAY": False,
                          "why": f"운영자 서명 부재 seq {miss}"}, ensure_ascii=False))
        return 1
    r = w.replay_verify(entries)
    out = {"H7_FULL_REPLAY": bool(r["ok"] and ok_id),
           "identity_rederived": ok_id, **r}
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0 if out["H7_FULL_REPLAY"] else 1


if __name__ == "__main__":
    sys.exit(main())
