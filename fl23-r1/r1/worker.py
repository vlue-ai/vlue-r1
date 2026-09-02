#!/usr/bin/env python3
"""worker.py — R1 앵커 워커: 실물 계산-이행 ([M-95] · E-3 · A-1).

앵커 좌석(창세 anchor0 — 키 = 노드 시드 파생)이 열린 작업을 폴링해 ★실제로 계산하고
기한 내 DELIVER한다. ★워커가 죽으면 이행이 없고 — 커널 시한-사고가 실발동한다(진짜
기한·진짜 사고 — 페릴의 실물성은 「죽을 수 있음」에 있다).

실행: python3 worker.py --url http://127.0.0.1:8788 [--once] [--poll SEC]
"""
import argparse
import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "fin_lean", "lang23"))
sys.path.insert(0, _HERE)

import jobs as JOBS                                                # noqa: E402
from sdk import Fl21Client                                         # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (    # noqa: E402
    Ed25519PrivateKey)


class AnchorWorker(Fl21Client):
    """anchor0 좌석 — ★D-1: 키는 파일로만(노드가 data_dir에 export한 anchor0.key)."""

    def __init__(self, base_url, key_path, name="anchor0"):
        self.url = base_url.rstrip("/")
        self.p = name
        self.key = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(open(key_path).read().strip()))
        self.meta = self._get("/meta")
        self.log_id = bytes.fromhex(self.meta["log_id"])

    def _ensure_key(self):
        raise RuntimeError("워커 키는 파일 로드")

    def work_once(self):
        js = self._get(f"/jobs?anchor={self.p}")
        done = []
        budget = 20_000_000                                       # ★[M-210] R3-F05-M3 — 패스당 총 작업량(Σn) 예산: 64 × N_MAX 정지(~2분) 차단
        _mine = [(r, j) for r, j in (js.get("jobs") or {}).items()
                 if isinstance(j, dict) and isinstance(j.get("job"), dict) and str(j["job"].get("kind", "")).startswith("sha256")]
        for ref, j in _mine[:64]:                              # ★[M-209] R2-F11-6 한 패스 상한 · ★[M-211] R4-F04-4 — kind 필터 **뒤**에 슬라이스(비-sha256 열린 잡이 창을 점유해 뒤 잡을 굶기던 것)
            _n = j["job"].get("n")
            if not isinstance(_n, int) or not (1 <= _n <= JOBS.N_MAX):   # ★[M-208] R4-19 — 악의 노드의 무계 n(정지) 거부
                continue
            _sd = j["job"].get("seed")
            try:                                                          # ★[M-209] R2-F05-3 — 비정형 seed(홀수 hex 등) = 건너뜀(크래시 아님)
                if not isinstance(_sd, str) or len(_sd) % 2 or not (1 <= len(_sd) <= 128):
                    raise ValueError
                bytes.fromhex(_sd)
            except ValueError:
                continue
            if budget - _n < 0:
                break                                                 # 남은 잡은 다음 패스
            budget -= _n
            try:                                                      # ★[M-211] R4-F04-4 — 한 잡의 예외가 패스 전체를 멈추지 않게 격리
                out = JOBS.compute(j["job"]["kind"], j["job"]["seed"], j["job"]["n"])
            except Exception as _ex:
                print(json.dumps({"skip": ref, "why": str(_ex)[:120]}, ensure_ascii=False), flush=True)
                continue
            # ★[M-149] SR-1 — H2 결박: sdk.deliver_job 경유(output_sha256를 서명에 결박).
            # 봉투 직접 조립은 운영자 자신의 판매 경로(자동-이행)만 H2 밖에 두던 구멍 —
            # T-HASHBIND ⓓ(워커-경로)가 이 결박을 게이트로 못박는다.
            r = self.deliver_job(ref, out)
            done.append({"ref": ref, "seq": r["seq"]})
        return done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8788")
    ap.add_argument("--key", required=True,
                    help="앵커 키 파일(노드 data_dir의 anchor0.key)")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--poll", type=float, default=2.0)
    a = ap.parse_args()
    w = AnchorWorker(a.url, a.key)
    if a.once:
        print(json.dumps({"delivered": w.work_once()}, ensure_ascii=False))
        return 0
    print(json.dumps({"worker": "up", "anchor": w.p}), flush=True)
    while True:
        try:
            d = w.work_once()
            if d:
                print(json.dumps({"delivered": d}, ensure_ascii=False), flush=True)
        except Exception as e:
            print(json.dumps({"worker_error": str(e)[:150]}), flush=True)
        time.sleep(a.poll)


if __name__ == "__main__":
    sys.exit(main())
