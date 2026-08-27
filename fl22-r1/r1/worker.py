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
sys.path.insert(0, os.path.join(_HERE, "..", "fin_lean", "lang22"))
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
        for ref, j in js["jobs"].items():
            if not j["job"]["kind"].startswith("sha256"):
                continue              # pycheck 등 지능-작업은 워커 몫 아님(P-1 — 외부 앵커)
            out = JOBS.compute(j["job"]["kind"], j["job"]["seed"], j["job"]["n"])
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
