#!/usr/bin/env python3
"""cosigner.py — ★D-2 분리 공동-서명자 데몬 ([M-105]).

노드와 다른 프로세스/호스트에서 자기 키 하나로 head를 서명해 /cosig로 회신한다 —
노드의 단독 위조를 2-of-3이 실제로 견제하려면 키가 물리적으로 흩어져야 한다(동거 = 연극).
비동기 도착은 verify_chain의 confirmation-depth 시맨틱(pending 꼬리)이 흡수한다.

이전 절차(런북 §D-2): 창세 의식(첫 기동·전 키 생성) 후 cosign{2,3}.key 파일을 이 데몬의
호스트로 **이동**(원본 삭제)하고, 노드를 `--cosign-local cosign1`로 재기동.

실행: python3 cosigner.py --url http://NODE:8788 --name cosign2 --key cosign2.key [--poll 5]
"""
import argparse
import json
import os
import sys
import time
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from sdk import DOMAIN, USER_AGENT, domains_for                    # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (    # noqa: E402
    Ed25519PrivateKey)


class Cosigner:
    def __init__(self, url, name, key_path, state_path=None):
        self.url = url.rstrip("/")
        self.name = name
        self.key = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(open(key_path).read().strip()))
        self.state_p = state_path or key_path + ".state"
        self.next = (int(open(self.state_p).read().strip())
                     if os.path.exists(self.state_p) else 0)
        # ★[M-208] R4-31(냉독 4 · F07-4) — 내가 서명한 (seq → head) 이력을 영속 보관한다: 같은 seq 에 다른 head 가 오면
        #   (재-창세·포크) 서명을 **거부**하고 두 head 를 증거로 남긴다 — 「짧으면 0부터」 규칙이 서명자 자신의 증인 자격을
        #   지우던 것을 봉합(cosigner 는 head 를 재계산하지 않지만, 자기가 서명한 head 와의 모순은 볼 수 있다).
        self.heads_p = self.state_p + ".heads"
        self.heads = {}
        if os.path.exists(self.heads_p):
            for line in open(self.heads_p, encoding="utf-8"):
                if line.strip():
                    rec = json.loads(line)
                    self.heads[int(rec["seq"])] = rec["head"]

    def _req(self, method, path, obj=None):
        data = json.dumps(obj).encode() if obj is not None else None
        r = urllib.request.Request(self.url + path, data=data, method=method,
                                   headers={"Content-Type": "application/json",
                                            "User-Agent": USER_AGENT})
        with urllib.request.urlopen(r, timeout=30) as resp:
            raw = resp.read(32 * 1024 * 1024 + 1)          # ★[M-208] R4-12 — 악의 노드 무한 본문 상한
            if len(raw) > 32 * 1024 * 1024:
                raise RuntimeError("응답 크기 상한 초과")
            return json.loads(raw)

    def run_once(self):
        """미서명 구간 전부 서명·회신 — 서명 수를 반환(멱등 · 상태 파일로 재시작 내구)."""
        done = 0
        # ★커서 안전장치(완결성 점검 med): 로그가 커서보다 짧으면(재-창세/복원) 0부터
        # 재-서명 — forward-only 커서가 신규 로그를 영구 건너뛰던 under-sign 봉합.
        st = self._req("GET", "/state")
        dom = domains_for(self._req("GET", "/meta"))["env"]      # ★FL2.3 — 세대-적응(FL22 노드·FL23 노드 모두)
        if self.next > st["seq"]:
            self.next = 0
        rounds = 0
        while True:
            page = self._req("GET", f"/log?since={self.next}")["entries"]
            if not page:
                break
            rounds += 1
            # ★[M-208] R4-18(냉독 4 · F11) — 악의 노드의 비-단조 seq 페이지 = 무한 루프·/cosig 홍수(2.5초 6,297건 재현) 차단
            if not all(isinstance(x, dict) and isinstance(x.get("seq"), int) for x in page) or \
                    page[0]["seq"] < self.next or any(page[i]["seq"] >= page[i + 1]["seq"] for i in range(len(page) - 1)) \
                    or rounds > 10_000:
                raise RuntimeError(f"/log 비-단조·비정형 페이지(since {self.next}) — 서명 중단(악의 노드 방어)")
            for e in page:
                prev_h = self.heads.get(int(e["seq"]))
                if prev_h is not None and prev_h != e["head"]:
                    ev = {"seq": e["seq"], "signed_head": prev_h, "offered_head": e["head"], "name": self.name}
                    with open(self.state_p + ".fork", "a", encoding="utf-8") as fh:
                        fh.write(json.dumps(ev) + "\n")
                    raise RuntimeError(f"★포크/재-창세 증거: seq {e['seq']} 에 내가 서명한 head {prev_h[:12]}… ≠ 제시 head {e['head'][:12]}… — 서명 거부"
                                       f"(증거 = {self.state_p}.fork)")
                sig = self.key.sign(dom + bytes.fromhex(e["head"])).hex()
                self._req("POST", "/cosig", {"name": self.name, "seq": e["seq"],
                                             "head": e["head"], "sig": sig})
                self.next = e["seq"] + 1
                done += 1
                if prev_h is None:
                    self.heads[int(e["seq"])] = e["head"]
                    with open(self.heads_p, "a", encoding="utf-8") as fh:
                        fh.write(json.dumps({"seq": e["seq"], "head": e["head"]}) + "\n")
            with open(self.state_p, "w") as fh:
                fh.write(str(self.next))
        return done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8788")
    ap.add_argument("--name", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--poll", type=float, default=5.0)
    ap.add_argument("--once", action="store_true")
    a = ap.parse_args()
    co = Cosigner(a.url, a.name, a.key)
    if a.once:
        print(json.dumps({"signed": co.run_once(), "next": co.next}))
        return 0
    print(json.dumps({"cosigner": "up", "name": a.name}), flush=True)
    while True:
        try:
            n = co.run_once()
            if n:
                print(json.dumps({"signed": n, "next": co.next}), flush=True)
        except Exception as e:
            print(json.dumps({"cosigner_error": str(e)[:150]}), flush=True)
        time.sleep(a.poll)


if __name__ == "__main__":
    sys.exit(main())
