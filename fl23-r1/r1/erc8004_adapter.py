#!/usr/bin/env python3
"""erc8004_adapter — ★V-1([M-157·M-159]) VLUE 노드 = ERC-8004 지목-검증자 어댑터.

ERC-8004(Trustless Agents)의 Validation Registry 는 요청자가 **검증자를 지목**하고
(validationRequest) 지목-검증자가 0~100 스칼라로 응답한다(validationResponse — 증거
URI 는 선택). 이 어댑터는 **VLUE 노드를 그 지목-검증자 뒤에 앉힌다**:

  스웜/체인-측 요청(ref 지목) → 이 원장의 실제 판정(약속-일치 · H2 결박)을 조회 →
  응답 = 100(이행-정산) | 0(시한-사고 정산) · ⛔미성숙(open)은 응답 거부 →
  responseURI 문서(attest + 판정 근거) + responseHash + **calldata**(hex) 산출.

★정직 경계: ⓐ스칼라는 이 원장의 판정 형식이 아니다(VERIFIER §스칼라-기각) — 어댑터는
**이진 사상**(100/0)만 내보내고 근거 전문은 responseURI 문서가 携行한다(그쪽 표준의
「선택」을 우리는 **항상-첨부**로 채운다) ⓑ**온체인 송신은 이 도구 밖**(키·가스·체인
선택 = 운영자 몫) — 산출물은 서명-전 calldata 다 ⓒkeccak256·ABI 인코더는 순수-stdlib
재구현(의존성 0 — R-6 증명-앵커 계보)이고 `--selftest` 가 공지 벡터로 자기검증한다.

사용:
  python3 erc8004_adapter.py selftest
  python3 erc8004_adapter.py respond --url https://node.vlue.ai --ref <ref> \
      --request-hash <0x..32바이트> --response-uri <게시 예정 URI> --out ./resp
"""
import argparse
import hashlib
import json
import os
import sys
import urllib.request

# ── 순수-stdlib keccak-256 (이더리움 = 원판 Keccak 패딩 0x01 — SHA3-256 아님) ──

_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
       0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
       0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
       0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
       0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
       0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _rotl(v, n):
    return ((v << n) | (v >> (64 - n))) & _M


def _keccak_f(st):
    for rc in _RC:
        c = [st[x][0] ^ st[x][1] ^ st[x][2] ^ st[x][3] ^ st[x][4]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                st[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(st[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                st[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        st[0][0] ^= rc
    return st


def keccak256(data: bytes) -> bytes:
    rate = 136
    st = [[0] * 5 for _ in range(5)]
    pad = data + b"\x01" + b"\x00" * ((-len(data) - 2) % rate) + b"\x80"
    for off in range(0, len(pad), rate):
        blk = pad[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            st[x][y] ^= int.from_bytes(blk[8 * i:8 * i + 8], "little")
        _keccak_f(st)
    out = b"".join(st[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out[:32]


# ── 최소 ABI 인코더 — validationResponse(bytes32,uint8,string,bytes32,string) ──

SIG = "validationResponse(bytes32,uint8,string,bytes32,string)"


def _pad32(b):
    return b + b"\x00" * ((-len(b)) % 32)


def encode_response(request_hash: bytes, response: int, response_uri: str,
                    response_hash: bytes, tag: str) -> bytes:
    assert len(request_hash) == 32 and len(response_hash) == 32
    assert 0 <= response <= 100
    s1, s2 = response_uri.encode(), tag.encode()
    off1 = 5 * 32
    off2 = off1 + 32 + len(_pad32(s1))
    head = (request_hash + response.to_bytes(32, "big")
            + off1.to_bytes(32, "big") + response_hash
            + off2.to_bytes(32, "big"))
    tail = (len(s1).to_bytes(32, "big") + _pad32(s1)
            + len(s2).to_bytes(32, "big") + _pad32(s2))
    return keccak256(SIG.encode())[:4] + head + tail


# ── 판정 사상 — 원장 상태 → 0/100 ──────────────────────────────────────────────

def _get(url, path):
    with urllib.request.urlopen(url.rstrip("/") + path, timeout=30) as r:
        raw = r.read(32 * 1024 * 1024 + 1)                        # ★[M-210] 응답 상한(전 진입점 동형)
        if len(raw) > 32 * 1024 * 1024:
            raise RuntimeError("응답 크기 상한 초과")
        return json.loads(raw)


def _party_guard(job, meta, self_demo):
    """★무-오염 가드([M-161]) — 운영자-당사자 항목의 무라벨 attestation 차단.

    프로덕션의 공개 주장(「자기-체결 0」·K5′ 비-운영자 지표)을 attestation 경로가
    희석하지 못하게: 보유자(holder)가 운영자-좌석이면 `--self-demo` 라벨 없이는 거부,
    라벨이 있으면 응답 문서에 origin 필드로 **명시 표기**된다(정직-표기 계보)."""
    seats = {"operator"} | set(meta.get("genesis") or [])         | set(meta.get("cosigners") or [])
    holder = job.get("holder")
    if holder in seats:
        if not self_demo:
            raise SystemExit(f"⛔자기-당사자(holder={holder}) — 무-오염: "
                             "--self-demo 라벨 없이는 attestation 금지")
        return "operator-demonstration (labeled)"
    return "participant"


def respond(url, ref, request_hash_hex, response_uri, out_dir, tag="vlue-r1",
            self_demo=False):
    j = _get(url, f"/job/{ref}")
    meta = _get(url, "/meta")
    origin = _party_guard(j, meta, self_demo)
    state = j.get("state")
    if state == "open":
        raise SystemExit(f"⛔미성숙(open) — 판정 전 응답 금지(ref={ref})")
    if state == "delivered":
        resp = 100
    elif state == "settled_or_returned":
        resp = 0                       # 시한-사고로 정산 — 약속-불이행 확정
    else:
        raise SystemExit(f"⛔미지 상태 {state!r}")
    anchor = j.get("anchor") or (j.get("job") or {}).get("anchor")
    doc = {"standard": "ERC-8004 validationResponse (prepared by vlue-r1)",
           "verdict": resp, "origin": origin,
           "basis": "deadline-peril settlement on ledger "
           "(pass/fail + hash-bound evidence — not a scalar opinion)",
           "log_id": meta["log_id"], "ref": ref, "job": j,
           "attest_hint": f"{url}/attest/{anchor}" if anchor else None,
           "replay": "public full-state replay: replay_full.py (H7)",
           "tag": tag}
    raw = json.dumps(doc, ensure_ascii=False, sort_keys=True).encode()
    rhash = keccak256(raw)
    os.makedirs(out_dir, exist_ok=True)
    fp = os.path.join(out_dir, f"erc8004_{ref}.json")
    with open(fp, "wb") as f:
        f.write(raw)
    cd = encode_response(bytes.fromhex(request_hash_hex.removeprefix("0x")),
                         resp, response_uri or os.path.basename(fp), rhash, tag)
    cp = os.path.join(out_dir, f"erc8004_{ref}.calldata.hex")
    with open(cp, "w") as f:
        f.write(cd.hex() + "\n")
    return {"response": resp, "responseHash": rhash.hex(), "doc": fp,
            "calldata": cp, "selector": cd[:4].hex()}


def selftest():
    out = {}
    out["keccak_empty"] = keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    out["keccak_abc"] = keccak256(b"abc").hex() == (
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
    sel = keccak256(SIG.encode())[:4].hex()
    out["selector_8hex"] = len(sel) == 8
    cd = encode_response(b"\x11" * 32, 100, "u", b"\x22" * 32, "t")
    out["abi_shape"] = (cd[:4].hex() == sel and cd[4:36] == b"\x11" * 32
                       and cd[36:68][-1] == 100
                       and int.from_bytes(cd[68:100], "big") == 160
                       and cd[100:132] == b"\x22" * 32)
    out["pass"] = all(out.values())
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["selftest", "respond"])
    ap.add_argument("--url")
    ap.add_argument("--ref")
    ap.add_argument("--request-hash", default="00" * 32)
    ap.add_argument("--response-uri", default="")
    ap.add_argument("--out", default="./erc8004_out")
    ap.add_argument("--self-demo", action="store_true",
                    help="운영자-당사자 항목의 라벨-attestation(문서에 명시 표기)")
    a = ap.parse_args()
    if a.cmd == "selftest":
        r = selftest()
        print(json.dumps(r, ensure_ascii=False))
        return 0 if r["pass"] else 1
    if not (a.url and a.ref):
        raise SystemExit("respond: --url·--ref 필수")
    print(json.dumps(respond(a.url, a.ref, a.request_hash, a.response_uri,
                             a.out, self_demo=a.self_demo),
                     ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
