#!/usr/bin/env python3
"""replay_full.py — ★H7([M-127] FL2.2 J-2) 시드-독립 전-상태 공개 재검증.

라이트 검증(sdk.verify_chain)이 head-사슬·서명을 재는 것 위에, 이 도구는 **법 자체를
재실행**한다: /meta의 공개 재료(operator_pk·genesis_pks·gen·label·bridge_ref)만으로
검증-전용 세계(`World.from_public`)를 만들고 /log 전량을 리플레이해 ⓐ모든 상태 전이가
법을 지켰는지 ⓑstate_root·head·_force 결박 ⓒ운영자 head_sig ⓓ★fp0·log_id 재유도가
발표문 값과 일치하는지를 판정한다 — 창세-시드는 필요 없다(신뢰표의 「replay from
zero」 잔여 해소).

실행: python3 replay_full.py --url https://NODE  (번들의 fin_lean/lang23 · lang22 옆에서 — 세대는 /meta.domain 으로 자동 선택)
"""
import argparse
import json
import os
import sys
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))

def _kernel_for(domain):
    """★FL2.3 — 세대 선택: /meta.domain 접두로 커널을 고른다(FL22-* = 아카이브 원장도 같은 도구로 재검증)."""
    import importlib
    lang = "lang22" if str(domain).startswith("FL22") else "lang23"
    sys.path.insert(0, os.path.join(_HERE, "..", "fin_lean", lang))
    return importlib.import_module("kernel22" if lang == "lang22" else "kernel23").World


UA = "vlue-replay/0.1 (+https://vlue.ai)"   # ★[M-144] 기본 urllib UA는 WAF 봇 차단 대상


MAX_RESP = 32 * 1024 * 1024                  # ★[M-209] R2-F11-1 — 응답 1건 상한(sdk 와 동형 · 악의 노드 OOM 레버 차단)
_TOTAL = {"bytes": 0, "cap": 2 * 1024 * 1024 * 1024}   # 누적 총량(기본 2GB · --max-total-mb)


def _get(url, path):
    req = urllib.request.Request(url + path, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read(MAX_RESP + 1)
        if len(raw) > MAX_RESP:
            raise SystemExit(json.dumps({"H7_FULL_REPLAY": False, "why": f"응답 크기 상한 {MAX_RESP} 초과(fail-closed)"}))
        _TOTAL["bytes"] += len(raw)
        if _TOTAL["bytes"] > _TOTAL["cap"]:
            raise SystemExit(json.dumps({"H7_FULL_REPLAY": False, "why": f"누적 판독 총량 상한 {_TOTAL['cap']} 초과(fail-closed)"}))
        return json.loads(raw)


def _sample_union(entries, ref, want, k_eff):
    """★[M-209] R2-F04-2 — 커밋-표본 합집합의 공개 재유도: 그 ref 의 모든 fl21.ocommit head 에 대해 PRF(head‖ref‖ctr) 인덱스를 합친다."""
    import hashlib
    want = max(1, min(int(want), 100)); k_eff = max(1, min(int(k_eff), 16))   # ★[M-210] R3-F05-H1 — 노드-제어 n·k 무계 연산(행) 차단(스키마 상한과 동형)
    idxs = set()
    for e in entries:
        env = e.get("env") or {}
        a = env.get("args") or {}
        if env.get("typ") == "TICKMARK" and a.get("kind") == "fl21.ocommit" and a.get("ref") == ref and e.get("kind") != "REJECT":
            seed = bytes.fromhex(e["head"]) + ref.encode(); picked, ctr = set(), 0
            while len(picked) < min(k_eff, want) and ctr < 4096:
                v = int.from_bytes(hashlib.sha256(seed + ctr.to_bytes(4, "big")).digest(), "big") % want
                ctr += 1
                picked.add(v)
            idxs.update(picked)
    return sorted(idxs)


def main():
    # ★[M-195] 아키텍처 방어(냉독 라운드5): 악의 노드의 어떤 비정형 서빙도 크래시가
    # 아니라 H7_FULL_REPLAY:false 로 — 검증-견고성 부류를 함수 전체로 닫는다.
    try:
        return _main_inner()
    except SystemExit:
        raise
    except Exception as e:
        print(json.dumps({"H7_FULL_REPLAY": False,
                          "why": f"검증 예외(비정형 서빙 추정): {type(e).__name__}"},
                         ensure_ascii=False))
        return 1


def _main_inner():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--batches", type=int, default=10_000)
    ap.add_argument("--genesis-head", default=None, help="★[M-209] 대역-외 창세 head(RELEASE) — 첫 항 head 와 대조(같은 정체성의 다른 창세 거부)")
    ap.add_argument("--max-total-mb", type=int, default=2048, help="누적 판독 총량 상한(MB)")
    a = ap.parse_args()
    url = a.url.rstrip("/")
    _TOTAL["cap"] = int(a.max_total_mb) * 1024 * 1024
    meta = _get(url, "/meta")
    pks = {"operator": meta.get("operator_pk0") or meta["operator_pk"], **(meta.get("genesis_pks") or {})}   # ★J-4 창세 키(REKEY 뒤엔 current ≠ genesis)
    World = _kernel_for(meta.get("domain", "FL23"))
    w = World.from_public(pks, meta["label"], tuple(meta["genesis"]),
                          gen=dict(meta["gen"]),
                          bridge_ref=meta.get("bridge_ref"))
    ok_id = (w.log_id.hex() == meta["log_id"] and w.fp0 == meta["fp0"])
    entries, s = [], 0
    for _ in range(a.batches):
        page = _get(url, f"/log?since={s}").get("entries")
        if not isinstance(page, list):                      # ★[M-208] R4-16(냉독 4 · F05 HIGH) — 비정형 페이지는 break 가 아니라 **실패**
            print(json.dumps({"H7_FULL_REPLAY": False, "why": f"/log 비정형 페이지(since {s}) — 0항 검증을 성공으로 보고하지 않는다"},
                             ensure_ascii=False))
            return 1
        if not page:
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
    if not entries:                                     # ★[M-208] R4-16 — 원천-철회(빈 로그)는 「전량 재검증 성공」이 아니다
        print(json.dumps({"H7_FULL_REPLAY": False, "why": "원장 0항 — 검증 대상 없음(라이브 원장이면 노드가 로그를 감춘 것)"},
                         ensure_ascii=False))
        return 1
    # ★[M-210] R3-F07-1/F12-1 — 기본 핀: 번들 RELEASE 의 log_id 를 주장하는 노드면 RELEASE 의 genesis_head 를 자동 대조(핀 없는 검증 = 동일-정체성·다른-창세 임포스터 통과)
    pin_src = "flag" if a.genesis_head else None
    if not a.genesis_head:
        try:
            from sdk import release_pins as _rp
            _pins = _rp()
            if _pins.get("log_id") and str(meta.get("log_id")) == _pins["log_id"] and _pins.get("genesis_head"):
                a.genesis_head = _pins["genesis_head"]; pin_src = "release"
        except Exception:
            pass
    # ★[M-209] R2-F07-1 — 창세 내용 고정: 대역-외 genesis_head 대조 · /meta.genesis_head 정합
    if a.genesis_head and str(entries[0].get("head")) != str(a.genesis_head):
        print(json.dumps({"H7_FULL_REPLAY": False, "why": f"genesis_head 불일치: 원장 {str(entries[0].get('head'))[:12]}… ≠ 기대 {a.genesis_head[:12]}…"}, ensure_ascii=False))
        return 1
    if meta.get("genesis_head") is not None and str(meta["genesis_head"]) != str(entries[0].get("head")):
        print(json.dumps({"H7_FULL_REPLAY": False, "why": "노드 /meta.genesis_head ≠ 서빙된 첫 항 head"}, ensure_ascii=False))
        return 1
    # ★[M-209] R2-F06-1 — JOIN/REKEY 저-위수 키 = 위조 가능 주체(fail-closed)
    from sdk import ed25519_weak_pk
    for e in entries:
        env = e.get("env") or {}
        pks = []
        if e.get("kind") != "REJECT" and env.get("typ") in ("JOIN", "REKEY"):
            pks = [(env.get("args") or {}).get("pk" if env["typ"] == "JOIN" else "new_pk")]
        elif e.get("kind") != "REJECT" and env.get("typ") == "GENESIS_IMPORT":          # ★[M-210] 수입 주체 pk 도
            pks = [(x or {}).get("pk") for x in ((env.get("args") or {}).get("principals") or []) if isinstance(x, dict)]
        for pk in pks:
            try:
                weak = ed25519_weak_pk(bytes.fromhex(str(pk)))
            except ValueError:
                weak = True
            if weak:
                print(json.dumps({"H7_FULL_REPLAY": False, "why": f"약한 키 등록 seq {e.get('seq')}({env['typ']})"}, ensure_ascii=False))
                return 1
    r = w.replay_verify(entries)
    # ★[M-208] R4-17(냉독 4 · F12) — 파생-상태 대조: 노드가 주장하는 /balance 가 재실행 잔고와 다르면 거짓 노드(fail-closed)
    mism = []
    try:
        names = sorted({str(n.get("owner")) for n in w.notes.values()} | set(getattr(w, "nonces", {}) or {}))
        names = [x for x in names if x and not x.startswith("@")][:256]          # 에스크로 좌석(@…) 제외 · 실주체만
        for pnm in names:
            bal = _get(url, f"/balance/{pnm}").get("balance")
            if bal != w.bal(pnm):
                mism.append({"p": pnm, "node": bal, "replayed": w.bal(pnm)})
    except Exception as ex:                              # 대조 불가 = 실패로 기록(침묵 통과 금지)
        mism.append({"error": str(ex)[:80]})
    # ★[M-209] R2-F04-2 — 커밋-표본 합집합 공개 재유도(ref 별 · 표본-클래스 잡의 검사 인덱스 = 이 값이어야 한다)
    samples = {}
    try:
      if r["ok"]:                                                     # ★[M-210] 리플레이 실패 뒤엔 표본 블록을 돌리지 않는다(연산-행 차단)
        for e in entries:
            env = e.get("env") or {}; a_ = env.get("args") or {}
            if env.get("typ") == "TICKMARK" and a_.get("kind") == "fl21.ocommit" and e.get("kind") != "REJECT":
                samples.setdefault(a_.get("ref"), None)
        for ref in list(samples)[:64]:
            j = _get(url, f"/job/{ref}").get("job") or {}
            spec = j.get("job") or j
            if isinstance(spec, dict) and spec.get("kind") == "sha256_chain_sampled" and isinstance(spec.get("n"), int) \
                    and 1 <= spec["n"] <= 5_000_000 and 1 <= int(spec.get("k", 2)) <= 16:                  # ★[M-210] 노드-제어 n·k 스키마 상한 밖 = 무시
                import jobs as _JOBS                                   # ★[M-210] R3-F04-1 — 체크포인트 간격은 jobs.CKPT(50,000) 하나의 정본(구판 100,000 오기)
                want = -(-spec["n"] // _JOBS.CKPT)
                samples[ref] = _sample_union(entries, ref, want, int(spec.get("k", 2)))
                chk = ((j.get("verify") or {}).get("checked")) if isinstance(j, dict) else None
                if j.get("delivered") and isinstance(chk, list) and sorted(chk) != samples[ref]:
                    mism.append({"ref": ref, "checked": sorted(chk), "sample_union": samples[ref]})   # ★공개 재유도 ≠ 노드 검사 = 실패
    except Exception as ex:
        samples = {"error": str(ex)[:80]}
    out = {"H7_FULL_REPLAY": bool(r["ok"] and ok_id and not mism),
           "identity_rederived": ok_id, "genesis_head": entries[0].get("head"), "genesis_pin": pin_src, "balance_mismatch": mism,
           "sample_union": samples, **r}
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0 if out["H7_FULL_REPLAY"] else 1


if __name__ == "__main__":
    sys.exit(main())
