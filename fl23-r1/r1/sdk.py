#!/usr/bin/env python3
"""sdk.py — FL2.3 R1 클라이언트 SDK ([M-95] · E-2 · A-2/A-6).

★커널 무임포트 — 외부 주체가 받는 것: 이 파일 + EXTERNAL_QUICKSTART.md. 서명·정준화·
헤드 산식을 독립 재구현하고(골든-서명 테스트가 커널과 바이트-동일을 결박 —
tests/test_sig_golden.py), 키는 클라이언트가 생성·보관한다(노드는 공개키만 받는다).

라이트 검증(A-6): 로그 head-사슬 재계산 + 운영자 head_sig + 공동-서명 k-of-n — 전체
상태-리플레이 검증은 커널 공개본으로(공개 시 동봉).

의존: python3 표준 라이브러리 + cryptography(Ed25519).
"""
import base64
import hashlib
import json
import re
import os
import urllib.request

_CKPT = 50_000                       # 표본-검증 클래스의 체크포인트 간격(노드와 동일)

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.exceptions import InvalidSignature

DOMAIN = b"FL23-v0.1" + b"\x00" * 7          # 커널 FL23_DOMAIN과 동일(골든 결박 · ★FL2.3)
BOARD_DOMAIN = b"FL23-BOARD"                 # ★호가 창(오프-원장) — 원장 봉투와 도메인 분리
RELAY_DOMAIN = b"FL23-RELAY"                 # ★[M-162] leg-릴레이(서명 사서함)
ACCEPT_DOMAIN = b"FL23-ACPT"                 # ★[M-178] 수락-채널(record-only 2차-이력)
# ★[M-144] 명시 User-Agent: ⓐ기계 클라이언트의 정직한 자기-식별(트래픽이 로그에서
# 읽힌다) ⓑ★실전 필수 — 기본값 `Python-urllib/*`는 CDN·WAF의 봇 차단에 걸린다(실측:
# node.vlue.ai 이관 직후 SDK만 403 error 1010 · curl·브라우저는 200). 에이전트 경제의
# 정문이 「기계라서」 닫히면 K5′는 수요 0을 거짓 기록한다.
# ★[M-209] R2-F06-1 — Ed25519 저-위수(항등점 등) 공개키 판별(노드 node.py 와 동형 · 검증기도 JOIN/REKEY 에 실린 키를 거른다)
_ED_P = 2 ** 255 - 19
_ED_D = (-121665 * pow(121666, -1, _ED_P)) % _ED_P


def _ed_decode(b):
    y = int.from_bytes(b, "little"); sign = y >> 255; y &= (1 << 255) - 1
    if y >= _ED_P:
        return None
    y2 = y * y % _ED_P; u = (y2 - 1) % _ED_P; v = (_ED_D * y2 + 1) % _ED_P
    x2 = u * pow(v, -1, _ED_P) % _ED_P
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P:
        x = x * pow(2, (_ED_P - 1) // 4, _ED_P) % _ED_P
    if (x * x - x2) % _ED_P:
        return None
    if x == 0 and sign:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    return (x, y)


def _ed_add(P, Q):
    x1, y1 = P; x2, y2 = Q
    k = _ED_D * x1 * x2 % _ED_P * y1 % _ED_P * y2 % _ED_P
    return ((x1 * y2 + x2 * y1) * pow(1 + k, -1, _ED_P) % _ED_P,
            (y1 * y2 + x1 * x2) * pow(1 - k, -1, _ED_P) % _ED_P)


def ed25519_weak_pk(pk_bytes):
    """True = 약한 키(길이 이상 · 비-정규 · 곡선 밖 · 저-위수[8P = O]) — 그 키의 서명은 소유-증명이 아니다."""
    if not isinstance(pk_bytes, (bytes, bytearray)) or len(pk_bytes) != 32:
        return True
    P = _ed_decode(bytes(pk_bytes))
    if P is None:
        return True
    Q = P
    for _ in range(3):
        Q = _ed_add(Q, Q)
    return Q == (0, 1)


MAX_TOTAL_RESP = 256 * 1024 * 1024           # ★[M-209] R2-F11-2 — verify_chain 이 누적 판독하는 총량 상한(페이지 반복으로 메모리 무계 방지)

RELEASE_PINS = {   # ★[M-211] R4-F07/F12/F05 — 번들 RELEASE 정체성 값의 **내장 사본**(sdk.py 단독 복사에도 핀 유지 · T-IMPORT23 가 RELEASE 파일과 대조)
    "log_id": "3128a815d8657e0624eb91b81a1dec621cc7674cc7e9e677159268f83e0a6faf",
    "genesis_head": "5a387eea3aecf6ed86f94f77dc32fb39cacabafeb97e15459c641c3f8a1ebb49",
    "operator_pk0": "175399ae2c7d52d869eac0d709c619b00174c02785120ad0746ec8a54c68a4bd",
    "cosigners": ["cd32021c7795fee38b70548b08478ff8f81ee652dc7eb6285148a104595d94c3",
                  "3707d38bddcc028280f3e0d2e815259539aa542ff94ae652c3cb2cdde14f4214",
                  "bc5d31505cff434f7c6132fa067edc1cd169f53e73f96ec3bda04712082a0bad"],
    "cosign_k": 2,
}


def _parse_release(txt):
    """RELEASE(_EN).md 정체성 표에서 핀 값을 읽는다 — 표 **셀** 기준(산문 속 다른 해시를 집지 않는다)."""
    import re as _re
    out = {}
    for key, pat in (("log_id", r"^\|\s*\**log_id\**\s*\|\s*`([0-9a-f]{64})`"),
                     ("operator_pk0", r"^\|\s*\**operator_pk[^|\n]*\|\s*`([0-9a-f]{64})`"),
                     ("genesis_head", r"^\|[\s★\*]*genesis_head[^|\n]*\|\s*`([0-9a-f]{64})`")):   # 행 머리의 ★/굵게 표식 허용(다른 행의 산문은 안 집는다)
        m = _re.search(pat, txt, flags=_re.M)
        if m:
            out[key] = m.group(1)
    m = _re.search(r"^\|\s*cosigner pks \((\d)-of-(\d)\)\s*\|([^\n]*)", txt, flags=_re.M)
    if m:
        out["cosign_k"] = int(m.group(1))
        out["cosigners"] = _re.findall(r"`([0-9a-f]{64})`", m.group(3))
    return out


def release_pins(path=None):
    """★[M-210]/[M-211] 대역-외 핀(genesis_head · log_id · operator_pk0 · cosigners · cosign_k).
    원천 = sdk.py 옆의 RELEASE_EN.md·RELEASE.md(둘 다 읽어 교차) → 없으면 내장 RELEASE_PINS.
    파일과 내장값이 어긋나면 **핀을 내지 않고** conflict 를 표시한다(틀린 핀으로 조용히 통과/실패하지 않는다)."""
    import os as _os
    here = _os.path.dirname(_os.path.realpath(__file__))
    files = [path] if path else [_os.path.join(here, "RELEASE_EN.md"), _os.path.join(here, "RELEASE.md")]
    parsed, present = [], 0
    for fp in files:
        try:
            txt = open(fp, encoding="utf-8").read()
        except OSError:
            continue
        present += 1
        parsed.append(_parse_release(txt))
    if present and not any(x.get("log_id") and x.get("genesis_head") for x in parsed):
        return {"source": "conflict", "conflict": "unparsed"}           # ★[M-213] Q-6(R5-F05-4) — 파일은 있는데 못 읽으면 조용히 내장으로 떨어지지 않는다
    parsed = [x for x in parsed if x.get("log_id") and x.get("genesis_head")]
    if not parsed:
        return {**RELEASE_PINS, "source": "embedded"}
    base = dict(parsed[0])
    for other in parsed[1:] + [RELEASE_PINS]:
        for k in ("log_id", "genesis_head", "operator_pk0"):
            if other.get(k) and base.get(k) and other[k] != base[k]:
                return {"source": "conflict", "conflict": k}
        if other.get("cosigners") and base.get("cosigners") and sorted(other["cosigners"]) != sorted(base["cosigners"]):
            return {"source": "conflict", "conflict": "cosigners"}       # ★[M-213] 공동서명자 집합·k 도 교차
        if other.get("cosign_k") is not None and base.get("cosign_k") is not None and other["cosign_k"] != base["cosign_k"]:
            return {"source": "conflict", "conflict": "cosign_k"}
    for k in ("operator_pk0", "cosigners", "cosign_k"):
        base.setdefault(k, RELEASE_PINS[k])
    base["source"] = "file"
    return base


MAX_RESP = 32 * 1024 * 1024                  # ★[M-208] 응답 본문 상한(32MB — /log 500항 × 16KB 봉투 상한 = 8MB 여유)
USER_AGENT = "vlue-sdk/0.1 (+https://vlue.ai)"


def canon(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode()


def sig_msg(log_id: bytes, body: dict, nonce: int, domain: bytes = None) -> bytes:
    return (domain or DOMAIN) + log_id + canon(body) + int(nonce).to_bytes(8, "big")


def domains_for(meta: dict) -> dict:
    """★FL2.3 — 세대-적응: 노드 /meta.domain(예 "FL23-v0.1")에서 봉투·보드·릴레이·수락·챌린지 도메인을 파생한다.
    한 SDK 가 라이브 세대와 아카이브 세대(FL22-*)를 함께 섬긴다(전환 창의 운영 도구 · 검증자)."""
    d = str(meta.get("domain") or "FL23-v0.1")
    pre = d.split("-", 1)[0].encode()
    return {"env": d.encode().ljust(16, b"\x00"), "board": pre + b"-BOARD", "relay": pre + b"-RELAY",
            "accept": pre + b"-ACPT", "chal": pre + b"-CHAL"}


def spec_norm(job: dict) -> dict:
    """★H2([M-121]) — 스펙 정규형(노드 validate_spec과 동일 규칙 · 해시의 기준).
    제출자·노드·외부 검증자가 같은 바이트를 해싱하기 위한 유일 정의."""
    k = job.get("kind")
    if k in ("sha256_chain", "sha256_chain_sampled"):
        spec = {"kind": k, "seed": str(job.get("seed", "")).lower(),
                "n": int(job.get("n"))}
        if k == "sha256_chain_sampled" and "k" in job:
            spec["k"] = int(job["k"])    # ★[M-162] 검증-깊이도 H2 결박(노드와 동일)
        return spec
    if k == "ed25519_verify":
        return {"kind": k, "pk": str(job.get("pk", "")).lower(),
                "msg_sha256": str(job.get("msg_sha256", "")).lower()}
    if k == "pycheck":
        return {"kind": "pycheck", "test_b64": job["test_b64"]}
    spec = {"kind": "pyjudge", "checker_b64": job["checker_b64"]}
    if job.get("input_b64"):
        spec["input_b64"] = job["input_b64"]
    return spec


def _norm_deps(job: dict):
    """★W-4([M-201]) 구성-링크 v0 — 노드 jobs._deps 와 동일 규칙(정렬 · 16-hex · 1~8)."""
    d = job.get("deps")
    if not d:
        return None
    return sorted(str(x) for x in d)


def spec_sha256(job: dict) -> str:
    """REDEEM에 결박할 명세 해시 = sha256(canon(정규형 스펙)) — deps 포함(노드 validate_spec 동형)."""
    spec = spec_norm(job)
    d = _norm_deps(job)
    if d is not None:
        spec["deps"] = d
    return hashlib.sha256(canon(spec)).hexdigest()


def output_sha256(output) -> str:
    """DELIVER에 결박할 산출 해시 = sha256(canon(output)) — 문자열·객체 형 공통."""
    return hashlib.sha256(canon(output)).hexdigest()


def _co_ok(co_pks, name, sig_hex, head_hex, domain=None):
    try:
        co_pks[name].verify(bytes.fromhex(sig_hex),
                            (domain or DOMAIN) + bytes.fromhex(head_hex))
        return True
    except (KeyError, InvalidSignature, ValueError):
        return False


def escape_rate(n, k, m=1, ckpt=50_000):
    """★[M-172] E-4 — 표본-검증 탈출률의 폐형(초기하): m개 구간 위조가 k-표본을
    전부 피할 확률 = C(S−m, k) / C(S, k) · S = ⌈n/CKPT⌉. m=1이 위조자-최적(R-SAMPLE
    실측: S=5,k=2 → 0.595 측정 vs 0.600 이론 — 18셀 3σ-일치)."""
    import math
    S = -(-int(n) // ckpt)
    k = min(int(k), S)
    if m > S - k:
        return 0.0
    return math.comb(S - m, k) / math.comb(S, k)


def suggest_k(n, damage, tol=1, ckpt=50_000):
    """★[M-208] 이 모델은 **첫 추첨**의 탈출률이다 — 재추첨(새 ocommit)은 표본을 누적하므로 이행자가 재시도로 얻는 추가 탈출 확률은 0 이다(냉독 4 R4-3 · 단일-추첨 값이 곧 총 탈출률). ★[M-172] E-4 — 매수자의 검증-깊이 폐형: 잔여 기대-피해 q₁(k)·D ≤ tol 이
    되는 최소 k. m=1에서 q₁ = 1 − k/S 이므로 **k* = ⌈S·(1 − tol/D)⌉**(D ≤ tol 이면
    k=기본 2 · D ≥ S·tol 이면 k=S = 전-구간 = 탈출 0). ⚠️정직(v0): 깊이의 화폐-가격은
    현재 0이다(검증 비용은 노드-예산이 흡수 · 자연-상한 k ≤ S · 레이트리밋이 남용
    상한) — 큰 피해액이면 k를 아끼지 말라. 커버는 별개 축이다(탈출-잔여는 시한-사고
    페릴 밖 — 커버가 못 덮는다)."""
    S = -(-int(n) // ckpt)
    if damage <= tol:
        k = min(2, S)
    else:
        k = min(S, max(2, -(-S * (damage - tol) // damage)))
    return {"k": k, "S": S, "escape": escape_rate(n, k, 1, ckpt),
            "residual_expected_damage": escape_rate(n, k, 1, ckpt) * damage,
            "full_check": k >= S}


class Fl21Client:
    """외부 참여자 클라이언트 — 키 자율 보관·서명·제출·라이트 검증."""

    def __init__(self, base_url, principal, key_path):
        self.url = base_url.rstrip("/")
        self.p = principal
        self.key_path = key_path
        self.key = self._ensure_key()
        self.meta = self._get("/meta")
        self._reconcile_key_next()                        # ★[M-210] 회전 중 크래시 잔재(.next) — 노드 레지스트리 pk 로 승격/폐기
        # ★[M-208] R4-13(냉독 4) — 비정형 /meta 는 트레이스백이 아니라 명시 실패(가이드 첫 줄 = 이 생성자)
        if not (isinstance(self.meta, dict) and isinstance(self.meta.get("log_id"), str)
                and re.fullmatch(r"[0-9a-f]{64}", self.meta["log_id"])):
            raise RuntimeError("노드 /meta 비정형(log_id 64-hex 부재) — 이 노드는 검증할 수 없다(fail-closed)")
        self.log_id = bytes.fromhex(self.meta["log_id"])

    # ── 키(클라이언트 보관 — 노드에 비밀이 가지 않는다) ──
    @property
    def _d(self):
        """★세대-적응 도메인(env·board·relay·accept·chal) — /meta.domain 파생 · meta 없는 서브클래스는 FL2.3 기본."""
        m = getattr(self, "meta", None)
        return domains_for(m if isinstance(m, dict) else {})

    @property
    def domain(self):
        return self._d["env"]

    def _ensure_key(self):
        if os.path.exists(self.key_path):
            raw = bytes.fromhex(open(self.key_path).read().strip())
            return Ed25519PrivateKey.from_private_bytes(raw)
        nxt = self.key_path + ".next"
        if os.path.exists(nxt):                          # ★[M-211] R4-F06-8 — 키 파일 부재 + 회전 잔재 = 그 키가 유일 사본: 새 키를 만들지 않고 승격
            os.replace(nxt, self.key_path)
            raw = bytes.fromhex(open(self.key_path).read().strip())
            return Ed25519PrivateKey.from_private_bytes(raw)
        k = Ed25519PrivateKey.generate()
        # ★비밀 원자-권한 생성([M-143] F-D): write-후-chmod의 umask 노출 창 제거
        fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(k.private_bytes_raw().hex())
        return k

    # ── ★FL2.3 J-4 — 내 키 회전(선-회전 수단 · 탈취-후 복구 아님) ──
    def rekey(self):
        """새 키 생성 → 소유-증명(새 키가 DOMAIN‖log_id‖REKEY‖p‖new_pk‖old_pk 에 서명) → REKEY 제출 →
        수용되면 키 파일을 원자 교체. 구-키 서명은 그 항 다음부터 거부된다."""
        self._reconcile_key_next()                        # ★[M-211] R4-F02-1/F06-2 — 이전 회전 잔재를 먼저 해소(응답 유실 뒤 재시도가 유일 사본을 덮던 것)
        if os.path.exists(self.key_path + ".next"):
            raise RuntimeError("rekey: 이전 회전이 미해결(.next 존재 · /pk 대조 불가) — 노드 복귀 뒤 클라이언트를 재생성하면 자동 재조정된다")
        new = Ed25519PrivateKey.generate()
        new_pk = new.public_key().public_bytes_raw()
        old_pk = self.key.public_key().public_bytes_raw()
        msg = self.domain + self.log_id + b"REKEY" + self.p.encode() + new_pk + old_pk
        env = self.sign_env("REKEY", {"principal": self.p, "new_pk": new_pk.hex(),
                                      "new_sig": new.sign(msg).hex()})
        nxt = self.key_path + ".next"                    # ★[M-210] R3-F06-2 — 새 키를 제출 **전에** .next 로 fsync(제출 뒤 크래시 = 새 키 유실·구 키 거부 = 자기-브릭 방지)
        fd = os.open(nxt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)     # ★[M-211] O_EXCL — 기존 .next 를 절대 덮지 않는다
        with os.fdopen(fd, "w") as fh:
            fh.write(new.private_bytes_raw().hex()); fh.flush(); os.fsync(fh.fileno())
        try:
            r = self._post("/submit", {"env": env})
        except RuntimeError as _e:
            import re as _re
            _m = _re.match(r"^HTTP (\d{3})", str(_e))
            if _m and 400 <= int(_m.group(1)) < 500:     # ★[M-213] 숫자 코드로 판정(본문 부분문자열 아님) · 4xx = 미커밋 확정 → .next 보관(삭제 아님)
                self._stash_next(nxt)
            raise                                         # 5xx/타임아웃 = 커밋 여부 불명 → .next 그대로(다음 재조정이 /pk 로 판정)
        try:                                              # ★[M-213] 200 도 노드 `/pk` 로 재확인 뒤에만 교체(거짓 200 → 유효 키 파기 차단)
            _cur = (self._get(f"/pk/{self.p}") or {}).get("pk")
        except Exception:
            _cur = None
        if _cur != new_pk.hex():
            self.key_next_unresolved = True
            return {**(r if isinstance(r, dict) else {"r": r}), "new_pk": new_pk.hex(), "note": "노드 /pk 가 새 키를 확인하지 않아 키 파일을 교체하지 않았다(.next 유지 · 다음 서명 전 재조정)"}
        if not os.path.exists(nxt):                       # ★[M-215] D1-1 — 같은 키 파일을 쓰는 다른 프로세스가 이미 재조정(승격 또는 stale 보관)
            if not self._recover_from_store(new_pk.hex()):
                self.key_next_unresolved = True
                return {**(r if isinstance(r, dict) else {"r": r}), "new_pk": new_pk.hex(), "note": "다른 프로세스가 .next 를 처리했고 새 키를 보관소에서 찾지 못했다(다음 서명 전 재조정)"}
            return {**(r if isinstance(r, dict) else {"r": r}), "new_pk": new_pk.hex(), "note": "다른 프로세스가 먼저 재조정 — 보관소에서 새 키 채택"}
        self._backup_key(".prev")
        os.replace(nxt, self.key_path)
        self.key = new
        return {**(r if isinstance(r, dict) else {"r": r}), "new_pk": new_pk.hex()}

    # ── ★M-3([M-157]) 매수자-정책 캡슐 — AP2 IntentMandate 형상의 선언적 가드 ──
    # 조작-채널(보드 detail 등 자유문)의 마지막 방어선을 「판단」이 아니라 「선언」으로.
    # 전부 클라이언트-측(법 아님 — 커널·노드 무접촉) · 인수자 정책(underwriter.py)의
    # 매수자판. 미설정 = 무가드(기존 행동 불변).
    def set_policy(self, anchors=None, max_exposure=None, max_spend=None,
                   expiry_epoch=None, sampled_ok=True, min_k=None):
        """anchors = 허용목록(None=전체) · max_exposure = 청구당 액면 상한 ·
        max_spend = 누적 액면 상한 · expiry_epoch = 이 에포크 이후 발주 거부 ·
        sampled_ok=False = 표본-검증 kind 전면 거부 · ★min_k = 표본-깊이 하한
        ([M-162] — 표본-잡을 사되 깊이 k ≥ min_k 를 선언으로 강제)."""
        self.policy = {"anchors": set(anchors) if anchors else None,
                       "max_exposure": max_exposure, "max_spend": max_spend,
                       "expiry_epoch": expiry_epoch, "sampled_ok": sampled_ok,
                       "min_k": min_k, "spent": 0}

    def _policy_guard(self, anchor, nid, kind, k=None):
        pol = getattr(self, "policy", None)
        if pol is None:
            return
        if pol["anchors"] is not None and anchor not in pol["anchors"]:
            raise RuntimeError(f"정책: 앵커 {anchor} 허용목록 밖")
        if not pol["sampled_ok"] and kind.endswith("_sampled"):
            raise RuntimeError("정책: 표본-검증 kind 거부(탈출-잔여 = 매수자 몫)")
        if pol.get("min_k") is not None and kind.endswith("_sampled") and \
                (k is None or k < pol["min_k"]):
            raise RuntimeError(f"정책: 표본-깊이 k={k} < 하한 {pol['min_k']}")
        if pol["expiry_epoch"] is not None and \
                self.state()["epoch"] >= pol["expiry_epoch"]:
            raise RuntimeError(f"정책: 유효기한 경과(≥ {pol['expiry_epoch']})")
        face = next((m["face"] for m in self.notes() if m["nid"] == nid), None)
        if face is not None:
            if pol["max_exposure"] is not None and face > pol["max_exposure"]:
                raise RuntimeError(f"정책: 노출 {face} > 상한 {pol['max_exposure']}")
            if pol["max_spend"] is not None and \
                    pol["spent"] + face > pol["max_spend"]:
                raise RuntimeError(f"정책: 누적 {pol['spent']}+{face} > "
                                   f"{pol['max_spend']}")
        return face                                  # ★R-3 — 계상은 성공 후(호출자)

    def pk_hex(self):
        return self.key.public_key().public_bytes_raw().hex()

    def _reconcile_key_next(self):
        """★[M-210]/[M-211] key_path.next(회전 제출 뒤 파일 교체 전 크래시 잔재)를 노드 현행 공개키(/pk/<p>)와 대조.
        ① /pk == .next 키 → 승격(구 키는 .prev 로 보관) ② /pk == 현행 키 → 회전 미커밋 확정 → .next 를 .stale-<ts> 로 **보관**(삭제 아님)
        ③ 그 외(조회 실패·비정형·타 키) → **무접촉** + key_next_unresolved 표시(서명 전 재시도) — 어떤 갈래도 키 재료를 지우지 않는다(R4-F02/F06 HIGH)."""
        nxt = self.key_path + ".next"
        self.key_next_unresolved = False
        if not os.path.exists(nxt):
            return
        try:
            cand = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(open(nxt).read().strip()))
        except Exception:
            self._stash_next(nxt)                    # ★[M-213] 손상 .next 는 .corrupt-<ns> 로 보관하고 진행(영구 미해결 방지)
            return
        try:
            cur = (self._get(f"/pk/{self.p}") or {}).get("pk")
        except Exception:
            cur = None
        cand_hex = cand.public_key().public_bytes_raw().hex()
        my_hex = self.key.public_key().public_bytes_raw().hex() if getattr(self, "key", None) else None
        if isinstance(cur, str) and cur == cand_hex:
            self._backup_key(".prev")
            os.replace(nxt, self.key_path); self.key = cand
        elif isinstance(cur, str) and my_hex and cur == my_hex:
            self._stash_next(nxt)                    # 미커밋 확정 — append-only 보관(.next.stale-<ns>-<pk8>)
        else:
            if isinstance(cur, str) and len(cur) == 64 and self._recover_from_store(cur):   # ★[M-213] 노드 키가 보관소에 있으면 승격(자기치유)
                return
            self.key_next_unresolved = True

    def _store_name(self, base, priv):
        """★[M-213] Q-3(R5-F02-1/2) — 보관 파일 이름 = <base>-<ns>-<pk8>: 같은 초 충돌·깊이-1 덮어쓰기로 커밋된 키 재료가 소멸하던 것.
        O_EXCL 로 만들고 충돌이면 접미를 올린다(append-only · 어떤 보관도 다른 보관을 덮지 않는다)."""
        import time as _t
        pk8 = priv.public_key().public_bytes_raw().hex()[:8]
        for i in range(64):
            cand = f"{base}-{_t.time_ns()}-{pk8}" + (f"-{i}" if i else "")
            try:
                fd = os.open(cand, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as fh:
                    fh.write(priv.private_bytes_raw().hex()); fh.flush(); os.fsync(fh.fileno())
                return cand
            except FileExistsError:
                continue
        raise RuntimeError("키 보관 파일 이름 충돌 반복")

    def _backup_key(self, suffix):
        """현행 키 파일을 append-only 보관(.prev-<ns>-<pk8>) — 덮어쓰기 없음."""
        try:
            if os.path.exists(self.key_path):
                priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(open(self.key_path).read().strip()))
                self._store_name(self.key_path + suffix, priv)
        except (OSError, ValueError):
            pass

    def _stash_next(self, nxt, base_suffix=".stale"):
        """`.next` 를 삭제 대신 append-only 보관으로 옮긴다."""
        try:
            priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(open(nxt).read().strip()))
            self._store_name(nxt + base_suffix, priv)
        except (OSError, ValueError):
            import time as _t
            try:
                os.replace(nxt, f"{nxt}.corrupt-{_t.time_ns()}"); return
            except OSError:
                return
        try:
            os.remove(nxt)
        except OSError:
            pass

    def _recover_from_store(self, cur_hex):
        """★[M-213] 노드가 아는 현행 키(cur_hex)가 내 현행 키와 다르면 보관소(.next · .prev-* · .next.stale-*)에서 같은 pk 의 키를 찾아 승격."""
        import glob as _gl
        cands = [self.key_path, self.key_path + ".next"] + sorted(_gl.glob(self.key_path + ".prev-*")) + sorted(_gl.glob(self.key_path + ".next.stale-*"))   # ★[M-215] D1-1 — 다른 프로세스가 이미 승격한 키 파일 자체도 후보
        for fp in cands:
            try:
                priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(open(fp).read().strip()))
            except (OSError, ValueError):
                continue
            if priv.public_key().public_bytes_raw().hex() == cur_hex:
                if fp == self.key_path:                  # 이미 파일이 원장 키 — 메모리만 갱신
                    self.key = priv; return True
                self._backup_key(".prev")
                if fp == self.key_path + ".next":
                    os.replace(fp, self.key_path)
                else:
                    self._write_key_file(priv)
                self.key = priv
                return True
        return False

    def _write_key_file(self, priv):
        tmp = self.key_path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(priv.private_bytes_raw().hex()); fh.flush(); os.fsync(fh.fileno())
        os.replace(tmp, self.key_path)

    # ── HTTP ──
    def _req(self, method, path, obj=None):
        data = json.dumps(obj).encode() if obj is not None else None
        r = urllib.request.Request(self.url + path, data=data, method=method,
                                   headers={"Content-Type": "application/json",
                                            "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(r, timeout=30) as resp:
                raw = resp.read(MAX_RESP + 1)          # ★[M-208] R4-12 — 악의 노드의 무한 본문(OOM 레버) 상한
                if len(raw) > MAX_RESP:
                    raise RuntimeError(f"응답 크기 상한 {MAX_RESP} 초과 — 노드 응답 거부(fail-closed)")
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            err = e.read(MAX_RESP + 1)[:MAX_RESP].decode(errors="replace")[:300]   # ★[M-210] R3-F11-1 — 오류-경로도 상한(악의 노드 4xx+거대 본문 OOM)
            if "bad_signature" in err and not getattr(self, "_healing", False):   # ★[M-213] 내 키가 원장 키와 어긋나면 보관소에서 자기치유(다음 호출부터 유효)
                self._healing = True
                try:
                    _cur = (self._get(f"/pk/{self.p}") or {}).get("pk")
                    if isinstance(_cur, str) and _cur != self.key.public_key().public_bytes_raw().hex():
                        self._recover_from_store(_cur)
                except Exception:
                    pass
                finally:
                    self._healing = False
            raise RuntimeError(f"HTTP {e.code}: {err}") from None

    def _get(self, path):
        return self._req("GET", path)

    def _post(self, path, obj):
        return self._req("POST", path, obj)

    # ── 봉투 서명(커널과 바이트-동일 — 골든 결박) ──
    def sign_env(self, typ, args, nonce=None):
        """서명 봉투. ★[M-210] nonce 명시 = 같은 주체가 한 /block 에 둘 이상의 다리를 넣을 때(커널은 다리마다 nonce 를 전진: n, n+1, …)."""
        if getattr(self, "key_next_unresolved", False):     # ★[M-211] 회전 잔재 미해결 → 서명 전 재조정 재시도(브릭 대신 자기치유)
            self._reconcile_key_next()
        st = self._get(f"/nonce/{self.p}")
        _n = st["nonce"] if nonce is None else int(nonce)
        body = {"typ": typ, "args": args, "p": self.p, "epoch": st["epoch"]}
        sig = self.key.sign(sig_msg(self.log_id, body, _n, self.domain))
        return {**body, "nonce": _n, "sig": sig.hex()}

    # ── 참여 동작 ──
    def join(self):
        return self._post("/join", {"principal": self.p, "pk": self.pk_hex()})

    def balance(self):
        return self._get(f"/balance/{self.p}")["balance"]

    def notes(self):
        return self._get(f"/notes/{self.p}")["notes"]

    def notes_of(self, color):
        """특정 발행자(색)의 내 노트 — ★[M-103] 상환은 발행자에게만(색-일치)."""
        return [n for n in self.notes() if n.get("color") == color]

    def bootstrap(self, k=None):
        """★[M-103] 상호 신용 교환: 내 자기-IOU k AU ↔ anchor0-IOU k AU(원자 스왑 ·
        한도 = 노드 bootstrap_cap). join 직후 첫 유동성 — 일방 지급이 아니라 교환이다."""
        k = k if k is not None else self.meta.get("bootstrap_cap", 8)
        anchor0 = self.meta["genesis"][0]
        mine = [n for n in self.notes_of(self.p)]
        pick = next((n for n in mine if n["face"] == k), None)
        if pick is None:
            big = next((n for n in mine if n["face"] > k), None)
            if big is None:
                raise RuntimeError(f"자기-IOU {k} AU 부족")
            self.split(big["nid"], [k, big["face"] - k])
            pick = next(n for n in self.notes_of(self.p) if n["face"] == k)
        leg = self.make_leg("XFER", {"frm": self.p, "to": anchor0,
                                     "note": pick["nid"]})
        return self._post("/bootstrap", {"leg": leg})

    def issue(self, k):
        """★회전-발행: 내 색 유통량이 한도 아래면 자기-IOU k AU 재발행([M-104] —
        이행-소각이 부채를 지운 만큼 다시 발행 가능 · 요청은 서명-결박)."""
        env = self.sign_env("TICKMARK", {"kind": "fl21.issue", "k": int(k)})
        return self._post("/issue", {"env": env})

    def split(self, nid, parts):
        return self._post("/submit", {"env": self.sign_env(
            "SPLIT", {"owner": self.p, "note": nid, "parts": parts})})

    def merge(self, nids):
        """노트 병합(파편화 역방향 — 커널 MERGE)."""
        return self._post("/submit", {"env": self.sign_env(
            "MERGE", {"owner": self.p, "notes": list(nids)})})

    def xfer(self, to, nid):
        return self._post("/submit", {"env": self.sign_env(
            "XFER", {"frm": self.p, "to": to, "note": nid})})

    def redeem_job(self, anchor, nid, seed, n, kind="sha256_chain", T=None,
                   k=None, deps=None):
        """★T = 잡별 시한(FL2.2 J-1) · ★k = 표본-검증 깊이([M-162] — 2~16 ·
        무지정 = 서버 기본 2 · H2가 깊이까지 결박: 깊이↔가격 쌍대의 매수자-다이얼)."""
        _pg_face = self._policy_guard(anchor, nid, kind, k)   # ★M-3 선언-가드
        job = {"kind": kind, "seed": seed, "n": n}
        if k is not None:
            job["k"] = int(k)
        if deps:                                     # ★W-4 구성-링크 v0 — 상류 ref(스펙 해시에 결박)
            job["deps"] = [str(x) for x in deps]
        args = {"holder": self.p, "note": nid, "anchor": anchor,
                "spec_sha256": spec_sha256(job)}                  # ★H2 결박
        if T is not None:
            args["T"] = int(T)
        env = self.sign_env("REDEEM", args)
        r = self._post("/job", {"env": env, "job": job})
        pol = getattr(self, "policy", None)          # ★R-3 — 성공 후에만 누적 계상
        if pol is not None and _pg_face is not None and \
                pol.get("max_spend") is not None:
            pol["spent"] += _pg_face
        return r

    def job(self, ref):
        return self._get(f"/job/{ref}")

    def state(self):
        return self._get("/state")

    def stats(self):
        return self._get("/stats")

    # ── ★이행자 역할(P-1) — 누구나 앵커가 될 수 있다 ──
    def open_jobs(self):
        """나를 앵커로 지명한 열린 작업들."""
        return self._get(f"/jobs?anchor={self.p}")["jobs"]

    @staticmethod
    def compute_sha256(job):
        """sha256 계열 로컬 계산(이행자용 — pycheck는 당신의 지능 몫)."""
        h = bytes.fromhex(job["seed"])
        if job["kind"] == "sha256_chain":
            for _ in range(int(job["n"])):
                h = hashlib.sha256(h).digest()
            return h.hex()
        ck = []
        n = int(job["n"])
        for i in range(0, n, _CKPT):
            for _ in range(min(_CKPT, n - i)):
                h = hashlib.sha256(h).digest()
            ck.append(h.hex())
        return {"final": h.hex(), "ckpts": ck}

    def deliver_job(self, ref, output):
        env = self.sign_env("DELIVER", {"anchor": self.p, "ref": ref,
                                        "output_sha256": output_sha256(output)})
        return self._post("/deliver", {"env": env, "output": output})  # ★H2 결박

    def judge_job(self, judge_anchor, nid, target_ref, checker_b64):
        """★판정-재귀 v0([M-120]) — target 잡의 산출을 입력으로 「판정」을 주문.
        판정도 이행이다: 판정자(judge_anchor)는 input.txt(= target 산출)를 심사한
        verdict를 산출로 전달하고, checker는 verdict의 형식만 검사한다(내용은 판정자
        몫 — 그것이 상품). verdict는 /job으로 공개·H2로 대상·명세가 head-결박된다."""
        tgt = self.job(target_ref)
        t_out = tgt.get("output")
        # 입력 규약: input.txt = 대상 산출의 canonical JSON(형 무관 — 판정자는 json 파싱)
        ib = base64.b64encode(canon(t_out)).decode()
        job = {"kind": "pyjudge", "checker_b64": checker_b64, "input_b64": ib}
        env = self.sign_env("REDEEM", {"holder": self.p, "note": nid,
                                       "anchor": judge_anchor,
                                       "spec_sha256": spec_sha256(job),
                                       "judges_ref": target_ref})  # 감사용 참조 결박
        return self._post("/job", {"env": env, "job": job})

    def work_pending(self):
        """열린 sha256 계열 작업을 전부 계산·전달(pycheck는 건너뜀)."""
        done = []
        for ref, j in self.open_jobs().items():
            if j["job"]["kind"].startswith("sha256"):
                done.append(self.deliver_job(ref,
                                             self.compute_sha256(j["job"])))
        return done

    # ── ★버전-경계 선언(P-10) — head-결박 공개 선언(요율이 분절을 안다) ──
    def declare_version(self, v):
        env = self.sign_env("TICKMARK", {"kind": "fl21.version",
                                         "v": str(v)[:32]})
        return self._post("/submit", {"env": env})

    # ── ★작업-범위 선언(H5 — [M-126]) — 온-원장 결박·노드가 제출-시점 강제 ──
    def declare_scope(self, kinds=None, raw=False, max_exposure=0, max_T=0,
                      clear=False):
        """내 수락 범위 공표: kinds(잡 클래스 화이트리스트)·raw(원시 상환 수락)·
        max_exposure(청구 액면 상한)·★max_T(잡별 시한 상한 — FL2.2 · 0 = 무제한).
        범위-밖 청구는 노드가 제출 시점에 거부한다(기한-사고·EXIT-잠금 그리프 차단).
        clear=True = 선언 철회(전-수락 복귀)."""
        args = {"kind": "fl21.scope", "clear": True} if clear else \
            {"kind": "fl21.scope", "kinds": list(kinds or []),
             "raw": bool(raw), "max_exposure": int(max_exposure),
             "max_T": int(max_T)}
        return self._post("/submit", {"env": self.sign_env("TICKMARK", args)})

    # ── ★재검증 요청(P-11 — [M-126]) — 낙관적-검증의 챌린지 창 ──
    def challenge(self, ref):
        """이행-완료 잡의 재검증을 노드에 요구한다(등록 주체 서명 — 오프-원장 요청).
        일치 = 계수만 · ★불일치 = 온-원장 기록(fl21.challenge — 앵커 공개 실적).
        표본-검증 클래스는 재검증마다 새 구간을 뽑아 검증 깊이가 실제로 깊어진다."""
        import secrets as _sec
        body = {"ref": str(ref), "p": self.p, "epoch": self._get("/state")["epoch"], "nonce": _sec.token_hex(8)}   # ★[M-211] R4-F09-3 — 릴레이 동형 신선-서명(영구 재생 토큰 차단)
        sig = self.key.sign(self._d["chal"] + self.log_id + canon(body)).hex()
        return self._post("/challenge", {**body, "sig": sig})

    # ── ★호가 창(R2-a) — 오프-원장 서명 게시판(ASK = 매도 호가 · WANT = 매수 호가) ──
    # ⚠️게시는 자문(무-에스크로·무-구속) — 구속·정산은 온-원장(redeem_job·submit_block)만.
    def board(self):
        """현재 호가 창: asks(가격 오름차순 = 최우선 매도부터)·wants(내림차순)."""
        return self._get("/board")

    def _board_send(self, body):
        sig = self.key.sign(self._d["board"] + self.log_id + canon(body)).hex()
        return self._post("/board", {"post": body, "sig": sig})

    # ── ★[M-162] leg-릴레이 — 원자-체결의 대역-외 leg 교환 자기-서비스 ──
    def send_leg(self, to, payload):
        """서명-leg(들)를 상대 사서함으로 — payload = 임의 JSON(관례: {"ref", "legs"}).
        ⚠️노드는 무해석·무구속(자문층) · leg 봉투는 nonce-1회용이라 중계 탈취 이득 0."""
        body = {"p": self.p, "to": to,
                "blob": json.dumps(payload, ensure_ascii=False),
                "epoch": self.state()["epoch"]}   # ★R-1 신선도(재전송 차단)
        sig = self.key.sign(self._d["relay"] + self.log_id + canon(body)).hex()
        return self._post("/relay", {"msg": body, "sig": sig})

    def fetch_legs(self):
        """내 사서함 수신(읽고-지움) — [{frm, payload, epoch}]."""
        import secrets as _sec
        body = {"p": self.p, "fetch": True, "epoch": self._get("/state")["epoch"], "nonce": _sec.token_hex(8)}   # ★[M-210] 신선-서명(epoch ±8) + 1회용 서명(같은 에포크 재-폴링도 새 서명)
        sig = self.key.sign(self._d["relay"] + self.log_id + canon(body)).hex()
        r = self._post("/relay/fetch", {"msg": body, "sig": sig})
        out = []
        for m in r["msgs"]:
            try:
                out.append({"frm": m["frm"], "epoch": m["epoch"],
                            "payload": json.loads(m["blob"])})
            except Exception:
                continue                     # 비-JSON blob = 조용히 버림(자문층)
        return out

    def post_ask(self, kind, title, price, detail="", ttl=1440):
        """매도 호가 게시: 「kind 작업을 price AU(최소)부터 이행하겠다」.
        ttl = 수명(에포크 · 기본 1440 = 60s 틱 기준 하루 · 상한 10080)."""
        return self._board_send({
            "side": "ask", "kind": kind, "title": str(title),
            "detail": str(detail), "price": int(price), "p": self.p,
            "expires": self._get("/state")["epoch"] + int(ttl)})

    def post_want(self, kind, title, price, detail="", ttl=1440):
        """매수 호가 게시: 「kind 작업을 price AU(최대)까지 사겠다」."""
        return self._board_send({
            "side": "want", "kind": kind, "title": str(title),
            "detail": str(detail), "price": int(price), "p": self.p,
            "expires": self._get("/state")["epoch"] + int(ttl)})

    def retract_post(self, post_id):
        """내 게시 철회(본인-서명이 소유 증명)."""
        return self._board_send({"rm": str(post_id), "p": self.p})

    # ── ★[M-178] 수락-채널 v0 — 일치-후-수락 의견(record-only · 요율-비연동) ──
    def accept_job(self, ref, verdict="accept", note="", ttl=10080):
        """이행-후 산출에 수락/재작업 의견을 서명-공표(그 청구의 매수자만).
        (ref, 나)당 1건 — 재게시 = 교체(번복은 새 의견). ⚠️record-only: 정산·요율
        무접촉 — 내 거절-비율도 같은 채널에 공개된다(양측 대칭)."""
        # ★[M-209] v = (ref, 나) 판정 버전 — 기존 레코드가 있으면 +1(교체는 전진만 · 캡처된 옛 서명의 재생-되돌리기 차단)
        _ac = self._get("/accept")
        _ac = _ac if isinstance(_ac, dict) else {}
        cur = next((r for r in (_ac.get("records") or _ac.get("accepts") or [])
                    if isinstance(r, dict) and (r.get("rec") or {}).get("ref") == str(ref) and (r.get("rec") or {}).get("p") == self.p), None)
        # ★[M-210] R3-F09-1 — 노드의 (ref, p) 고수위 워터마크(최신 레코드가 만료된 뒤에도 산다)까지 넘어야 게시된다
        _hw = max((int(h.get("v", 0)) for h in (_ac.get("hwm") or []) if isinstance(h, dict) and h.get("ref") == str(ref) and h.get("p") == self.p), default=0)
        v = max(int(((cur or {}).get("rec") or {}).get("v", 0)), _hw) + 1
        body = {"ref": str(ref), "p": self.p, "verdict": str(verdict),
                "note": str(note),
                "expires": self._get("/state")["epoch"] + int(ttl), "v": v}
        sig = self.key.sign(self._d["accept"] + self.log_id + canon(body)).hex()
        return self._post("/accept", {"rec": body, "sig": sig})

    def accepts(self):
        """수락-레코드 전량(집계는 underwriter.py acceptance)."""
        return self._get("/accept")

    # ── ★원자 다자-거래 — 다리(서명 봉투) 교환 + /block 제출(all-or-nothing) ──
    def make_leg(self, typ, args):
        """원자 거래용 다리 — sign_env와 동일(상대와 교환해 submit_block으로)."""
        return self.sign_env(typ, args)

    def submit_block(self, legs):
        """다리 목록을 원자 제출 — 하나라도 실패하면 전부 무효(커널 BLOCK 법)."""
        return self._post("/block", {"legs": legs})

    def suggest_prem(self, ref):
        """공정 보험료 제안 = ⌈p̂ × exposure⌉ — /stats 공개 요율 원료.
        ★버전-세탁 방어(완결성 점검 med): 현 세그먼트만 보면 앵커가 새 버전을 선언해
        나쁜 손해 이력을 무비용 세탁한다. ⟹ **성숙 이력이 있는 세그먼트 중 최악 p̂**을
        보수적으로 쓴다(무이력 신버전은 prior로 남되 과거 나쁨을 못 지운다).
        ⚠️p̂×exposure는 총-기대손실 상한 — 인수자는 불이행-층 뒤 2차-손실이므로 실제
        기대원가는 그 이하다(가격은 시장이 정한다 · 이건 상한-제안일 뿐)."""
        j = self.job(ref)
        st = self.stats()
        a = st["anchors"].get(j["anchor"])
        if not a or not a.get("segments"):
            p_hat = 0.5                        # 무이력 = 라플라스 prior
        else:
            mature = [s["p_hat"] for s in a["segments"].values()
                      if s.get("mature", 0) > 0]
            cur = a["segments"].get(a.get("version") or "v0")
            p_hat = max(mature) if mature else \
                (cur or list(a["segments"].values())[-1])["p_hat"]
        return max(1, -(-int(p_hat * j["exposure"] * 100) // 100))

    # ── ★인수(P-4) — 남의 청구를 인수하기(담보 β≥1/2 · 기금 몫 자기적립) ──
    def cover(self, ref, prem=1, force=False, submit=True):
        if not self.notes():         # ★N-22([M-125]) — 빈 지갑 = 정제 예외
            raise RuntimeError("커버 불가: 보유 노트 0(담보·기금 재원 없음)")
        j = self.job(ref)
        exp = j["exposure"]
        # ★기한-후 인수 가드(직접 재리뷰 RU-1): 기한 지난 열린 청구의 인수 = 즉시 손실
        if not force and self.state()["epoch"] > j["deadline"]:
            raise RuntimeError("기한 경과 청구 — 인수는 즉시 손실(force=True로 무시 가능)")
        need = -(-exp // 2)                      # β_min = 1/2(정수-정확 상향)
        st = self.state()
        g = self.meta["gen"]
        prem_f = prem * g["uw_phi_num"] // g["uw_phi_den"]
        cap = g["fq_mult"] * max(st["F_peak"], g["fq_base"])
        if g["fq_mult"] > 0 and st["F_uw"] + prem_f > cap:
            prem_f = 0                            # ★흡입-결박 미러(커널 v0.3 동형)
        # ★[M-155] F-1 — 정확-액면 담보: 커널은 담보를 **합계**로 검증하고 정산은
        # 잉여를 mint-back 한다(U-2 — 유통 캠페인에서 원문 재확인) ⟹ 종전 1-단위
        # 쪼개기(구현 선택)는 커버당 노트 O(need) 증식 = state_root 천장 낭비였다.
        # 필요 액면을 정확히 깎아 담보 1장 + 기금 ≤1장으로 연다(경제 동일 — T-COVER).
        used = set()

        def _carve(face):
            if face <= 0:
                return None
            for n in self.notes():
                if n["face"] == face and n["nid"] not in used:
                    used.add(n["nid"])
                    return n["nid"]
            frees = [n for n in self.notes() if n["nid"] not in used]
            big = max(frees, key=lambda x: x["face"]) if frees else None
            if big is None or big["face"] < face:
                raise RuntimeError(
                    f"담보·기금 재원 부족(필요 액면 {face} · "
                    f"최대 가용 {big['face'] if big else 0})")
            self.split(big["nid"], [face, big["face"] - face])
            nid = next(n["nid"] for n in self.notes()
                       if n["face"] == face and n["nid"] not in used)
            used.add(nid)
            return nid
        cov = [_carve(need)]
        fund = [f for f in [_carve(prem_f)] if f]
        env = self.sign_env("UW", {"uw": self.p, "ref": ref,
                                   "cov_notes": cov, "prem": prem,
                                   "prem_fund_notes": fund})
        if not submit:
            return env                          # 원자 거래용 다리로 반환
        return self._post("/submit", {"env": env})

    # ── ★실적 증명(P-9) — 운영자-서명·전량-아니면-무 ──
    def fetch_attest(self, principal):
        return self._get(f"/attest/{principal}")

    def _operator_key_schedule(self):
        """★[M-212] R5-F06-1(CRITICAL 수리) — 운영자 키-일정 [(발효 seq, pk_hex)] 은 **verify_chain 이 검증한 사슬의 부산물**로만 얻는다:
        head 재계산 · 그 시점 운영자 키의 head_sig · 창세 핀(RELEASE) 을 통과한 REKEY 항만 일정에 들어간다. 구판은 /log 의 REKEY 를
        무검증으로 추종해 미러가 위조 REKEY 한 줄로 공격자 키를 일정에 넣을 수 있었다(신뢰를 한 칸 옮겼을 뿐 검증을 옮기지 않은 실패 모드)."""
        n = int((self._get("/state") or {}).get("seq") or 0)
        cache = getattr(self, "_opk_cache", None)
        if cache and cache[0] == n:
            return cache[1]
        r = self.verify_chain()
        if not (isinstance(r, dict) and r.get("ok")):
            raise RuntimeError(f"사슬 검증 실패 — 키-일정 유도 불가: {(r or {}).get('why')}")
        sched = list(getattr(self, "_op_sched", []) or [])
        self._opk_cache = (n, sched)
        return sched

    def verify_attest(self, att):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey as _PK)
        doc = att.get("doc") if isinstance(att, dict) else None
        if not isinstance(doc, dict) or not isinstance(att.get("operator_sig"), str):   # ★[M-215] D2-10 — 비정형 입력은 예외가 아니라 ok:false
            return {"ok": False, "why": "어테스트 형식 비정형(doc/operator_sig)"}
        if doc.get("complete") is not True:
            return {"ok": False, "why": "부분 발췌 = 무효(전량-아니면-무) — stale 어테스트(as_of < upto)도 여기 포함"}
        if doc.get("log_id") != self.log_id.hex():         # ★[M-211] 다른 원장의 어테스트를 이 원장 것으로 받지 않는다
            return {"ok": False, "why": "log_id 불일치(다른 원장의 어테스트)"}
        try:
            sched = self._operator_key_schedule()
        except Exception as _ex:                            # 사슬이 검증되지 않으면 어테스트도 검증되지 않는다(fail-closed)
            return {"ok": False, "why": str(_ex)[:200]}
        upto = int(doc.get("upto_seq") or 0)
        active = [pk for (frm, pk) in sched if frm <= upto]
        try_pks = [active[-1]] if active else [sched[0][1]]
        try:
            for hx in try_pks:
                try:
                    _PK.from_public_bytes(bytes.fromhex(hx)).verify(bytes.fromhex(att["operator_sig"]), self.domain + canon(doc))
                    return {"ok": True, "principal": doc["principal"], "upto_seq": doc["upto_seq"], "key": hx[:16]}
                except InvalidSignature:
                    continue
            return {"ok": False, "why": "서명 위조(발효 운영자 키-일정 아래 검증 실패)"}
        except (ValueError, TypeError):
            return {"ok": False, "why": "어테스트 형식 비정형"}

    # ── 라이트 검증(A-6 · R-6 봉합): 확정 높이까지 엄격 검증 + 미서명 최신 꼬리는 pending ──
    def verify_chain(self, since=0, limit_batches=200, expect_genesis_head=None):
        # ★[M-210]/[M-211] 기본 핀 = RELEASE(파일 또는 내장 사본)의 genesis_head — 노드가 RELEASE 의 log_id 를 주장할 때만.
        #   결과는 핀 여부를 **증언**한다(genesis_pin · release_identity) — 핀 없는 ok 와 핀 있는 ok 가 같은 출력이던 것(R4).
        _pins = release_pins()
        _pin_src = "flag" if expect_genesis_head is not None else None
        _rel = "unknown"
        if _pins.get("source") == "conflict":
            _rel = "conflict"
        elif _pins.get("log_id"):
            _rel = "match" if str((self.meta or {}).get("log_id")) == _pins["log_id"] else "mismatch"
        self._release_pins_eff = _pins if _rel == "match" else ({**RELEASE_PINS, "source": "embedded"} if _rel == "conflict" else {})   # ★[M-213] Q-5 — 충돌이어도 공동서명 핀은 내장 사본으로 보수 유지
        if expect_genesis_head is None and _rel == "match":
            expect_genesis_head = _pins.get("genesis_head"); _pin_src = "release"
        if expect_genesis_head is None and _rel == "conflict":
            return {"ok": False, "why": f"RELEASE 핀 충돌({_pins.get('conflict')}) — 파일과 내장 사본이 다르다 · expect_genesis_head= 를 명시하라",
                    "genesis_pin": None, "release_identity": _rel}
        """head 사슬·운영자 서명은 전량 엄격. 공동-서명(k-of-n)은 비동기 도착하므로
        ★공동-서명이 아직 부족한 **최신 연속 꼬리**는 위반이 아니라 `pending`(확정 미도달).
        블록체인 confirmation-depth 시맨틱 — 확정 prefix가 정합이면 ok(pending 별도 보고).
        위반은 오직: head 불일치·사슬 단절·운영자 서명 위조·★확정된(공동서명 완비) 항목의
        서명 실패(= 진짜 변조). ★limit_batches 소진 = 절단 명시 실패([M-143] F-A —
        부분 검증을 ok로 보고하지 않는다 · 큰 원장은 인자를 올려 전량 검증).

        ★[M-195] **아키텍처 방어**(냉독 라운드5 — 검증-견고성 부류가 M-189·192·194 에서
        loop 별로 세 번 「닫혔다」가 매번 다른 경로[JOIN-pk 파싱·cosig 병합·log fetch·
        스칼라 항]에서 재발했다). 인스턴스 대신 **함수 전체를 감싼다**: 악의 노드가 어떤
        비정형을 서빙해도 크래시(트레이스백) 대신 ok:false 를 돌려준다. 정당한 ok:false
        반환은 예외가 아니라 return 이라 이 래퍼를 그대로 통과한다."""
        try:
            _r = self._verify_chain_inner(since, limit_batches, expect_genesis_head)
            if isinstance(_r, dict):
                _r["genesis_pin"] = _pin_src
                _r["release_identity"] = _rel
                if _pin_src is None:
                    _r["pin_note"] = ("이 노드는 RELEASE 의 원장이 아니다(log_id 불일치) — 다른 배포면 정상 · 발표 원장을 기대했다면 위조" if _rel == "mismatch"
                                      else "genesis_head 무핀 — expect_genesis_head= 를 명시하라")
                elif _rel == "conflict":
                    _r["pin_note"] = "RELEASE 파일↔내장 핀 충돌 — 명시 핀으로 진행 · 공동서명 핀은 내장 사본 기준(sdk.py 갱신 필요)"   # ★[M-213] 플래그 경로도 증언
                if _r.get("ok") and _r.get("confirmed", 0) == 0:
                    _r["warning"] = "확정 0 — 2-of-3 공동서명으로 확정된 항이 없다(pending 만) · confirmed 를 읽으라"   # ★[M-213] Q-6(R5-F05-6)
            return _r
        except Exception as e:
            return {"ok": False,
                    "why": f"검증 예외(악의 노드의 비정형 서빙 추정): {type(e).__name__}"}

    def _verify_chain_inner(self, since=0, limit_batches=200, expect_genesis_head=None):
        meta = self.meta
        # ★FL2.3 J-4 — 시작점은 **창세** operator 키(operator_pk0) · 이후 REKEY 항이 키-일정을 준다(로그-파생)
        op_pk = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(meta.get("operator_pk0") or meta["operator_pk"]))
        self._op_sched = [(0, meta.get("operator_pk0") or meta["operator_pk"])]   # ★[M-212] 일정 시작 = 창세 키
        co_pks = {c: Ed25519PublicKey.from_public_bytes(bytes.fromhex(h))
                  for c, h in meta["cosigners"].items()}
        k_need = meta["cosign_k"]
        self._fetched_bytes = 0                                   # ★[M-211] R4-F05-7 — 호출마다 누적 리셋(조기 반환 잔량 합산 방지)
        _pe = getattr(self, "_release_pins_eff", {}) or {}
        if _pe.get("cosign_k") is not None:                      # ★[M-211] R4-F05-2 — 노드-선언 k·공동서명자 집합을 RELEASE 로 대조(k=0 「전량 확정」 위조 차단)
            if int(k_need) < int(_pe["cosign_k"]) or set(meta["cosigners"].values()) != set(_pe.get("cosigners") or []):
                return {"ok": False, "why": f"공동서명 구성이 RELEASE 와 다르다(노드 k={k_need} · 서명자 {len(meta['cosigners'])}명 vs RELEASE k={_pe['cosign_k']} · {len(_pe.get('cosigners') or [])}명)"}
        if not isinstance(k_need, int) or isinstance(k_need, bool) or k_need < 1 or k_need > len(meta["cosigners"]):
            return {"ok": False, "why": f"cosign_k={k_need!r} 비정형(1 ≤ k ≤ 서명자 수 {len(meta['cosigners'])})"}   # ★[M-213] k 상한(무한 pending 위조 차단)
        # ★[M-115] 봉투-서명 전량 검증 원료(냉독 결함 1 봉합 — 문서 주장을 참으로):
        # 참여자 pk = JOIN 항목에서 등록 · 창세 좌석 pk = /meta.genesis_pks · 운영자 = op_pk.
        # 이로써 「악의 운영자가 사용자-행위를 위조해 끼워 넣는」 것까지 라이트 검증이 잡는다.
        env_pks = {"operator": op_pk}
        for a, h in (meta.get("genesis_pks") or {}).items():
            env_pks[a] = Ed25519PublicKey.from_public_bytes(bytes.fromhex(h))
        lid = bytes.fromhex(meta["log_id"])

        def _env_ok(env):
            p_ = env.get("p")
            pk = env_pks.get(p_)
            if pk is None:
                return f"봉투 서명자 미지({p_})"
            body = {"typ": env.get("typ"), "args": env.get("args"),
                    "p": p_, "epoch": env.get("epoch")}
            try:
                pk.verify(bytes.fromhex(env["sig"]),
                          sig_msg(lid, body, env["nonce"]))
            except (InvalidSignature, ValueError, KeyError, TypeError):
                return "봉투 서명 위조"
            return None
        cos = {}
        s = since
        cos_complete = False
        for _ in range(limit_batches):
            batch = self._get(f"/cosigs?since={s}")["cosigs"]
            if not batch:
                cos_complete = True
                break
            _tot = getattr(self, "_fetched_bytes", 0) + len(json.dumps(batch))          # ★[M-210] R3-F05-M1 — /cosigs 도 누적 총량 상한
            self._fetched_bytes = _tot
            if _tot > MAX_TOTAL_RESP:
                self._fetched_bytes = 0
                return {"ok": False, "why": f"누적 판독 총량 상한 {MAX_TOTAL_RESP} 초과(/cosigs) — 노드 응답 거부(fail-closed)"}
            for r in batch:      # ★D-2 병합 — 분리 서명자의 부분-서명 줄들을 합친다
                m = cos.setdefault(r["seq"], {"head": r["head"], "sigs": {}})
                if r["head"] == m["head"]:
                    for cnm, sg in r["sigs"].items():
                        m["sigs"].setdefault(cnm, sg)
            if not isinstance(batch[-1].get("seq"), int) or batch[-1]["seq"] + 1 <= s:
                return {"ok": False, "why": "/cosigs 페이지 비-전진(악의 노드 — 왕복 증폭 차단)"}   # ★[M-208] R4-14
            s = batch[-1]["seq"] + 1
        entries = []
        s = since
        log_complete = False
        for _ in range(limit_batches):
            page = self._get(f"/log?since={s}")["entries"]
            if not page:
                log_complete = True
                break
            entries += page
            _tot = getattr(self, "_fetched_bytes", 0) + len(json.dumps(page))
            self._fetched_bytes = _tot
            if _tot > MAX_TOTAL_RESP:                                                        # ★[M-209] R2-F11-2 — 누적 총량 상한
                self._fetched_bytes = 0
                return {"ok": False, "why": f"누적 판독 총량 상한 {MAX_TOTAL_RESP} 초과 — 노드 응답 거부(fail-closed)"}
            if not isinstance(page[-1].get("seq"), int) or page[-1]["seq"] + 1 <= s:
                return {"ok": False, "why": "/log 페이지 비-전진(악의 노드 — 왕복 증폭 차단)"}       # ★[M-208] R4-14
            s = page[-1]["seq"] + 1
        # ★F-A([M-143]) — 침묵-절단 금지: limit_batches가 소진돼 전량을 못 가져왔으면
        # 부분-검증을 ok로 보고하지 않는다(「전량-아니면-무」 — attest와 같은 규범).
        # 검증기 자신이 유일한 침묵 상한이던 자리의 봉합 — 명시 실패 + 인자 상향 안내.
        if not (cos_complete and log_complete):
            return {"ok": False, "truncated": True,
                    "fetched": len(entries),
                    "why": f"절단: limit_batches({limit_batches}) 소진 — 전량 미조회"
                           "(부분 검증은 판정이 아니다 · 인자를 올려 재실행)"}
        # ★[M-208] R4-15(냉독 4 · F05) — 「원천-철회」와 「전위-절단」은 ok 가 아니다: since 0 인데 0항이면 실패 ·
        #   첫 항은 창세(seq 0 · prev "genesis")에 앵커 · 노드가 /state 로 주장하는 seq 보다 적게 서빙하면 꼬리 생략 = 실패.
        if since == 0 and not entries:
            return {"ok": False, "why": "원장 0항 — 라이브 원장의 원천-철회이거나 빈 노드(검증 대상 없음 = ok 아님)"}
        if since == 0 and entries and not (entries[0].get("seq") == 0 and entries[0].get("prev") == "genesis"):
            return {"ok": False, "why": f"창세 앵커 부재: 첫 항 seq {entries[0].get('seq')} prev {str(entries[0].get('prev'))[:12]} — 전위-절단"}
        self._fetched_bytes = 0
        # ★[M-209] R2-F07-1 — 창세 **내용** 고정: 대역-외 genesis_head(RELEASE)를 주면 첫 항 head 와 대조 · 노드 /meta.genesis_head 와도 정합해야 한다
        if since == 0 and entries:
            _gh = str(entries[0].get("head"))
            if expect_genesis_head is not None and _gh != str(expect_genesis_head):
                return {"ok": False, "why": f"genesis_head 불일치: 원장 {_gh[:12]}… ≠ 기대 {str(expect_genesis_head)[:12]}… — 같은 정체성의 다른 창세"}
            _mg = (self.meta or {}).get("genesis_head")
            if _mg is not None and str(_mg) != _gh:
                return {"ok": False, "why": "노드 /meta.genesis_head 가 서빙된 첫 항과 다르다"}
        # ★[M-209] R2-F06-1 — JOIN/REKEY 로 등록된 키가 저-위수면 그 주체의 봉투는 누구나 위조 가능: 검증 거부(fail-closed)
        for e in entries:
            _env = e.get("env") or {}
            if e.get("kind") == "REJECT":
                continue
            _pks = []
            if _env.get("typ") in ("JOIN", "REKEY"):
                _pks = [(_env.get("args") or {}).get("pk" if _env["typ"] == "JOIN" else "new_pk")]
            elif _env.get("typ") == "GENESIS_IMPORT":                                   # ★[M-210] R3-F05-M2 — 수입 주체 pk 도 검사
                _pks = [(x or {}).get("pk") for x in ((_env.get("args") or {}).get("principals") or []) if isinstance(x, dict)]
            for _pk in _pks:
                try:
                    _weak = ed25519_weak_pk(bytes.fromhex(str(_pk)))
                except ValueError:
                    _weak = True
                if _weak:
                    return {"ok": False, "why": f"약한 키 등록 seq {e.get('seq')}({_env['typ']}) — 저-위수 공개키는 소유-증명이 아니다(위조 가능 주체)"}
        try:
            claimed = int(self._get("/state").get("seq"))
            if claimed < 0:
                raise ValueError
        except Exception:
            return {"ok": False, "why": "/state 비정형 — 꼬리-생략 검사를 할 수 없다(fail-closed)"}   # ★[M-211] R4-F05-6
        if entries and claimed is not None and entries[-1].get("seq") is not None and claimed > int(entries[-1]["seq"]) + 1:
            return {"ok": False, "why": f"꼬리 생략: 노드 /state.seq {claimed} > 서빙된 마지막 seq {entries[-1]['seq']}"}
        if not entries and claimed is not None and claimed > since:       # ★[M-213] Q-6(R5-F05-5) — since>0 에서 0항은 「전량 확정」이 아니다
            return {"ok": False, "why": f"꼬리 생략: since {since} 이후 항이 있어야 하는데(/state.seq {claimed}) 노드가 0항을 줬다"}
        prev = None
        confirmed = 0
        pending = 0
        for e in entries:
            # ★[M-191] 엔트리 형식 검증(냉독 라운드2 — head_sig 외 형제 필드도 null/
            # 오타입에 크래시했다: prev.encode()·state_root 등). 악의 노드가 검증-거부
            # 대신 트레이스백을 유발하지 못하게 진입부에서 형식을 균일 거부한다.
            if not (isinstance(e, dict) and isinstance(e.get("prev"), str)
                    and isinstance(e.get("head"), str)
                    and isinstance(e.get("state_root"), str)
                    and isinstance(e.get("env"), dict)
                    and isinstance(e.get("seq"), int)):
                sq = e.get("seq") if isinstance(e, dict) else "?"
                return {"ok": False, "why": f"엔트리 형식 비정형 seq {sq}"}
            try:
                base = {k: e[k] for k in ("env", "fp", "w_epoch", "state_root")}
                if "_force" in e:
                    base = base | {"_force": e["_force"]}
                if e.get("kind") == "REJECT":             # ★FL2.3 J-7 — 인증-거부 항(상태 불변 · head 는 kind 결박)
                    base = base | {"kind": "REJECT"}
                head = hashlib.sha256(e["prev"].encode() + canon(base)).hexdigest()
            except Exception:
                # ★[M-192] 비정형 엔트리는 크래시 아닌 ok:false(냉독 라운드3 — 통째 방어)
                return {"ok": False, "why": f"엔트리 형식 비정형 seq {e.get('seq')}"}
            if head != e["head"]:
                return {"ok": False, "why": f"head 불일치 seq {e['seq']}"}
            if prev is not None and e["prev"] != prev:
                return {"ok": False, "why": f"사슬 단절 seq {e['seq']}"}
            prev = e["head"]
            env = e["env"]
            bad = _env_ok(env)                       # ★[M-115] 봉투 서명 검증
            if bad is None and env.get("typ") == "BLOCK":
                for lg in (env.get("args") or {}).get("legs") or []:
                    bad = _env_ok(lg)                # 원자 블록의 다리도 각자 서명
                    if bad:
                        break
            if bad:
                return {"ok": False, "why": f"{bad} seq {e['seq']}"}
            is_rej = e.get("kind") == "REJECT"
            if env.get("typ") == "JOIN" and not is_rej:   # 이후 봉투의 서명자 pk 등록
                a_ = (env.get("args") or {})
                env_pks[a_.get("principal")] = \
                    Ed25519PublicKey.from_public_bytes(bytes.fromhex(a_["pk"]))
            if env.get("typ") == "GENESIS_IMPORT" and not is_rej:   # ★J-11 — 승계 주체 pk 등록
                for it in (env.get("args") or {}).get("principals") or []:
                    env_pks[it["p"]] = Ed25519PublicKey.from_public_bytes(bytes.fromhex(it["pk"]))
            # ★[M-189] C-1 — 부재를 **거부**한다(옛 `if in`은 서명 없는 로그를
            # 통과시켰다 — 냉독 2차 B1). 라이브 전수 head_sig 보유 확인(부재-거부가
            # pending 정상 동작을 안 깬다: pending 은 head_sig 는 있고 cosig 만 미도달).
            if "head_sig" not in e:
                return {"ok": False, "why": f"운영자 서명 부재 seq {e['seq']}"}
            try:
                op_pk.verify(bytes.fromhex(e["head_sig"]),
                             self.domain + bytes.fromhex(e["head"]))
            except (InvalidSignature, ValueError, TypeError):
                # ★[M-190] null head_sig 등 비정형은 크래시가 아니라 ok:false(냉독 최대판)
                return {"ok": False, "why": f"운영자 서명 위조/비정형 seq {e['seq']}"}
            if env.get("typ") == "REKEY" and not is_rej:   # ★J-4 키-일정: 이 항까지는 구-키 · 다음 항부터 신-키
                a_ = (env.get("args") or {})
                _npk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(a_["new_pk"]))
                env_pks[env.get("p")] = _npk
                if env.get("p") == "operator":
                    op_pk = _npk
                    self._op_sched.append((int(e["seq"]) + 1, a_["new_pk"]))   # ★[M-212] R5-F06-1 — 키-일정은 **검증된 사슬의 부산물**(head 재계산·head_sig 통과 항만)
            r = cos.get(e["seq"])
            good = 0
            if r and r["head"] == e["head"]:
                for c, sig in r["sigs"].items():
                    try:
                        co_pks[c].verify(bytes.fromhex(sig),
                                         self.domain + bytes.fromhex(e["head"]))
                        good += 1
                    except (KeyError, InvalidSignature, ValueError, TypeError):
                        pass    # ★[M-194] 비-hex·홀수-길이·비-str cosig sig 크래시 봉합
                        # (냉독 라운드4 — 통째-방어가 cosig 루프를 안 덮었다 · 형제 _co_ok 동형)
            if good >= k_need:
                confirmed += 1
            else:
                pending += 1
        # ★pending은 최신 연속 꼬리에만 허용(확정된 것 뒤에 미확정이 오는 정상 성장) —
        # 중간에 구멍(확정 사이 미확정)이 있으면 그건 변조/누락이다.
        tail_ok = True
        seen_pending = False
        for e in entries:
            r = cos.get(e["seq"])
            good = sum(1 for c, sig in (r["sigs"].items() if r
                                        and r["head"] == e["head"] else [])
                       if _co_ok(co_pks, c, sig, e["head"], self.domain))
            if good >= k_need:
                if seen_pending:
                    tail_ok = False       # 확정이 미확정 뒤에 옴 = 꼬리 아님
                    break
            else:
                seen_pending = True
        if not tail_ok:
            return {"ok": False, "why": "공동-서명 구멍(확정 사이 미확정 — 변조 의심)"}
        return {"ok": True, "confirmed": confirmed, "pending": pending,
                "head": prev,
                "note": ("pending = 최신 공동-서명 미도달 꼬리(정상 · ~1틱 후 확정)"
                         if pending else "전량 확정")}
