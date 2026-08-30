#!/usr/bin/env python3
"""node.py — R1 노드: FL2.1 캐논(FROZEN)을 감싸는 공개형 서비스 ([M-95] · E-1).

지위: ★캐논 무접촉 — kernel22 v0.1(FL2.2 — [M-127])을 읽기-전용 임포트(법 재구현 0 · lab과 같은 규율의
제품판). 외부 주체는 HTTP API + SDK로 참여한다(키는 클라이언트가 보관 — 노드는 운영자
키만). 영속 = append-only 대장(jsonl) + 기동 전체-리플레이(head 대조 · 파일럿 규율의
서비스판 — A-3). 전 핸들러 예외-격리(비정규 입력 = 4xx · 노드 생존 — A-4). 헤드 k-of-n
공동-서명 사이드카(A-6 — ⚠️v0은 키가 한 노드에 동거: 분산 보관은 배포 문제로 등재).

★화폐 모델 v0([M-103] — D-4 확정 · 자유은행 (i)): 모든 노트에 **색(발행자)**이 있다 —
JOIN 시 자기-IOU 발행(구매력 지급이 아니라 자기-약속 자본) · 상환은 **발행자에게만**
(색-일치 라우팅) · 유입 유동성 = ★상호 신용 교환(/bootstrap — 신규자 자기-IOU ↔
anchor0-IOU 원자 스왑 · 한도 결박 · WIR형) · 배상 노트 = 불이행-앵커 색. 색은 로그-파생
(리플레이 시 재구성 — 사이드카 없음). 데모-유입(무색 보조금)은 폐지.

실행: python3 node.py --data DIR [--port 8788] [--auto-tick SEC] [--join-issue 20]
"""
import argparse
import hashlib
import json
import os
import re
import secrets as _secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "fin_lean", "lang22"))

from kernel22 import (World, Fl22Error as Fl21Error,               # noqa: E402
                      FL22_DOMAIN as FL21_DOMAIN, _canon)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (    # noqa: E402
    Ed25519PublicKey)
import jobs as JOBS                                                # noqa: E402

LABEL = "fl22-r1"
# ★[M-105] D-3 프로덕션 GEN: fq_mult=1(★실측 보정표 n≤128→1 — RFRONT2 규모-의존) ·
# identity_budget=128(전 인구가 보정-구역 안 · k-공존 대역 4배 여유 · 세계-사멸 방지)
GEN = {"fq_mult": 1, "identity_budget": 128,
       # ★FL2.2 리뷰 F-R1 — 잡별-T 상한(EXIT-잠금 그리프 유계 · 60s 틱 기준 1주)
       "redeem_T_max": 10080}
GENESIS = ("anchor0",)               # 창세 앵커(워커 좌석) — 외부 주체는 JOIN
COSIGNERS = ("cosign1", "cosign2", "cosign3")
COSIGN_K = 2
_PNAME = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
BOOT_CAP = 8                         # ★[M-103] 상호-신용 스왑 상한(주체당 · anchor0-IOU)
BLOCK_LEG_TYPES = ("XFER", "UW", "REDEEM", "TICKMARK")   # 색-추적 가능 다리만
OCOMMIT_CAP = 64                      # ★[M-190] ref당 ocommit(재추첨) 상한 —
# C-2 변종(냉독 최대판): 유효-서명 앵커가 틀린 산출로 /deliver 를 재생하면 매번
# ocommit 이 원장에 남는다(nonce 미소비 · deep-verify 실패는 롤백 안 됨). C-2 로
# 제3자는 차단됐고 이제 「앵커 자기-그리핑」인데, 공유 원장 비대는 유계화해야 한다.
# M-164 그라인딩-탐지(재추첨 공개-계수)는 보존하되 ref당 상한을 둔다(정상 이행 = 1회).
# ── ★호가 창(R2-a — [M-116] /scope 성장판 · [시장-미시구조 §6] 최소 발견층) ──
# 게시판 = **오프-원장** 서명 봉투(비용 ~0 · seq 무접촉 · 매칭·정산은 온-원장 그대로).
# 도메인 분리: 게시 서명은 원장 봉투로 재생 불가(역방향도) — 별도 도메인 + log_id 결박.
BOARD_DOMAIN = b"FL22-BOARD"
RELAY_DOMAIN = b"FL22-RELAY"         # ★[M-162] leg-릴레이(오프-원장 서명 사서함)
ACCEPT_DOMAIN = b"FL22-ACPT"         # ★[M-178] 수락-채널(record-only 2차-이력)
ACCEPT_TTL_MAX = 10080               # 레코드 수명 상한(에포크 — 60s 틱 기준 1주)
ACCEPT_PER_P = 256                   # 주체당 활성 레코드 상한(거래-당 1건이라 board보다 큼)
ACCEPT_MAX = 8192                    # 전역 상한(자원 가드)
BOARD_TTL_MAX = 10080                # 게시 수명 상한(에포크 — 60s 틱 기준 1주)
BOARD_PER_P = 8                      # 주체당 활성 게시 상한(스팸 — 예치금은 R2 등재)
BOARD_MAX = 4096                     # 전역 게시 상한(자원 가드)
# ── ★P-11 /challenge([M-126] R2-A — 낙관적-검증의 재검증 창) ──
CHAL_DOMAIN = b"FL22-CHAL"           # 오프-원장 서명 요청(원장 봉투와 도메인 분리)


class Node:
    def __init__(self, data_dir, join_issue=20, genesis_issue=40,
                 bootstrap_cap=BOOT_CAP, cosign_local=None, bridge_ref=None,
                 unit_scale=1):
        # ★[M-127] 단위-정책: 1 AU = unit_scale 기본단위(커널은 정수 액면 — 스케일
        # 불가지). 프로덕션 = 1000(mAU — 미시-보험 입도 해소: prem 1 = 0.1%@1AU).
        self.unit_scale = max(1, int(unit_scale))
        self.dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.lock = threading.RLock()
        self.join_issue = int(join_issue)      # ★[M-103] 자기-IOU 회전 한도([M-104])
        self.genesis_issue = int(genesis_issue)  # 창세 앵커 회전 한도
        self.boot_cap = int(bootstrap_cap)     # ★상호-신용 스왑 상한/주체
        self.colors = {}             # ★nid → 발행자(색) — 로그-파생(리플레이 재구성)
        self.bootstrap_used = {}     # ★주체 → 스왑 누계(로그-파생 · BOOT_CAP 결박)
        self._cosig_seen = set()     # ★(seq, 서명자) — /cosig 재생 중복-제거
        self.cosig_map = {}          # ★N-3([M-110]) — seq→병합 서명(/cosigs 서빙 정본)
        self.ledger_p = os.path.join(data_dir, "entries.jsonl")
        self.cosig_p = os.path.join(data_dir, "cosigs.jsonl")
        self.jobs_p = os.path.join(data_dir, "jobs.json")
        # ★호가 창 — 자문층(정산 아님): 손상 = 빈 판(대장이 정본 · 게시는 재게시 가능)
        self.relay = {}                 # ★[M-162] to → [msg] (휘발 — TTL 짧음)
        self.ocommits = {}              # ★[M-164] ref → 산출-커밋 수(재추첨 흔적)
        self.note_touch = {}            # ★[M-170] nid → 최근 접촉 에포크(F-9a 원료)
        self.board_p = os.path.join(data_dir, "board.json")
        self.board = {}              # id → {post, sig, id}
        if os.path.exists(self.board_p):
            try:
                self.board = json.load(open(self.board_p, encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self.board = {}
        # ★[M-178] 수락-채널 v0 — 자문층(record-only · 요율-비연동 · 손상 = 빈 판)
        self.accept_p = os.path.join(data_dir, "accept.json")
        self.accepts = {}            # id → {rec, sig, id} · id = H(ref|p) = 교체-주소
        if os.path.exists(self.accept_p):
            try:
                self.accepts = json.load(open(self.accept_p, encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self.accepts = {}
        # ── ★D-1 키 실물화: 비밀은 소스가 아니라 data_dir(0600 · 첫 기동 시 생성) ──
        seed = self._load_secret_int(os.path.join(data_dir, "node_secret"))
        # ── ★D-2 공동-서명 분리([M-105]): 노드는 --cosign-local 부분집합의 개인키만 보유 ·
        #    공개키 전량은 cosign_pubs.json(창세 의식에서 고정) · 원격 서명자는 데몬
        #    (cosigner.py)이 /cosig로 회신 — verify_chain의 confirmation-depth가 비동기 흡수 ──
        self.cosign_local = tuple(cosign_local) if cosign_local else COSIGNERS
        if not set(self.cosign_local) <= set(COSIGNERS):
            raise Fl21Error("cosign_local ⊆ COSIGNERS")
        pubs_p = os.path.join(data_dir, "cosign_pubs.json")
        if os.path.exists(pubs_p):
            self.cosign_pubs = json.load(open(pubs_p, encoding="utf-8"))
            self.cos_keys = {}
            for c in self.cosign_local:
                kp = os.path.join(data_dir, f"{c}.key")
                if not os.path.exists(kp):
                    raise Fl21Error(f"D-2: 로컬 서명 키 없음({c}) — 이전했다면 "
                                    "--cosign-local에서 제외")
                self.cos_keys[c] = self._load_ed_key(kp)
        else:                        # 창세 의식: 전 키 생성 → 비-로컬 키 파일은 호스트 이전
            allk = {c: self._load_ed_key(os.path.join(data_dir, f"{c}.key"))
                    for c in COSIGNERS}
            self.cosign_pubs = {c: k.public_key().public_bytes_raw().hex()
                                for c, k in allk.items()}
            json.dump(self.cosign_pubs, open(pubs_p, "w", encoding="utf-8"))
            self.cos_keys = {c: allk[c] for c in self.cosign_local}
        self.scopes = {}             # ★H5([M-126]) anchor → 작업-범위(로그-파생 — 리플레이 재구성)
        self.w = World(master_seed=seed, label=LABEL,
                       genesis_agents=GENESIS, gen=GEN,
                       bridge_ref=bridge_ref)   # ★D-3 — U-0 계보(파일럿 head 결박)
        self._export_anchor_key(data_dir)       # 워커 좌석 키(0600 — 워커가 파일로 로드)
        self.jobs = {}               # ref → {job, anchor, holder, deadline, state, output}
        self._stats_cache = None     # ★D-13 — (log_len, stats)
        self._audit_cache = None     # ★F-B([M-143]) — (log_len, audit 결과)
        self._replay()
        if self.persisted == 0 and self.genesis_issue > 0:   # ★창세 자기-IOU(1회)
            for a in GENESIS:
                self._ksubmit(self.w.sign_env(
                    "operator", "EXT_IN", {"to": a, "amount": self.genesis_issue}))
            self._persist_new()

    @staticmethod
    def _write_secret(path, text):
        """★F-D([M-143]) — 비밀 파일 원자-권한 생성: write-후-chmod는 umask에 따라
        짧은 노출 창이 있다 — O_EXCL·0600으로 생성 자체를 잠근다(경합 = 크게 실패)."""
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(text)

    @staticmethod
    def _load_secret_int(path):
        if os.path.exists(path):
            return int(open(path).read().strip())
        v = _secrets.randbits(256)   # ★RD-8 — 파생 키의 실효 보안 = 시드 엔트로피(256b)
        Node._write_secret(path, str(v))
        return v

    @staticmethod
    def _load_ed_key(path):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey)
        if os.path.exists(path):
            return Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(open(path).read().strip()))
        k = Ed25519PrivateKey.generate()
        Node._write_secret(path, k.private_bytes_raw().hex())
        return k

    def _export_anchor_key(self, data_dir):
        for a in GENESIS:
            p = os.path.join(data_dir, f"{a}.key")
            if not os.path.exists(p):
                self._write_secret(p, self.w._keys[a].private_bytes_raw().hex())

    # ── 영속·복구(A-3) ──
    @staticmethod
    def _read_ledger_lines(path, label="대장"):
        """★H5 — 관용 리플레이: 크래시로 잘린 **마지막** 줄(부분쓰기)은 절단·무시한다
        (중간 줄의 파싱 실패는 진짜 손상 = 예외). ack=내구(fsync)이므로 잘린 꼬리는
        아직 ack 안 된 기입이다. ★N-1([M-108]) — 공동서명 파일도 같은 append+fsync
        창이라 동일 관용이 필요(빠뜨리면 잘린 꼬리 하나가 부팅-불능)."""
        raw = [ln for ln in open(path, encoding="utf-8").read().splitlines()
               if ln.strip()]
        out = []
        for i, ln in enumerate(raw):
            try:
                out.append(json.loads(ln))
            except json.JSONDecodeError:
                if i == len(raw) - 1:
                    break                # 마지막 줄만 관용(부분쓰기)
                raise Fl21Error(f"{label} 손상: 중간 줄 {i} 파싱 실패")
        return out

    @staticmethod
    def _repair_tail(path):
        """★N-2([M-108]) — 잘린 꼬리의 **물리 절단**(부팅 시): 관용 리더가 읽기에서
        무시해도 파일에 남으면 다음 append가 개행 없이 그 줄에 이어붙어, ack된 항목이
        접착-손상으로 **무음 유실**(마지막 줄일 때) 또는 영구 부팅-불능(중간 줄이 될 때)
        이 된다(재현 실증 — 「ack=내구」 위반). 절단되는 바이트는 ack 전(fsync 미완)
        기입뿐이라 무손실 · 완결-무개행 꼬리는 항목 보존·개행만 보수."""
        if not os.path.exists(path):
            return
        raw = open(path, "rb").read()
        if not raw or raw.endswith(b"\n"):
            return
        nl = raw.rfind(b"\n")
        tail = raw[nl + 1:]
        try:
            json.loads(tail)
            with open(path, "ab") as f:      # 완결 줄(개행만 유실) — 개행 보수
                f.write(b"\n")
        except ValueError:
            with open(path, "r+b") as f:     # 부분쓰기 — ack 전 바이트 절단
                f.truncate(nl + 1 if nl >= 0 else 0)

    def _replay(self):
        self._repair_tail(self.ledger_p)     # ★N-2 — append 접착 방지(물리 절단)
        self._repair_tail(self.cosig_p)
        n = 0
        if os.path.exists(self.ledger_p):
            prev = "genesis"
            for e in self._read_ledger_lines(self.ledger_p):
                bi = set(self.w.notes)           # ★색 리플레이(로그-파생)
                rp_b = ({k: dict(v) for k, v in self.w.redeem_pending.items()}
                        if e["env"]["typ"] == "TICK" else None)
                r = self.w._commit(e["env"], replay=True)
                if r["head"] != e["head"] or e["prev"] != prev:
                    raise Fl21Error(f"대장 리플레이 불일치 seq {e['seq']}")
                self._color_step(r, bi, rp_b)
                prev = e["head"]
                n += 1
            for i, e in enumerate(self._read_ledger_lines(self.ledger_p)[:n]):
                self.w.log[i] = e        # 서명 포함 원본 복원(관용 절단·정합)
        if os.path.exists(self.jobs_p):
            try:
                self.jobs = json.load(open(self.jobs_p, encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self.jobs = {}           # ★H5 — 잡 메타 손상은 무해(고아 = GC · 대장이 정본)
        a = self.w.audit()
        if not a["ok"]:
            raise Fl21Error("기동 audit 실패")
        self.persisted = n
        for _e in self.w.log:           # ★[M-165] R4-9 — 재기동 시 ocommit 재구성
            if _e["env"].get("p") == "operator" and \
                    _e["env"]["typ"] == "TICKMARK" and \
                    isinstance(_e["env"].get("args"), dict) and \
                    _e["env"]["args"].get("kind") == "fl21.ocommit":
                _r = _e["env"]["args"].get("ref")
                self.ocommits[_r] = self.ocommits.get(_r, 0) + 1
        self._backfill_cosigs()      # ★내구성 자기치유(아래) — 크래시 반쪽-영속 봉합

    def _backfill_cosigs(self):
        """★공동-서명 구멍 자기치유(직접 리뷰 RD-1): 대장(entries.jsonl) 뒤에 공동-서명
        (cosigs.jsonl)이 별도 append라 그 사이 크래시가 나면 엔트리는 있는데 서명이 없는
        구멍이 남고, 그 구멍이 최신-꼬리가 아니게 되면 verify_chain이 원장을 **영구
        '변조'로 오판**한다(정직한 운영자가 낙인). 공동-서명은 head에 대한 **결정론** 서명이고
        노드가 키를 쥐고 있으므로 빠진 것만 재생성한다 — ★있는 서명은 절대 덮지 않는다
        (손상·head-불일치 서명의 변조 검출은 그대로 살린다 · T-COSIGN 불변)."""
        merged = {}                  # ★병합(D-2 — 줄이 부분-서명일 수 있다) · 있는 서명 불가침
        if os.path.exists(self.cosig_p):
            # ★N-1([M-108]) — 잘린-꼬리 관용을 여기도(대장과 동일 크래시 창)
            for r in self._read_ledger_lines(self.cosig_p, label="공동서명"):
                m = merged.setdefault(r["seq"], {"seq": r["seq"],
                                                 "head": r["head"], "sigs": {}})
                if r["head"] == m["head"]:
                    for c, s in r["sigs"].items():
                        m["sigs"].setdefault(c, s)
                        self._cosig_seen.add((r["seq"], c))   # 재생 중복-제거 시드
        changed = False
        for e in self.w.log:
            m = merged.setdefault(e["seq"], {"seq": e["seq"], "head": e["head"],
                                             "sigs": {}})
            for c, k in self.cos_keys.items():   # ★로컬 키만 치유(원격 몫은 데몬·pending)
                if c not in m["sigs"]:
                    m["sigs"][c] = k.sign(
                        FL21_DOMAIN + bytes.fromhex(e["head"])).hex()
                    changed = True
        # ★N-3([M-110] 맥락-0 5차 적발): /cosigs는 이 병합-맵을 seq-정렬로 서빙한다 —
        # 원시 파일은 append-순서(seq 비정렬·seq당 다중 행)라 행-단위 500 절단 시 페이지
        # 경계에 걸린 seq의 잔여 서명이 SDK 커서(seq+1)에 영구 누락 → 원장 ~167항부터
        # 외부 verify_chain이 영구 「변조 의심」 오판(재현 확정 · 신뢰-뿌리 파괴).
        self.cosig_map = merged
        if not changed:
            return
        tmp = self.cosig_p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as ch:
            for seq in sorted(merged):
                ch.write(json.dumps(merged[seq], sort_keys=True) + "\n")
        os.replace(tmp, self.cosig_p)

    def _atomic(self, fn):
        """★다중 커밋 원자화(완결성 점검 B1 — 부분-커밋 방지): 여러 _ksubmit을 감싸
        실패 시 세계 상태·로그·색·부트스트랩 계수를 진입 시점으로 전부 되감는다.
        (단일 _ksubmit은 커널 _commit이 이미 롤백하지만, 두 커밋 사이 실패는 못 막았다 —
        bootstrap이 EXT_IN 후 BLOCK 실패 시 고아 발행을 남기던 구멍.)"""
        snap = self.w._snap()
        nlog = len(self.w.log)
        cols, boot = dict(self.colors), dict(self.bootstrap_used)
        try:
            return fn()
        except Exception:
            self.w._restore(snap)
            del self.w.log[nlog:]
            self.colors, self.bootstrap_used = cols, boot
            raise

    # ── ★색 엔진([M-103] — 자유은행 (i) · 색 = 로그-파생 · 캐논 무접촉) ──
    def _ksubmit(self, env):
        """커널 제출 + 색 전이(모든 기입 경로 공통 — 리플레이와 동일 규칙)."""
        bi = set(self.w.notes)
        rp_b = ({k: dict(v) for k, v in self.w.redeem_pending.items()}
                if env.get("typ") == "TICK" else None)
        entry = self.w.submit(env)
        self._color_step(entry, bi, rp_b)
        return entry

    def _color_step(self, entry, before_ids, rp_before=None):
        """엔트리 하나의 색 전이([M-103] 규칙): EXT_IN = 수취인 자기-IOU · SPLIT/MERGE =
        상속 · 이동(XFER/REDEEM/UW 담보)은 색 불변 · 소멸(DELIVER/BURN 등)은 제거 ·
        정산(TICK) 배상 = ★불이행-앵커 색 · 그 밖의 정산 재발행(압류 잔돈·담보 잔여) =
        소유자 자기 색(자기 재-약속 독해 — [FREEBANK_ANALOGY §4]·폭포 한계의 정직 규칙)."""
        env = entry["env"]
        self._scope_step(env)                          # ★H5 — 범위 선언 파생
        if env["typ"] == "BLOCK":
            for lg in env["args"]["legs"]:
                self._scope_step(lg)
        now_ids = set(self.w.notes)
        removed = before_ids - now_ids
        rcol = {nid: self.colors.get(nid) for nid in removed}
        for nid in removed:
            self.colors.pop(nid, None)
        added = sorted(now_ids - before_ids, key=int)
        typ = env["typ"]
        # ★F-9a([M-170]) — 노트 접촉-시각(죽은-노트 계기의 원료): 생성·이동이 갱신.
        # 부팅 색-리플레이가 이 함수를 전 엔트리에 돌리므로 재기동에도 자동 재구성.
        ep_now = entry.get("w_epoch", 0)
        for nid in added:
            self.note_touch[nid] = ep_now
        for nid in removed:
            self.note_touch.pop(nid, None)
        _legs = env["args"]["legs"] if typ == "BLOCK" else [env]
        for _lg in _legs:
            if _lg.get("typ") == "XFER":
                _n = str((_lg.get("args") or {}).get("note"))
                if _n in self.w.notes:
                    self.note_touch[_n] = ep_now
        if typ == "EXT_IN":
            for nid in added:
                self.colors[nid] = env["args"]["to"]      # ★자기-IOU 발행
        elif typ in ("SPLIT", "MERGE"):
            cs = {c for c in rcol.values() if c is not None}
            c = next(iter(cs)) if len(cs) == 1 else None  # 가드가 동색을 보장
            for nid in added:
                self.colors[nid] = c or self.w.notes[nid]["owner"]
        elif typ == "TICK":
            force = entry.get("_force") or {}
            # ★F-E([M-143]) — 배상 색-귀속: 휴리스틱(holder·액면 첫-일치 스캔) →
            # **위치+검증**. 커널 _settle의 배상 민트는 전 정산의 **마지막** 민트들이고
            # settled 기록 순서(성숙 ref 정렬 = covered 순서)와 1:1이다 ⟹ added 꼬리
            # K개(K = comp>0 기록 수)가 정확히 그 배상 노트다. 동일-(holder, 액면) 쌍이
            # 여럿이어도 순서가 귀속을 확정하고, 가정이 깨지면(세대-교체로 민트 순서
            # 변경 등) 조용한 오귀속 대신 **크게 실패**한다(색 전체성 불변식과 같은
            # 철학 — 돈의 귀속에 침묵-오류는 없다).
            recs = [r for r in force.get("settled", []) if r.get("comp", 0) > 0]
            comp_nids = added[len(added) - len(recs):] if recs else []
            claimed = set()
            if len(comp_nids) != len(recs):
                raise Fl21Error(f"색 귀속 검증 실패 seq {entry['seq']}: "
                                f"배상 민트 수 불일치({len(comp_nids)}≠{len(recs)})")
            for rec, nid in zip(recs, comp_nids):
                rp = (rp_before or {}).get(rec["ref"])
                n = self.w.notes[nid]
                if not rp or n["owner"] != rp["holder"] or \
                        n["face"] != rec["comp"]:
                    raise Fl21Error(f"색 귀속 검증 실패 seq {entry['seq']}: "
                                    f"배상 민트-순서 가정 파손(ref {rec['ref']})")
                self.colors[nid] = rp["anchor"]            # ★배상 = 불이행-앵커 색
                claimed.add(nid)
            for nid in added:                              # 압류 잔돈·담보 잔여
                if nid not in claimed:
                    self.colors[nid] = self.w.notes[nid]["owner"]
        elif typ == "BLOCK":
            legs = env["args"]["legs"]
            for lg in legs:                                # ★상호-신용 스왑 계수(로그-파생)
                a = lg.get("args") or {}
                if lg.get("typ") == "XFER" and a.get("frm") == GENESIS[0] and \
                   any(l2.get("typ") == "XFER" and
                       (l2.get("args") or {}).get("to") == GENESIS[0] and
                       l2.get("p") == a.get("to") for l2 in legs):
                    f = self.w.notes.get(str(a.get("note")), {}).get("face", 0)
                    p_ = a.get("to")
                    self.bootstrap_used[p_] = self.bootstrap_used.get(p_, 0) + f
            for nid in added:                              # (허용 다리엔 발행 없음 — 방어)
                self.colors[nid] = self.w.notes[nid]["owner"]
        else:
            for nid in added:                              # 방어(도달 불가 경로)
                self.colors[nid] = self.w.notes[nid]["owner"]
        if len(self.colors) != len(self.w.notes):          # ★색 전체성 불변식
            raise Fl21Error(f"색 불변식 파손 seq {entry['seq']}")

    def _scope_step(self, e):
        """★H5([M-126]) — 작업-범위 선언의 로그-파생(live·리플레이 공통 경로 =
        _color_step). 파생은 관용(비정형은 최선-해석) · 신규 제출의 엄격 검증은
        _guard_env가 한다."""
        if (e or {}).get("typ") != "TICKMARK":
            return
        a = e.get("args") or {}
        if not isinstance(a, dict) or a.get("kind") != "fl21.scope":
            return
        p = e.get("p")
        if a.get("clear"):
            self.scopes.pop(p, None)
            return
        kinds = a.get("kinds")
        me = a.get("max_exposure")
        mt = a.get("max_T")
        self.scopes[p] = {
            "kinds": [k for k in kinds if isinstance(k, str)]
            if isinstance(kinds, list) else [],
            "raw": a.get("raw") is True,
            "max_exposure": me if isinstance(me, int)
            and not isinstance(me, bool) and me >= 0 else 0,
            # ★FL2.2 리뷰 F-R1 — 잡별-T의 앵커-측 상한(EXIT-잠금·노출-기간 결박)
            "max_T": mt if isinstance(mt, int)
            and not isinstance(mt, bool) and mt >= 0 else 0}

    def _scope_check(self, anchor, kind, face, T=None):
        """★H5 — 범위-밖 청구의 제출-시점 거부(기한-사고 그리프 원천 차단).
        무-선언 앵커 = v0 시맨틱(전 수락 — 하위호환) · kind = 잡 클래스 또는 'raw' ·
        ★T = 잡별 시한(FL2.2 — max_T 선언 앵커는 초과-기간 청구를 거부: 긴-T가
        obl·EXIT-잠금을 임의 연장하는 그리프의 앵커-측 방어)."""
        sc = self.scopes.get(anchor)
        if sc is None:
            return
        if kind == "raw":
            if not sc.get("raw"):
                raise Fl21Error(f"H5 범위-밖: {anchor}는 원시 상환 미수락"
                                "(/scope 선언 참조)")
        elif kind not in sc.get("kinds", []):
            raise Fl21Error(f"H5 범위-밖: {anchor} 수락 = {sc.get('kinds')}")
        me = sc.get("max_exposure", 0)
        if me and face > me:
            raise Fl21Error(f"H5 범위-밖: 액면 {face} > 최대 노출 {me}")
        mt = sc.get("max_T", 0)
        if mt and T is not None and T > mt:
            raise Fl21Error(f"H5 범위-밖: 잡별 시한 {T} > 앵커 상한 {mt}")

    def _guard_env(self, env):
        """★서비스층 기입 정책(캐논 무접촉 — 경로 제한): RD-7 + 색-일치 라우팅([M-103])."""
        typ = (env or {}).get("typ")
        args = (env or {}).get("args") or {}
        if typ == "TICKMARK" and isinstance(args, dict) \
                and args.get("kind") == "fl21.scope":   # ★H5 — 선언 엄격 검증
            if args.get("clear") is True:
                pass
            else:
                kinds = args.get("kinds")
                if not isinstance(kinds, list) or \
                        any(k not in JOBS.KINDS for k in kinds):
                    raise Fl21Error(f"scope: kinds ⊆ {list(JOBS.KINDS)} 리스트")
                me = args.get("max_exposure", 0)
                if not isinstance(me, int) or isinstance(me, bool) or me < 0:
                    raise Fl21Error("scope: max_exposure ≥ 0 정수")
                if not isinstance(args.get("raw", False), bool):
                    raise Fl21Error("scope: raw = 불리언")
                mt = args.get("max_T", 0)
                if not isinstance(mt, int) or isinstance(mt, bool) or mt < 0:
                    raise Fl21Error("scope: max_T ≥ 0 정수")
        if typ == "DELIVER" and str(args.get("ref")) in self.jobs:
            raise Fl21Error("잡-결박 이행은 /deliver 경유(산출 검증-후 이행 — RD-7)")
        if typ == "TICKMARK" and isinstance(args, dict) \
                and args.get("kind") in ("fl21.ocommit", "fl21.challenge"):
            # ★[M-191] operator 가 **만드는** 예약 kind 만 차단(냉독 라운드2 — 사용자
            # fl21.ocommit 이 재기동 카운터를 오염 → DoS). 차단목록으로 좁힘: 다른
            # 사용자 kind(scope·version·issue·note 등)는 각자 경로에서 검증된다.
            raise Fl21Error(f"TICKMARK kind '{args.get('kind')}'는 예약(operator 전용)")
        if typ == "REDEEM":
            c = self.colors.get(str(args.get("note")))
            if c is None:
                raise Fl21Error("미지/무색 노트 — 상환 불가")
            if args.get("anchor") != c:
                raise Fl21Error(f"색-일치: 노트는 발행자({c})에게만 상환([M-103])")
        if typ == "MERGE":
            cs = {self.colors.get(str(x)) for x in (args.get("notes") or [])}
            if len(cs) != 1 or None in cs:
                raise Fl21Error("MERGE: 동색 노트만(색 상속 보전)")
        if typ == "REDEEM_CANCEL":   # ★취소-창([M-105] D-10 ④ — 취소-그리프 방어)
            j = self.jobs.get(str(args.get("ref")))
            if j and j.get("state") == "open" and \
                    self.w.epoch * 2 > j["t0"] + j["deadline"]:
                raise Fl21Error("취소-창 경과: 잡-결박 청구는 기한 절반 후 취소 불가"
                                "(이행 착수 매몰 방어)")
        if typ == "EXIT":            # ★발행자-부재 방어([M-113] 더블체크 FB-1/MS-1):
            # 커널 EXIT는 bal·obl만 봐서 **유통 중인 자기-색 발행부채**를 못 본다 —
            # 발행자가 자기-IOU를 전량 넘긴 뒤 EXIT하면 그 색 노트가 영구 상환-불능
            # (「앵커 무효」)이 되는데 노트는 계속 유통(자유은행 「깨진 은행권」·무음 방기).
            # 색은 서비스층 개념이라 방어도 서비스층 몫 — 유통 색부채가 남으면 EXIT 거부.
            out = self.outstanding(env.get("p"))
            if out > 0:
                raise Fl21Error(
                    f"EXIT: 유통 중인 자기-색 발행부채 {out}(먼저 상환/소각·회수 — "
                    "유통 노트의 상환-불능 방기 방지)")
        if typ == "BLOCK":
            # ★[M-190] CRITICAL — BLOCK 은 **/block 전용**이다: `block()`이 다리마다
            # `_guard_env`+BLOCK_LEG_TYPES+scope 를 강제한다. `/submit`(→submit→여기)로
            # BLOCK 봉투를 넣으면 이 함수가 최상위 typ 만 봐서 **다리가 무가드**로 커널행
            # ⟹ 색-라우팅·EXIT-부채·scope 우회(무고한 앵커를 미이행-사건 피고로 만들기 ·
            # 냉독 최대판 재현). 정상 내부 BLOCK 은 `_ksubmit` 직행이라 여기 안 온다.
            raise Fl21Error("BLOCK 은 /block 전용(원자 다리별 가드 경유 — /submit 불가)")
        if typ in ("OPEN", "CLOSE", "EXT_IN_POOL"):
            raise Fl21Error(f"{typ}: r1 표면 밖(색-추적 불가 연산)")

    @staticmethod
    def _fsync(fh):
        fh.flush()
        os.fsync(fh.fileno())

    def _persist_new(self):
        # ★H5 — 잡 메타를 대장보다 **먼저** 내구화(재배열): 창 안 크래시가 「이행-불가
        # 유령 청구」(대장엔 REDEEM·jobs엔 스펙 없음 → 강제 사고)를 남기던 순서를 뒤집어,
        # 실패 모드를 「고아 잡 메타(무해·GC)」로 바꾼다.
        tmp = self.jobs_p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as jf:
            json.dump(self.jobs, jf, ensure_ascii=False)
            self._fsync(jf)
        os.replace(tmp, self.jobs_p)
        # ★H5 — 대장·공동서명 append 후 fsync(ack = 내구 보장 · 정전에도 정산 불멸)
        with open(self.ledger_p, "a", encoding="utf-8") as fh, \
             open(self.cosig_p, "a", encoding="utf-8") as ch:
            for e in self.w.log[self.persisted:]:
                fh.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")
                sigs = {c: k.sign(FL21_DOMAIN + bytes.fromhex(e["head"])).hex()
                        for c, k in self.cos_keys.items()}
                ch.write(json.dumps({"seq": e["seq"], "head": e["head"],
                                     "sigs": sigs}, sort_keys=True) + "\n")
                self.cosig_map[e["seq"]] = {"seq": e["seq"], "head": e["head"],
                                            "sigs": dict(sigs)}   # ★N-3
            self._fsync(fh)
            self._fsync(ch)
        self.persisted = len(self.w.log)

    # ── 잡 상태 갱신(정산 관측 — 커널 로그가 정본) ──
    def _sync_jobs(self):
        for ref, j in self.jobs.items():
            c = self.w.uw_open.get(ref)
            if c:                       # ★커버 이력 보존(맥락-0 C-2 — 정산 후에도 감사 가능)
                j["cover"] = {"uw": c["uw"], "prem": c["prem"]}
            if j["state"] != "open":
                continue
            if ref not in self.w.redeem_pending:
                if j.get("delivered"):
                    j["state"] = "delivered"
                else:
                    j["state"] = "settled_or_returned"   # 시한-사고 경로(커널 정산)
        # 표시: 미결이며 기한 지난 잡(사고 예정 — 정보용)
        for j in self.jobs.values():
            if j["state"] == "open" and self.w.epoch > j["deadline"]:
                j["late"] = True

    # ── API 동작(전부 락 안) ──
    def meta(self):
        return {"label": LABEL, "domain": "FL22-v0.1",
                "log_id": self.w.log_id.hex(), "fp0": self.w.fp0,
                "operator_pk": self.w.reg.pk("operator").hex(),
                # ★[M-115] 창세 좌석 공개키(JOIN 없이 창세된 좌석의 봉투-서명 검증 원료
                # — 냉독 결함 2 봉합 · H7 시드-독립 리플레이의 대역-내 서빙)
                "genesis_pks": {a: self.w.reg.pk(a).hex() for a in GENESIS},
                "cosigners": dict(self.cosign_pubs),   # ★D-2 — 공개키 전량(분리 후에도)
                "cosign_k": COSIGN_K,
                "gen": dict(self.w.GEN), "genesis": list(GENESIS),
                "model": "free-banking-v0",   # ★[M-103] — 색·자기-발행·발행자-상환
                "join_issue": self.join_issue, "bootstrap_cap": self.boot_cap,
                "unit_scale": self.unit_scale,   # ★[M-127] 1 AU = 이만큼 기본단위
                "bridge_ref": self.w.bridge_ref,  # ★H7 — 공개-리플레이 재료(세대 계보)
                "job_kinds": list(JOBS.KINDS)}

    def state(self):
        return {"epoch": self.w.epoch, "seq": len(self.w.log),
                "head": self.w.log[-1]["head"] if self.w.log else "genesis",
                "F": self.w.F, "F_uw": self.w.F_uw, "F_peak": self.w.F_peak,
                "S": self.w.S,
                "ext_in": self.w.ext_in, "ext_out": self.w.ext_out,
                "principals": self.w.reg.size()}

    # ── ★P-5 /stats — 감시 지표·요율 원료(★D-13 증분 캐시 · 대칭-시차 · 버전-경계) ──
    def stats(self):
        key = (len(self.w.log), self.w.epoch)
        if self._stats_cache and self._stats_cache[0] == key:
            return self._stats_cache[1]
        out = self._stats_scan()
        self._stats_cache = (key, out)
        return out

    def _stats_scan(self):
        T = self.w.GEN["redeem_T"]
        now = self.w.epoch
        ver = {}                      # anchor → 현재 버전(P-10 — TICKMARK 선언)
        seg = {}                      # (anchor, ver) → {del, fail, mat}
        cov_open, cov_hist = len(self.w.uw_open), 0
        loss = {"anchor": 0, "cov": 0, "uw": 0, "fund": 0, "short": 0}
        uw_book = {}                  # ★RU-4 — 인수자별 실적{covered, prem, paid}
        ref_uw = {}                   # ref → uw(로그의 UW 봉투에서 재구성)
        tx_n = 0                      # ★RE-3 — 밀도(비-운영 발화 수)
        tape = {}                     # ★R2-a — kind별 최근 체결(원장-파생 = 위조-불가)
        chal = {}                     # ★P-11 — anchor별 확인-불일치 챌린지(원장-파생)

        def _seg(a):
            k = (a, ver.get(a, "v0"))
            return seg.setdefault(k, {"delivered": 0, "failed": 0, "mature": 0})

        vdecl = {}                    # ★[M-170] F-4 — 앵커별 version 선언 에포크들
        dvol = {}                     # ★[M-165] C-1 — 앵커별 이행-부피(액면 합):
                                      #   기계-경제 신뢰-상한(λ×이행-부피)의 원료
        dlast = {}                    # 앵커별 마지막 이행 에포크(색-실질 신호)

        def _deliver(a, ref, e):
            j = self.jobs.get(ref)
            t0 = j["t0"] if j and "t0" in j else None
            if j:
                dvol[a] = dvol.get(a, 0) + j["exposure"]
                dlast[a] = max(dlast.get(a, 0), e["w_epoch"])
            s = _seg(a)
            s["delivered"] += 1
            # ★대칭-시차 계수([M-94] — 성숙 가시 = t0+T 통일 · t0 미상은 즉시)
            if t0 is None or now >= t0 + T:
                s["mature"] += 1
            if j:                     # ★테이프(잡-경로 한정 — face·kind가 있는 체결)
                lst = tape.setdefault(j["job"]["kind"], [])
                lst.append({"seq": e["seq"], "epoch": e["w_epoch"],
                            "face": j["exposure"], "anchor": a})
                del lst[:-32]         # kind당 최근 32건

        for e in self.w.log:
            env = e["env"]
            legs = (env["args"]["legs"] if env["typ"] == "BLOCK"
                    else [env])
            for lg in legs:
                if lg.get("p") != "operator":
                    tx_n += 1                       # ★RE-3 밀도 — 참여자 발화
                if lg["typ"] == "DELIVER":
                    _deliver(lg["args"]["anchor"], lg["args"]["ref"], e)
                elif lg["typ"] == "UW":             # ★RU-4 — 인수자 북 재구성
                    u_ = lg["args"]["uw"]
                    ref_uw[lg["args"]["ref"]] = u_
                    b = uw_book.setdefault(u_, {"covered": 0, "prem": 0,
                                                "paid": 0})
                    b["covered"] += 1
                    b["prem"] += lg["args"].get("prem", 0)
                elif lg["typ"] == "TICKMARK" and \
                        isinstance(lg.get("args"), dict) and \
                        lg["args"].get("kind") == "fl21.version":
                    ver[lg["p"]] = str(lg["args"].get("v", "?"))[:32]
                    vdecl.setdefault(lg["p"], []).append(e["w_epoch"])
                elif lg["typ"] == "TICKMARK" and \
                        isinstance(lg.get("args"), dict) and \
                        lg["args"].get("kind") == "fl21.challenge":
                    chal[lg["args"].get("anchor", "?")] = \
                        chal.get(lg["args"].get("anchor", "?"), 0) + 1
            if env["typ"] == "TICK" and "_force" in e:
                fo = e["_force"]
                for r in fo.get("settled", []):
                    j = self.jobs.get(r["ref"])
                    for k in loss:
                        loss[k] += r.get(k, 0)
                    cov_hist += 1
                    u_ = ref_uw.get(r["ref"])
                    if u_:                          # ★RU-4 — 인수자 지급(담보+소구)
                        uw_book[u_]["paid"] += r.get("cov", 0) + r.get("uw", 0)
                    if j:
                        s = _seg(j["anchor"])
                        s["failed"] += 1
                        s["mature"] += 1
                for ref in fo.get("returned", []):
                    j = self.jobs.get(ref)
                    if j:
                        s = _seg(j["anchor"])
                        s["failed"] += 1
                        s["mature"] += 1
        anchors = {}
        for (a, v), s in seg.items():
            p_hat = (s["failed"] + 1) / (s["mature"] + 2)
            anchors.setdefault(a, {"version": ver.get(a, "v0"),
                                   "segments": {}})
            anchors[a]["segments"][v] = {**s, "p_hat": round(p_hat, 4)}
        for a, n in chal.items():                   # ★P-11 — 확인-불일치 공개 실적
            anchors.setdefault(a, {"version": ver.get(a, "v0"),
                                   "segments": {}})["challenged"] = n
        for a, v in dvol.items():                   # ★[M-165] C-1 — 신뢰-상한 원료
            anchors.setdefault(a, {"version": ver.get(a, "v0"),
                                   "segments": {}})["delivered_volume"] = v
        # ★F-4([M-170]) — 버전-주기(기간-프리미엄의 기계-원인 원료): 선언 간격 중앙값
        import statistics as _st
        for a, eps in vdecl.items():
            if len(eps) >= 2:
                gaps = [b - c for b, c in zip(eps[1:], eps[:-1])]
                anchors.setdefault(a, {"version": ver.get(a, "v0"),
                                       "segments": {}})["version_period"] = \
                    int(_st.median(gaps))
        # ★F-11([M-170]) — 발행자-측 동시-만기 계기(LLR 재심의 대칭-공백 봉합):
        # 그 앵커를 향한 열린 청구(부보 여부 무관 — 전부 그의 이행-용량 수요)의
        # 단일-성숙-틱 노출 합 최대. 인수자 maturity_peak의 발행자판.
        imat = {}
        for _r, rp in self.w.redeem_pending.items():
            if rp.get("T"):
                dl = rp["t0"] + rp["T"]
                aa = rp["anchor"]
                fc = self.w.notes[rp["nid"]]["face"]
                imat.setdefault(aa, {})
                imat[aa][dl] = imat[aa].get(dl, 0) + fc
        for a, mb in imat.items():
            anchors.setdefault(a, {"version": ver.get(a, "v0"),
                                   "segments": {}})["issuer_maturity_peak"] = \
                max(mb.values())
        prem_in = sum(c["prem"] for c in self.w.uw_open.values())
        # ★UW-1([M-113]·[M-126] 집행): prem은 인수자 자기-선언(커널 자기적립 —
        # 홀더→인수자 실지급에 비결박)이라 손해율의 분모로 신뢰 불가 ⟹ 정직 강등:
        # loss_ratio → loss_ratio_selfdecl(한정어) · 검증-분모판은 face-사map 필요(등재)
        pvsum = {}                    # ★U-C — 원자-체결 결박-보험료(잡-기록 파생)
        for ref2, j2 in self.jobs.items():
            u2 = (j2.get("cover") or {}).get("uw") or ref_uw.get(ref2)
            f2 = j2.get("prem_verified")
            if u2 and f2:
                pvsum[u2] = pvsum.get(u2, 0) + f2
        for u_, b in uw_book.items():
            b["loss_ratio_selfdecl"] = round(b["paid"] / b["prem"], 3) \
                if b["prem"] else None
            if pvsum.get(u_):
                b["prem_verified"] = pvsum[u_]        # 위조-불가 분모
                b["loss_ratio_verified"] = round(b["paid"] / pvsum[u_], 3)
        # ★U-1([M-157] · [ADR-388] 계보) — 동시-성숙 집중 계기: 폭포 층 ④·⑤를 여는
        # 실측 다이얼은 자본이 아니라 「같은 틱에 함께 성숙하는 노출」이다. 인수자별
        # ⓐopen_covers = 열린 커버 수 ⓑmaturity_peak = 단일 성숙-틱 노출 합의 최대
        # (소구-층은 자유 잔고를 그 틱의 동시-성숙분이 나눠 쓴다 — 원장-파생·위조-불가).
        mat_buckets = {}                             # uw → {deadline: Σexposure}
        for ref, o in self.w.uw_open.items():
            rp = self.w.redeem_pending.get(ref)
            if not rp:
                continue
            u_ = o["uw"]
            b = uw_book.setdefault(u_, {"covered": 0, "prem": 0, "paid": 0,
                                        "loss_ratio_selfdecl": None})
            b["open_covers"] = b.get("open_covers", 0) + 1
            dl = (rp["t0"] + rp["T"]) if rp.get("T") else None
            if dl is not None:
                face = self.w.notes[rp["nid"]]["face"]
                mb = mat_buckets.setdefault(u_, {})
                mb[dl] = mb.get(dl, 0) + face
        for u_, b in uw_book.items():
            b.setdefault("open_covers", 0)
            b["maturity_peak"] = max(mat_buckets.get(u_, {}).values(),
                                     default=0)
        colors_supply = {}                           # ★[M-103] 발행자별 미결 부채(집적 관측)
        for nid, n in self.w.notes.items():
            c = self.colors.get(nid, "?")
            colors_supply[c] = colors_supply.get(c, 0) + n["face"]
        # ★[M-165] C-3 — 색-실질 계기(기계-화폐 고유): 노트의 실질 = 발행자의
        # 상환-가능성이다. 배상 노트가 불이행-앵커 색으로 발행되는 설계(위험 꼬리표)에서
        # 「부재한 색」을 들고 있는 피해자·매수자가 즉시 볼 수 있어야 정직하다.
        color_health = {}
        STALE_N = 10_080                             # ★F-9a — 1주(60s 틱) 무-접촉
        for c0, sup in colors_supply.items():
            stale = sum(n["face"] for nid, n in self.w.notes.items()
                        if self.colors.get(nid) == c0
                        and now - self.note_touch.get(nid, now) >= STALE_N)
            color_health[c0] = {
                "supply": sup,
                "issuer_exited": c0 in self.w.exited,
                "issuer_balance": self.w.bal(c0) if isinstance(c0, str) else 0,
                "last_delivery_epoch": dlast.get(c0),
                # ★F-9a([M-170]) — 죽은-노트 계기: 장기 무-접촉 유통 비율(에이전트
                # 소멸성 × 회전-한도 전량-계수 ⟹ 질식 위험의 측정 — FL2.3 §7 원료)
                "stale_share": round(stale / sup, 4) if sup else 0.0}
        # ★N-17([M-125] 등재 · [M-154] 실장) — 모델-가계 집중(파생-가시 · 상관 요율 원료).
        # 관례: declare_version("가계/버전") — '/' 앞이 가계. ⚠️herfindahl_lb 는 **하한**:
        # 미선언 발행자는 각자 별개 가계로 계수한다(미상끼리 같은 가계면 실제 집중은 더
        # 높다) — undeclared_share 가 그 불확실성의 크기를 함께 보인다(정직 표기).
        fam_mass, undecl = {}, 0
        for c, face in colors_supply.items():
            v = ver.get(c, "")
            if "/" in v:
                fam = v.split("/", 1)[0][:16]
            else:
                fam, undecl = "~" + str(c)[:15], undecl + face
            fam_mass[fam] = fam_mass.get(fam, 0) + face
        _ft = sum(fam_mass.values())
        family = {"herfindahl_lb": (round(sum((m / _ft) ** 2
                                              for m in fam_mass.values()), 4)
                                    if _ft else None),
                  "families": fam_mass,
                  "undeclared_share": round(undecl / _ft, 4) if _ft else None}
        density = {"tx": tx_n,                       # ★RE-3 — 밀도 지표
                   "tx_per_epoch": round(tx_n / now, 3) if now else None,
                   "active_principals": self.w.reg.size() - 1,
                   "au_circulating": sum(n["face"] for n in
                                         self.w.notes.values()
                                         if not n["owner"].startswith("@")),
                   "au_burned_S": self.w.S,
                   "colors": colors_supply}
        return {"epoch": now, "symlag_T": T,
                "underwriters": uw_book,             # ★RU-4
                "family_concentration": family,      # ★N-17 — 상관 계기(하한)
                "color_health": color_health,        # ★[M-165] C-3 — 색-실질(기계-화폐)
                "density": density,
                "tape": tape,                        # ★R2-a — kind별 최근 체결 32
                "scopes": dict(self.scopes),         # ★H5 — 선언된 작업-범위(파생)
                "anchors": anchors,
                "coverage": {"open": cov_open, "settled": cov_hist,
                             "F_uw": self.w.F_uw, "F_peak": self.w.F_peak,
                             "open_prem": prem_in},
                "loss_layers": loss,
                "note": ("★대칭-시차 계수·버전-분절 — 잡-경로 한정"
                         "(원시 REDEEM은 t0 미상 = 즉시 계수) · "
                         "underwriters.prem = 자기-선언(비결박 — UW-1 한정어)")}

    # ── ★P-9 /attest — 실적 증명(전량-아니면-무 · 운영자-서명 · head-결박) ──
    def attest(self, principal):
        st = self.stats()
        a = st["anchors"].get(principal)
        doc = {"principal": principal, "log_id": self.w.log_id.hex(),
               "upto_seq": len(self.w.log),
               "upto_head": self.w.log[-1]["head"] if self.w.log else "genesis",
               "epoch": self.w.epoch, "complete": True,   # ★전량-아니면-무([FR-6])
               "stats": a or {"segments": {}, "version": None}}
        import kernel22 as K
        sig = self.w._keys["operator"].sign(
            FL21_DOMAIN + K._canon(doc)).hex()
        return {"doc": doc, "operator_sig": sig}

    def join(self, principal, pk_hex):
        if not _PNAME.match(principal or ""):
            raise Fl21Error("principal은 [a-z][a-z0-9_-]{1,31}")
        bytes.fromhex(pk_hex)
        self._ksubmit(self.w.sign_env("operator", "JOIN",
                                      {"principal": principal, "pk": pk_hex}))
        if self.join_issue > 0:      # ★[M-103] 자기-IOU 발행(구매력 아님 — 자기-약속 자본)
            self._ksubmit(self.w.sign_env("operator", "EXT_IN",
                                          {"to": principal,
                                           "amount": self.join_issue}))
        self._persist_new()
        return {"joined": principal, "issue": self.join_issue,
                "note": "발행분은 당신의 자기-IOU(색 = 당신) — 타인 노트는 교환·이행으로"}

    def outstanding(self, principal):
        """색 = principal인 유통량(에스크로 포함) = 그 발행자의 미결 이행-부채."""
        return sum(n["face"] for nid, n in self.w.notes.items()
                   if self.colors.get(nid) == principal)

    def issue(self, env):
        """★[M-104] 회전-발행(재점검 F-1): 발행권 = 일회 지급이 아니라 **회전 한도** —
        「내 색 유통량 ≤ 한도」. 이행-소각이 부채를 지우면 그만큼 재발행 가능(공급의
        단조-수축 봉합 — 소각↔발행이 이행 능력에 결박). 요청 = 본인-서명 TICKMARK
        (로그-결박·감사 가능) → 운영자 EXT_IN."""
        if not isinstance(env, dict) or env.get("typ") != "TICKMARK":
            raise Fl21Error("issue: 본인-서명 TICKMARK{kind: fl21.issue, k}")
        args = env.get("args") or {}
        if args.get("kind") != "fl21.issue":
            raise Fl21Error("issue: kind = fl21.issue")
        k = args.get("k")
        if not isinstance(k, int) or isinstance(k, bool) or k < 1:
            raise Fl21Error("issue: k ≥ 1 정수")
        p = env.get("p")
        cap = self.genesis_issue if p in GENESIS else self.join_issue
        out_now = self.outstanding(p)
        if out_now + k > cap:
            raise Fl21Error(f"issue: 회전 한도 초과({out_now}+{k} > {cap} — "
                            "이행-소각이 부채를 지우면 재발행 가능)")
        self.w._verify_env(env)      # ★B1 — 발행 전 사용자 요청 선검증
        self._atomic(lambda: (       # ★B1 — 요청↔발행 원자(부분-커밋 방지)
            self._ksubmit(env),      # 서명 요청을 로그에 결박(커널이 서명·nonce 검증)
            self._ksubmit(self.w.sign_env("operator", "EXT_IN",
                                          {"to": p, "amount": k}))))
        self._persist_new()
        return {"issued": k, "outstanding": self.outstanding(p), "cap": cap}

    def bootstrap(self, leg):
        """★[M-103] 상호 신용 교환(WIR형 — [FREEBANK_ANALOGY §1]): 신규자 자기-IOU
        노트(XFER 다리) ↔ 같은 액면의 anchor0-IOU 신규 발행을 원자 스왑. anchor0는
        신규자-IOU(그의 미래-이행 청구)를 자산으로 받는다 — 일방 보조금이 아니다.
        한도 = BOOT_CAP/주체(로그-파생 계수)."""
        if not isinstance(leg, dict) or leg.get("typ") != "XFER":
            raise Fl21Error("bootstrap: XFER 다리 하나(내 자기-IOU → anchor0)")
        a = leg.get("args") or {}
        p = leg.get("p")
        nid = str(a.get("note"))
        if a.get("to") != GENESIS[0] or a.get("frm") != p:
            raise Fl21Error("bootstrap: 다리는 본인→anchor0 XFER")
        if self.colors.get(nid) != p:
            raise Fl21Error("bootstrap: 자기-색 노트만(자기-IOU 교환)")
        face = self.w.notes.get(nid, {}).get("face", 0)
        used = self.bootstrap_used.get(p, 0)
        if face <= 0 or used + face > self.boot_cap:
            raise Fl21Error(f"bootstrap: 한도 초과({used}+{face} > {self.boot_cap})")
        self.w._verify_env(leg)      # ★B1 — 발행 전에 사용자 다리 선검증(서명·nonce·창)

        def _do():
            self._ksubmit(self.w.sign_env("operator", "EXT_IN",
                                          {"to": GENESIS[0], "amount": face}))
            new_nid = str(self.w.note_ctr - 1)
            back = self.w.sign_env(GENESIS[0], "XFER",
                                   {"frm": GENESIS[0], "to": p, "note": new_nid})
            entry = self._ksubmit(self.w.sign_env("operator", "BLOCK",
                                                  {"legs": [leg, back]}))
            return entry, new_nid
        entry, new_nid = self._atomic(_do)   # ★B1 — EXT_IN↔BLOCK 원자(고아 발행 방지)
        self._persist_new()
        return {"seq": entry["seq"], "head": entry["head"], "granted": face,
                "note_nid": new_nid, "used": self.bootstrap_used.get(p, 0),
                "cap": self.boot_cap}

    def submit(self, env):
        self._guard_env(env)         # ★RD-7 + 색-라우팅([M-103])
        if (env or {}).get("typ") == "REDEEM":        # ★H5 — 원시 상환 범위 검사
            a = env.get("args") or {}
            note = self.w.notes.get(str(a.get("note"))) or {}
            self._scope_check(a.get("anchor"), "raw", note.get("face", 0),
                              T=a.get("T"))
        entry = self._ksubmit(env)
        self._sync_jobs()            # 원시 UW/REDEEM_CANCEL도 잡 이력에 반영
        self._persist_new()
        return {"seq": entry["seq"], "head": entry["head"]}

    def submit_job(self, env, job):
        spec = JOBS.validate_spec(job)
        if env.get("typ") != "REDEEM":
            raise Fl21Error("job은 REDEEM 봉투에만 붙는다")
        want = (env.get("args") or {}).get("spec_sha256")
        if want is not None:             # ★H2([M-121]) — 명세를 서명 head에 결박
            got = hashlib.sha256(_canon(spec)).hexdigest()
            if want != got:
                raise Fl21Error("H2: spec_sha256 불일치 — 명세 결박 위반"
                                "(서명한 명세 ≠ 제출 명세)")
        nid = str((env.get("args") or {}).get("note"))
        note = self.w.notes.get(nid)
        if note is None:
            raise Fl21Error("미지 노트")
        floor = JOBS.price(spec) * self.unit_scale   # ★P-2 × 단위-정책([M-127])
        if note["face"] < floor:
            raise Fl21Error(f"가격 결박: 액면 {note['face']} < 최소 {floor}"
                            f"(1 AU = {JOBS.N_PER_AU} 작업량 · 1 AU = "
                            f"{self.unit_scale} 단위)")
        self._scope_check((env.get("args") or {}).get("anchor"),
                          spec["kind"], note["face"],
                          T=(env.get("args") or {}).get("T"))   # ★H5 범위 결박
        self._guard_env(env)         # ★색-일치 라우팅([M-103] — 발행자에게만 상환)
        before = set(self.w.redeem_pending)
        entry = self._ksubmit(env)
        ref = next(iter(set(self.w.redeem_pending) - before))
        rp = self.w.redeem_pending[ref]
        self.jobs[ref] = {"job": spec, "anchor": rp["anchor"],
                          "holder": rp["holder"], "t0": rp["t0"],
                          "exposure": note["face"],
                          # ★FL2.2 J-1 — 청구별 시한(커널 rp["T"]가 정본)
                          "deadline": rp["t0"] + (rp.get("T")
                                                  or self.w.GEN["redeem_T"]),
                          "state": "open"}
        self._persist_new()
        return {"seq": entry["seq"], "head": entry["head"], "ref": ref,
                "deadline_epoch": self.jobs[ref]["deadline"]}

    # ── ★B2 이행 3단(검증은 락 밖 — 서브프로세스가 노드를 얼리지 않게) ──
    def deliver_lookup(self, env):
        """락 안(짧게): ★[M-189] C-2 — **ocommit 전에 봉투를 인증**한다. 옛 경로는
        sampled 커밋-표본이 `ocommit_and_derive`로 원장을 **먼저** 박고 봉투 서명은
        `deliver_commit`(3단)에서야 봤다 ⟹ 위조·미서명 `/deliver`가 거부(400)되면서도
        영구 기입을 강제(냉독 2차). 여기서 커널 DELIVER 법과 **동일한 인가**를 미리 문다:
        ⓐ봉투 서명·nonce·창(`_verify_env`) ⓑ행위자 = 앵커(kernel §DELIVER: `p == anchor`).
        표본-유도 순서는 그대로 두되(커밋-head 결박 유지) 미인증분이 ocommit 에 못 닿게 한다."""
        ref = (env.get("args") or {}).get("ref")
        j = self.jobs.get(ref)
        if j is None:
            raise Fl21Error("미지 작업 ref")
        if j.get("delivered"):
            raise Fl21Error("이미 이행된 청구")
        # ★[M-191] CRITICAL — env.typ 강제(냉독 라운드2): /deliver 는 _guard_env 를
        # 안 타는 유일한 사용자-봉투 → _ksubmit 경로다. typ 을 안 보면 REDEEM/BLOCK/EXIT
        # 를 밀어 색-라우팅·EXIT-부채 가드를 우회(무고한 앵커를 미이행-피고로). deliver 는
        # 오직 DELIVER 봉투만 — 다른 typ 은 /submit(가드) 또는 /block(다리별 가드)로.
        if env.get("typ") != "DELIVER":
            raise Fl21Error("DELIVER: /deliver 는 DELIVER 봉투 전용"
                            "(다른 연산은 /submit·/block — 가드 경유)")
        self.w._verify_env(env)       # ⓐ 서명/nonce/창 — 미서명·위조 거부(부작용 없음)
        rp = self.w.redeem_pending.get(ref)   # ⓑ 커널 권위원본으로 이행자 = 앵커 확인
        if rp is None or env.get("p") != rp.get("anchor"):
            raise Fl21Error("DELIVER: 행위자 = 앵커(ocommit 전 인가)")
        return dict(j["job"])         # 스펙 스냅샷(검증 중 공유 상태 무접촉)

    # ── ★[M-164] V-B 커밋-표본 — 표본-무작위성을 원장-유도로(천장-깊이) ──
    # 문제(직접 정독으로 확정): 표본을 검증 직전 SystemRandom으로 뽑으면 실패한 시도가
    # **무-흔적**이라, 악의 운영자+앵커는 통과할 때까지 재추첨해 탈출률을 부양할 수
    # 있고 H7 재실행자는 「그 표본이 그 표본이었는지」를 재검증할 수 없다.
    # 해법: 검증 전에 TICKMARK fl21.ocommit{ref, output_sha256}을 **원장에 먼저 박고**,
    # 표본 = PRF(그 항의 head ‖ ref ‖ i) — ⓐ앵커는 커밋 전에 인덱스를 모른다(산출-
    # 그라인딩 차단: head는 커밋이 랜딩해야 정해진다) ⓑ재시도는 ocommit이 **하나 더
    # 쌓인다**(재추첨 = 공개 계수 · /job의 ocommits) ⓒH7 재실행자가 같은 인덱스를
    # 재유도해 같은 구간을 재검증할 수 있다(무작위성 자체의 공개-리플레이화).
    def ocommit_and_derive(self, env, output):
        """락 안: 산출-커밋 랜딩 → 커밋-head에서 표본 인덱스 유도. (want, idxs) 반환."""
        ref = (env.get("args") or {}).get("ref")
        j = self.jobs.get(ref)
        spec = j["job"]
        if self.ocommits.get(ref, 0) >= OCOMMIT_CAP:   # ★[M-190] 재생-증폭 유계화
            raise Fl21Error(f"ocommit 상한 {OCOMMIT_CAP} 초과 — 재추첨 한도"
                            "(정상 이행 1회 · 반복 실패는 산출-그라인딩)")
        osha = hashlib.sha256(_canon(output)).hexdigest()
        tm = self.w.sign_env("operator", "TICKMARK",
                             {"kind": "fl21.ocommit", "ref": ref,
                              "output_sha256": osha})
        entry = self._ksubmit(tm)
        self.ocommits[ref] = self.ocommits.get(ref, 0) + 1
        want = -(-spec["n"] // JOBS.CKPT)
        k_eff = min(spec.get("k", JOBS.SAMPLE_K), want)
        seed = bytes.fromhex(entry["head"]) + ref.encode()
        idxs, ctr = [], 0
        while len(idxs) < k_eff:
            v = int.from_bytes(hashlib.sha256(
                seed + ctr.to_bytes(4, "big")).digest(), "big") % want
            ctr += 1
            if v not in idxs:
                idxs.append(v)
        return sorted(idxs), entry["seq"]

    def deliver_commit(self, env, output, detail):
        """락 안(짧게): 잡 재확인 후 커널 DELIVER(시한·판정 내구성은 법이 강제)."""
        ref = (env.get("args") or {}).get("ref")
        j = self.jobs.get(ref)
        if j is None:
            raise Fl21Error("미지 작업 ref")
        if j.get("delivered"):
            raise Fl21Error("이미 이행된 청구")
        want = (env.get("args") or {}).get("output_sha256")
        if want is not None:             # ★H2([M-121]) — 산출을 서명 head에 결박
            got = hashlib.sha256(_canon(output)).hexdigest()
            if want != got:
                raise Fl21Error("H2: output_sha256 불일치 — 산출 결박 위반"
                                "(서명한 산출 ≠ 전달 산출)")
        if env.get("typ") != "DELIVER":       # ★[M-191] 벨트(deliver_lookup 이 이미 막지만)
            raise Fl21Error("DELIVER: typ 불일치")
        entry = self._ksubmit(env)    # ref/anchor/failed 재검증은 커널이 강제
        j["delivered"] = True
        j["output"] = output
        j["verify"] = detail
        self._sync_jobs()
        self._persist_new()
        return {"seq": entry["seq"], "head": entry["head"], "ref": ref,
                "verify": detail}

    def block(self, legs):
        """★원자 다자-거래(커널 BLOCK — all-or-nothing): 각 다리는 당사자-서명 봉투,
        제출은 운영자 좌석(제출자 ≠ 다리 서명자 — 커널 규칙). 보험료↔커버의 원자 교환 등."""
        if not isinstance(legs, list) or not (1 <= len(legs) <= 8):
            raise Fl21Error("legs는 1~8개")
        for lg in legs:              # ★색-추적 가능 다리만 + 다리별 정책([M-103]·RD-7)
            if not isinstance(lg, dict) or lg.get("typ") not in BLOCK_LEG_TYPES:
                raise Fl21Error(f"BLOCK 다리 타입은 {BLOCK_LEG_TYPES} 한정")
            self._guard_env(lg)
            if lg.get("typ") == "REDEEM":             # ★H5 — 블록 내 원시 상환도
                a = lg.get("args") or {}
                note = self.w.notes.get(str(a.get("note"))) or {}
                self._scope_check(a.get("anchor"), "raw", note.get("face", 0),
                                  T=a.get("T"))
        # ★[M-164] U-C 결박-보험료: 같은 블록의 UW(ref)+XFER(→uw) 쌍에서 보험료
        # 액면을 **커밋 전 라이브 원장**에서 포획(UW-1 자기-선언 한정어의 해소 —
        # 이 값은 노트 실물에서 읽은 것이라 위조-불가·H7 재유도 가능).
        pv = []
        uw_count = {}
        for lg in legs:
            if lg.get("typ") == "UW":
                u0 = (lg.get("args") or {}).get("uw")
                uw_count[u0] = uw_count.get(u0, 0) + 1
        for lg in legs:
            if lg.get("typ") == "UW":
                a = lg.get("args") or {}
                uwp, ref = a.get("uw"), a.get("ref")
                if uw_count.get(uwp, 0) != 1:
                    continue          # ★[M-165] R4-3 — 다중-UW 블록은 귀속 모호:
                                      #   보수적으로 포획 생략(과대-계상 금지)
                fee = sum((self.w.notes.get(str((x.get("args") or {})
                                                .get("note")), {})
                           .get("face", 0))
                          for x in legs
                          if x.get("typ") == "XFER"
                          and (x.get("args") or {}).get("to") == uwp)
                if fee > 0 and ref in self.jobs:
                    pv.append((ref, fee))
        entry = self._ksubmit(self.w.sign_env("operator", "BLOCK",
                                              {"legs": legs}))
        for ref, fee in pv:
            self.jobs[ref]["prem_verified"] = fee
        self._sync_jobs()
        self._persist_new()
        return {"seq": entry["seq"], "head": entry["head"]}

    def tick(self):
        ent = self._ksubmit(self.w.sign_env("operator", "TICK", {}))
        self._sync_jobs()
        self._persist_new()
        return {"epoch": self.w.epoch, "settle": ent.get("_force")}

    def cosig_add(self, body):
        """★D-2([M-105]) — 원격 서명자 데몬의 공동-서명 수신(검증-후 append)."""
        if not isinstance(body, dict):
            raise Fl21Error("cosig: 객체")
        name, seq = body.get("name"), body.get("seq")
        head, sig = body.get("head"), body.get("sig")
        pk = self.cosign_pubs.get(name)
        if pk is None:
            raise Fl21Error("cosig: 미지 서명자")
        if not isinstance(seq, int) or not (0 <= seq < len(self.w.log)):
            raise Fl21Error("cosig: seq 범위 밖")
        if self.w.log[seq]["head"] != head:
            raise Fl21Error("cosig: head 불일치")
        if (seq, name) in self._cosig_seen:      # ★재생 중복-제거(완결성 med — 무한증가 DoS)
            return {"ok": True, "seq": seq, "signer": name, "dup": True}
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk)).verify(
                bytes.fromhex(sig), FL21_DOMAIN + bytes.fromhex(head))
        except Exception:
            raise Fl21Error("cosig: 서명 무효")
        with open(self.cosig_p, "a", encoding="utf-8") as ch:
            ch.write(json.dumps({"seq": seq, "head": head,
                                 "sigs": {name: sig}}, sort_keys=True) + "\n")
            self._fsync(ch)
        self._cosig_seen.add((seq, name))
        cm = self.cosig_map.setdefault(seq, {"seq": seq, "head": head,
                                             "sigs": {}})   # ★N-3
        if cm["head"] == head:
            cm["sigs"].setdefault(name, sig)
        return {"ok": True, "seq": seq, "signer": name}

    def audit(self):
        # ★F-B([M-143]) — /audit 캐시: audit()은 전-원장 리플레이 O(원장)인데 공개
        # GET·락 안이라, 원장이 크면 익명 반복 호출이 노드를 세운다(RISK-1 동류).
        # 같은 로그 길이 = 결정론 동일 결과 ⟹ 길이-키 캐시(신규 기입만 재계산).
        key = len(self.w.log)
        if self._audit_cache and self._audit_cache[0] == key:
            return self._audit_cache[1]
        a = self.w.audit()
        ok = a["ok"] and set(self.colors) == set(self.w.notes)   # ★색 전체성
        out = {"ok": ok, "entries": a.get("entries")}
        self._audit_cache = (key, out)
        return out

    # ── ★호가 창(R2-a — [M-116] 발견층 · [시장-미시구조 §6]) ──
    # 게시 = 오프-원장 서명 공표(ASK = 매도 호가 · WANT = 매수 호가) — seq 무접촉.
    # ⚠️자문층이다: 게시는 에스크로가 아니고 아무것도 구속하지 않는다 — 구속·정산은
    # 온-원장 경로(REDEEM·BLOCK)만. 스팸 = 등록-주체 한정(join 예산에 결박) + 주체당
    # 상한 + TTL(예치금 파라미터는 R2 등재).
    def _offledger_verify(self, domain, body, sig, tag):
        """오프-원장 서명 요청 공통 검증(board·challenge — 도메인 분리 + log_id 결박)."""
        p = (body or {}).get("p")
        pk = self.w.reg.pk(p) if isinstance(p, str) else None
        if pk is None:
            raise Fl21Error(f"{tag}: 미등록 주체(먼저 /join)")
        try:
            Ed25519PublicKey.from_public_bytes(pk).verify(
                bytes.fromhex(sig), domain + self.w.log_id + _canon(body))
        except Exception:
            raise Fl21Error(f"{tag}: 서명 무효(도메인 + log_id + canon)")

    def _board_verify(self, body, sig):
        self._offledger_verify(BOARD_DOMAIN, body, sig, "board")

    # ── ★[M-162] leg-릴레이 — 서명 사서함(대역-외 leg 교환의 자기-서비스화) ──
    # 원자-체결(RU-2)의 마지막 마디: 매수자·인수자가 서명-leg를 노드 경유로 주고받는다.
    # 순수 저장-전달(내용 무해석·무구속) · 수신자-서명 fetch = 읽고-지움(단일 소비자) ·
    # ⚠️leg 봉투는 nonce-1회용이라 중계자·노드가 가로채도 「같은 체결」만 성립한다
    # (탈취 이득 0 — RU-2 원자성의 부수 성질 · 그래서 릴레이에 신뢰가 안 실린다).
    RELAY_TTL = 240                   # 에포크(60s 틱 = 4시간) — 짧게(만료 = 무해)
    RELAY_CAP = 32                    # 수신자당 미소비 상한(폭주 방어)
    RELAY_SENDER_CAP = 4              # ★R-2([M-163]) 발신자→수신함당 상한(표적-스팸 방어)
    RELAY_FRESH = 8                   # ★R-1([M-163]) 서명-본문 epoch 신선도 창
    RELAY_MAX_B = 8192                # blob 상한(leg 2~3개 + 여유)

    def relay_send(self, body, sig):
        if not isinstance(body, dict) or not isinstance(sig, str):
            raise Fl21Error("relay: {msg: 서명-본문, sig: hex}")
        self._offledger_verify(RELAY_DOMAIN, body, sig, "relay")
        to = body.get("to")
        blob = body.get("blob")
        now = self.w.epoch
        # ★R-1 — 재전송 차단: 서명-본문에 epoch 필수(신선도 창) + 창-내 중복 지문 거부
        #   (관찰자가 같은 서명-msg를 재-POST해 수신함을 재충전하는 경로 봉쇄 · leg 자체는
        #    nonce-1회용이라 정산 중복은 원래 불가 — 이것은 스팸-재충전 방어다)
        be = body.get("epoch")
        if not (isinstance(be, int) and abs(now - be) <= self.RELAY_FRESH):
            raise Fl21Error(f"relay: epoch 신선도(±{self.RELAY_FRESH}) 필수")
        fp = hashlib.sha256(_canon(body)).hexdigest()[:24]
        self.relay_seen = {h: e for h, e in getattr(self, "relay_seen", {})
                           .items() if e > now - self.RELAY_FRESH * 2}
        if fp in self.relay_seen:
            raise Fl21Error("relay: 중복 송신(재전송 차단)")
        if not (isinstance(to, str) and self.w.reg.pk(to) is not None):
            raise Fl21Error("relay: 수신자 미등록")
        if not (isinstance(blob, str) and len(blob) <= self.RELAY_MAX_B):
            raise Fl21Error(f"relay: blob ≤ {self.RELAY_MAX_B}자")
        box = self.relay.setdefault(to, [])
        box[:] = [m for m in box if m["expires"] > now]
        if len(box) >= self.RELAY_CAP:
            raise Fl21Error("relay: 수신함 가득(미소비 상한)")
        frm = body["p"]
        if sum(1 for m in box if m["frm"] == frm) >= self.RELAY_SENDER_CAP:
            raise Fl21Error(f"relay: 발신자당 미소비 ≤ {self.RELAY_SENDER_CAP}"
                            "(표적-스팸 방어)")
        self.relay_seen[fp] = now
        box.append({"frm": frm, "blob": blob, "epoch": now,
                    "expires": now + self.RELAY_TTL})
        return {"queued": len(box)}

    def relay_fetch(self, body, sig):
        """수신자-서명 fetch — 읽고-지움(사서함 의미론)."""
        if not isinstance(body, dict) or not isinstance(sig, str):
            raise Fl21Error("relay: {msg: 서명-본문, sig: hex}")
        self._offledger_verify(RELAY_DOMAIN, body, sig, "relay")
        if body.get("fetch") is not True:
            raise Fl21Error("relay: fetch 본문 아님")
        me = body["p"]
        now = self.w.epoch
        box = [m for m in self.relay.get(me, []) if m["expires"] > now]
        self.relay[me] = []
        return {"msgs": box, "epoch": now}

    def _board_gc(self):
        now = self.w.epoch
        dead = [i for i, r in self.board.items()
                if r["post"]["expires"] <= now]
        for i in dead:
            del self.board[i]
        return bool(dead)

    def _board_save(self):
        tmp = self.board_p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.board, fh, ensure_ascii=False)
        os.replace(tmp, self.board_p)     # 자문층 — 원자 교체면 충분(fsync는 대장 몫)

    def board_list(self):
        if self._board_gc():
            self._board_save()
        asks = sorted((r for r in self.board.values()
                       if r["post"]["side"] == "ask"),
                      key=lambda r: (r["post"]["price"], r["id"]))
        wants = sorted((r for r in self.board.values()
                        if r["post"]["side"] == "want"),
                       key=lambda r: (-r["post"]["price"], r["id"]))
        return {"epoch": self.w.epoch, "asks": asks, "wants": wants,
                "note": ("게시판 = 자문층(무-에스크로·무-구속) — 구속·정산은 "
                         "온-원장(REDEEM·BLOCK)만 · 체결 이력 = /stats.tape")}

    def board_post(self, body, sig):
        if not isinstance(body, dict) or not isinstance(sig, str):
            raise Fl21Error("board: {post: 서명-본문, sig: hex}")
        self._board_verify(body, sig)
        if "rm" in body:                  # 철회(본인-서명이 소유 증명)
            if set(body) != {"rm", "p"}:
                raise Fl21Error("board: 철회 본문은 {rm, p}만")
            rid = str(body["rm"])
            r = self.board.get(rid)
            if r and r["post"]["p"] != body["p"]:
                raise Fl21Error("board: 본인 게시만 철회 가능")
            self.board.pop(rid, None)
            self._board_save()
            return {"removed": rid}
        keys = {"side", "kind", "title", "detail", "price", "p", "expires"}
        if set(body) != keys:
            raise Fl21Error(f"board: 키는 정확히 {sorted(keys)}")
        if body["side"] not in ("ask", "want"):
            raise Fl21Error("board: side ∈ {ask, want}")
        # ★[M-154] "cover" — 인수 호가(커버-제안)의 발견층 1급 kind(오프-원장 자문층 ·
        # 테이프는 잡-경로 체결만 파생하므로 무영향 · 체결은 원자 /block 이 유일 경로)
        if body["kind"] not in JOBS.KINDS + ("other", "cover", "swap"):
            raise Fl21Error(f"board: kind ∈ {JOBS.KINDS + ('other', 'cover', 'swap')}")
        if not (isinstance(body["title"], str)
                and 1 <= len(body["title"]) <= 80):
            raise Fl21Error("board: title 1~80자")
        if not (isinstance(body["detail"], str) and len(body["detail"]) <= 400):
            raise Fl21Error("board: detail ≤ 400자")
        pr = body["price"]
        if not isinstance(pr, int) or isinstance(pr, bool) or \
                not (1 <= pr <= 10 ** 6):
            raise Fl21Error("board: price 1..10^6 정수 AU"
                            "(ask = 최소가 · want = 최대가)")
        ex, now = body["expires"], self.w.epoch
        if not isinstance(ex, int) or isinstance(ex, bool) or \
                not (now < ex <= now + BOARD_TTL_MAX):
            raise Fl21Error(f"board: expires ∈ (지금, 지금+{BOARD_TTL_MAX}]")
        self._board_gc()
        pid = hashlib.sha256(_canon(body)).hexdigest()[:16]   # 내용-주소(재게시 멱등)
        if pid not in self.board:
            if len(self.board) >= BOARD_MAX:
                raise Fl21Error(f"board: 전역 상한({BOARD_MAX})")
            mine = sum(1 for r in self.board.values()
                       if r["post"]["p"] == body["p"])
            if mine >= BOARD_PER_P:
                raise Fl21Error(f"board: 주체당 활성 {BOARD_PER_P}건"
                                "(철회/만료 후 재게시)")
        self.board[pid] = {"id": pid, "post": body, "sig": sig}
        self._board_save()
        return {"id": pid, "expires": ex}

    # ── ★[M-178] 수락-채널 v0(D-5) — 일치-후-수락의 양측 2차-이력(자문층) ──
    # 검증(일치)과 별개로 매수자가 이행-후 산출에 「수락/재작업」 의견을 서명-공표한다.
    # ⓐ양측이 한 몸: 판매자 taste_residual 과 매수자 거절-비율이 같은 레코드에서
    #   파생된다(일방 기록 = 허위-거절 갈취-레버 — [M-178] §2 D-5) ⓑrecord-only:
    #   정산·요율 무접촉(요율-결합은 T-EXTORT 실측 후 별도 재가) ⓒ(ref, p)당 1건 —
    #   재게시 = 교체(번복은 새 의견이지 삭제가 아니다) ⓓ이행-후에만·매수자(holder)만.
    def _accept_gc(self):
        now = self.w.epoch
        dead = [i for i, r in self.accepts.items()
                if r["rec"]["expires"] <= now]
        for i in dead:
            del self.accepts[i]
        return bool(dead)

    def _accept_save(self):
        tmp = self.accept_p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.accepts, fh, ensure_ascii=False)
        os.replace(tmp, self.accept_p)   # 자문층 — 원자 교체면 충분

    def accept_list(self):
        if self._accept_gc():
            self._accept_save()
        return {"epoch": self.w.epoch,
                "records": sorted(self.accepts.values(), key=lambda r: r["id"]),
                "note": ("수락-채널 v0 = record-only(요율-비연동 · 정산 무접촉) · "
                         "양측 파생 집계 = underwriter.py acceptance · "
                         "(ref,p)당 1건-교체")}

    def accept_post(self, body, sig):
        if not isinstance(body, dict) or not isinstance(sig, str):
            raise Fl21Error("accept: {rec: 서명-본문, sig: hex}")
        self._offledger_verify(ACCEPT_DOMAIN, body, sig, "accept")
        keys = {"ref", "p", "verdict", "note", "expires"}
        if set(body) != keys:
            raise Fl21Error(f"accept: 키는 정확히 {sorted(keys)}")
        if body["verdict"] not in ("accept", "rework"):
            raise Fl21Error("accept: verdict ∈ {accept, rework}")
        if not (isinstance(body["note"], str) and len(body["note"]) <= 200):
            raise Fl21Error("accept: note ≤ 200자")
        ref = str(body["ref"])
        j = self.jobs.get(ref)
        if j is None:
            raise Fl21Error("accept: 미지 ref")
        if not j.get("delivered"):
            raise Fl21Error("accept: 이행-후에만(일치 없는 수락-의견은 무의미)")
        if body["p"] != j.get("holder"):
            raise Fl21Error("accept: 그 청구의 매수자(holder)만")
        ex, now = body["expires"], self.w.epoch
        if not isinstance(ex, int) or isinstance(ex, bool) or \
                not (now < ex <= now + ACCEPT_TTL_MAX):
            raise Fl21Error(f"accept: expires ∈ (지금, 지금+{ACCEPT_TTL_MAX}]")
        self._accept_gc()
        rid = hashlib.sha256(f"acpt|{ref}|{body['p']}".encode()
                             ).hexdigest()[:16]    # (ref, p) 교체-주소
        if rid not in self.accepts:
            if len(self.accepts) >= ACCEPT_MAX:
                raise Fl21Error(f"accept: 전역 상한({ACCEPT_MAX})")
            mine = sum(1 for r in self.accepts.values()
                       if r["rec"]["p"] == body["p"])
            if mine >= ACCEPT_PER_P:
                raise Fl21Error(f"accept: 주체당 활성 {ACCEPT_PER_P}건")
        self.accepts[rid] = {"id": rid, "rec": body, "sig": sig}
        self._accept_save()
        return {"id": rid, "expires": ex}

    # ── ★P-11 /challenge([M-126] R2-A) — 낙관적-검증의 재검증 창 ──
    # 누구나(등록 주체) 이행-완료 잡의 재검증을 요청한다. 노드는 의무-재검증하고,
    # 불일치가 확인되면 온-원장 기록(운영자 TICKMARK fl21.challenge — head-결박)을
    # 남긴다. 표본-검증 클래스는 재검증마다 새 구간을 뽑으므로 챌린지가 검증 깊이를
    # 실제로 더한다([R-SAMPLE] 쌍대의 실행형). ⚠️v0.1 법-효과 = 평판 축(정직 등재 —
    # 배상은 인수-계약 조건·법-수준 소급은 FL2.2 회부 · [R2_DESIGN §2]).
    def challenge_lookup(self, body):
        """락 안(짧게): 서명·대상 확인 후 스펙·산출 스냅숏(락-밖 재검증용 — B2 동형)."""
        if not isinstance(body, dict):
            raise Fl21Error("challenge: {ref, p, sig}")
        ref, p, sig = body.get("ref"), body.get("p"), body.get("sig")
        if not (isinstance(ref, str) and isinstance(sig, str)):
            raise Fl21Error("challenge: {ref, p, sig}")
        self._offledger_verify(CHAL_DOMAIN, {"ref": ref, "p": p}, sig,
                               "challenge")
        j = self.jobs.get(ref)
        if j is None:
            raise Fl21Error("challenge: 미지 ref")
        if not j.get("delivered") or "output" not in j:
            raise Fl21Error("challenge: 미이행 잡(재검증 대상 없음)")
        return dict(j["job"]), j["output"]

    def challenge_commit(self, body, okv, detail):
        """락 안(짧게): 결과 기록 — 일치 = 계수만(오프-원장) · 불일치 = 온-원장 기록."""
        ref = body["ref"]
        j = self.jobs.get(ref)
        if j is None:
            raise Fl21Error("challenge: 미지 ref")
        ch = j.setdefault("challenges", {"ok": 0, "fail": 0})
        if okv:
            ch["ok"] += 1
            self._persist_new()          # 잡 메타만(원장 무접촉)
            return {"ref": ref, "verified": True, "challenges": dict(ch)}
        ch["fail"] += 1
        j["challenged"] = True
        entry = self._ksubmit(self.w.sign_env(
            "operator", "TICKMARK",
            {"kind": "fl21.challenge", "ref": ref, "anchor": j["anchor"],
             "by": body.get("p"),
             "why": str((detail or {}).get("why") or "불일치")[:80]}))
        self._persist_new()
        return {"ref": ref, "verified": False, "recorded_seq": entry["seq"],
                "challenges": dict(ch)}


class Handler(BaseHTTPRequestHandler):
    node: Node = None
    protocol_version = "HTTP/1.1"
    timeout = 30                      # ★slow-loris — 소켓 유휴 상한(느린 헤더/본문 절단)
    own_clock = False                 # ★SEC-1 — 노드가 자기 시계를 돌리면(auto-tick)
                                      # 외부 /tick 거부(시계는 노드의 것 · 기한-강제 방지)
    rate_limit = 0                    # ★D-6 — 초당 요청 상한/IP(0 = 끔 · 배포 시 켬)
    trust_forwarded = False           # ★D-5 — 프록시 뒤에서만 X-Forwarded-For 신뢰
    join_per_ip = 0                   # ★REACH-3 — join 상한/IP(0 = 끔 · 시빌 속도 제어)
    # ── ★H-1([M-188] RISK-1 경화) — 락-밖 재실행의 자원 유계화 ──────────────
    # 무거운 경로 둘(/challenge 재검증 · /deliver 산출 검증)은 **락 밖**에서 요청자
    # 코드를 서브프로세스로 재실행한다(`jobs.py` PY_TIMEOUT 10 CPU초·RLIMIT_AS 512MB).
    # ⚠️구멍의 실체: `join_per_ip` 는 **가입**을 제한하지 **챌린지**를 제한하지 않고,
    # 동시 재실행 수에는 상한이 아예 없었다 — 가입 주체 하나가 rate_limit 까지 난타하면
    # 서브프로세스가 무계로 쌓인다(단일 시퀀서라 노드 소진 = 시스템 전체 정지).
    # ⟹ 다이얼 둘: ⓐ주체당 창-예산(신원 하나를 무한 재사용 못 하게)
    #              ⓑ★전역 동시-재실행 슬롯(락-밖 처리의 대가를 유계화 — 포화 = 503)
    challenge_budget = 0              # 주체당 창-당 챌린지 상한(0 = 끔 · 배포 시 켬)
    challenge_window = 60             # 그 예산의 창(초)
    verify_slots = 0                  # 동시 재실행 상한(0 = 끔 · 배포 시 켬)
    verify_wait = 5.0                 # 슬롯 대기 상한(초) — 초과 = 503(대기도 자원이다)
    _buckets = {}
    _joins = {}                       # IP → join 수(프로세스 수명 · nd.lock 안에서만 접근)
    _chal = {}                        # 주체 → (창 시작, 사용량) — ★H-1ⓐ
    _slots = None                     # BoundedSemaphore | None — ★H-1ⓑ
    _block = threading.Lock()

    def _peer(self):
        # ★rate-limit이 프록시 뒤 단일 버킷으로 붕괴하는 것 방지 — 신뢰 프록시일 때만 XFF
        if self.trust_forwarded:
            xff = self.headers.get("X-Forwarded-For")
            if xff:
                return xff.split(",")[-1].strip()   # 마지막 홉(프록시가 붙인 실 피어)
        return self.client_address[0]

    def log_message(self, *a):        # 조용히(테스트 소음 방지)
        pass

    def _rate_ok(self):
        if self.rate_limit <= 0:
            return True
        ip = self._peer()
        now = time.monotonic()
        with self._block:
            tok, last = self._buckets.get(ip, (float(self.rate_limit), now))
            tok = min(float(self.rate_limit),
                      tok + (now - last) * self.rate_limit)
            # 유휴 IP 버킷 축출(무한 증가 방지 — 가득 찬 버킷은 상태가 없음)
            if len(self._buckets) > 4096:
                for k in [k for k, (t, ls) in self._buckets.items()
                          if now - ls > 60]:
                    del self._buckets[k]
            if tok < 1:
                self._buckets[ip] = (tok, now)
                return False
            self._buckets[ip] = (tok - 1, now)
            return True

    # ── ★H-1ⓐ 주체당 챌린지 예산 ──────────────────────────────────────────
    def _chal_budget_ok(self, p):
        """★H-1([M-188]) — 주체당 창-예산. ⚠️**서명 검증 뒤에만** 부른다:
        검증 전에 깎으면 위조 p 로 **남의 예산을 소진**시킬 수 있다(갈취-레버)."""
        if self.challenge_budget <= 0 or not isinstance(p, str):
            return True
        now, w = time.monotonic(), float(self.challenge_window or 60)
        with self._block:
            start, used = Handler._chal.get(p, (now, 0))
            if now - start >= w:                      # 창 갱신
                start, used = now, 0
            if len(Handler._chal) > 4096:             # 유휴 축출(무한 증가 방지)
                for k in [k for k, (s, _u) in Handler._chal.items()
                          if now - s > w * 2]:
                    del Handler._chal[k]
            if used >= self.challenge_budget:
                Handler._chal[p] = (start, used)
                return False
            Handler._chal[p] = (start, used + 1)
            return True

    # ── ★H-1ⓑ 전역 동시-재실행 슬롯 ───────────────────────────────────────
    def _slot_acquire(self):
        """포화면 False(= 503). 대기 상한을 두는 이유: 무한 대기는 스레드를 쌓아
        같은 소진을 다른 자원(스레드·소켓)으로 옮길 뿐이다."""
        sem = Handler._slots
        return True if sem is None else sem.acquire(timeout=self.verify_wait)

    def _slot_release(self):
        if Handler._slots is not None:
            Handler._slots.release()

    _BUSY = {"error": "재검증 용량 포화 — 잠시 후 재시도(H-1 동시-재실행 상한)"}

    def _deliver(self, nd, env, output):
        """★B2 이행 경로(로직 무변경 — ★H-1 슬롯 안에서 돌도록 분리만 했다).
        1) 락 안 짧게: 잡 확인·스펙 복사 2) 락 밖: 무거운 검증 3) 락 안: 커널 커밋."""
        with nd.lock:             # 1) 짧게: 잡 확인·스펙 복사
            spec = nd.deliver_lookup(env)
            idxs = None
            if spec["kind"] == "sha256_chain_sampled":
                # ★[M-165] R4-1 — 형식-사전검사(암호-무·락 안 짧게):
                # 쓰레기-형식이 무-비용으로 ocommit 원장-비대를 만들지 못하게
                pok, pwhy = JOBS.precheck_sampled(spec, output)
                if not pok:
                    raise Fl21Error(f"산출 검증 실패 — 이행 불인정"
                                    f"({pwhy.get('why', '형식')})")
                # ★[M-164] 커밋-표본: 커밋 랜딩 후 head-유도 인덱스로 검증
                idxs, cseq = nd.ocommit_and_derive(env, output)
        if idxs is not None:      # 2) 락 밖: 유도-표본으로 무거운 검증
            ok, detail = JOBS.verify_output(spec, output, idxs=idxs)
            if ok:
                detail["ocommit_seq"] = cseq
                detail["sample"] = "ledger-derived"
        else:
            ok, detail = JOBS.verify_output(spec, output)
        if not ok:
            raise Fl21Error(
                f"산출 검증 실패 — 이행 불인정({detail.get('why', '불일치')})")
        with nd.lock:             # 3) 짧게: 재확인 후 커널 커밋
            return self._send(200, nd.deliver_commit(env, output, detail))


    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if code >= 400:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            raise Fl21Error("Content-Length 비정형")
        if not (0 <= n <= 2_000_000):    # ★H6 — 음수 CL이 read(-1)=EOF까지(OOM) 우회하던 것
            raise Fl21Error("페이로드 상한/음수 거부")
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        nd = self.node
        if not self._rate_ok():
            return self._send(429, {"error": "유량 제한"})
        try:
            if self.path == "/robots.txt":
                # ★[M-144] 노드는 웹사이트가 아니라 API다 — 크롤러가 원장을 페이징하면
                # 오리진(단일 노드) 비용만 늘고 검색 가치는 0이다. 반면
                # 「쓰려는」 에이전트는 크롤러가 아니라 클라이언트라 이 지시의 대상이
                # 아니다(설명·발견 표면은 vlue.ai — 거기는 전면 개방).
                body = ("# This is an API, not a website.\n"
                        "# Humans and agents: read https://vlue.ai/llms.txt first.\n"
                        "# Clients calling this API deliberately are welcome —\n"
                        "# this only asks crawlers not to page the ledger.\n"
                        "User-agent: *\n"
                        "Disallow: /\n").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                return self.wfile.write(body)
            with nd.lock:
                p = self.path
                if p == "/meta":
                    return self._send(200, nd.meta())
                if p == "/state":
                    return self._send(200, nd.state())
                if p == "/audit":
                    return self._send(200, nd.audit())
                if p == "/stats":                     # ★P-5
                    return self._send(200, nd.stats())
                if p == "/board":                     # ★R2-a 호가 창(발견층)
                    return self._send(200, nd.board_list())
                if p == "/accept":                    # ★[M-178] 수락-채널(record-only)
                    return self._send(200, nd.accept_list())
                m = re.match(r"^/attest/([a-z0-9_-]+)$", p)
                if m:                                 # ★P-9
                    return self._send(200, nd.attest(m.group(1)))
                m = re.match(r"^/balance/([a-z0-9_-]+)$", p)
                if m:
                    return self._send(200, {"balance": nd.w.bal(m.group(1))})
                m = re.match(r"^/nonce/([a-z0-9_-]+)$", p)
                if m:
                    return self._send(200, {"nonce": nd.w.nonces.get(m.group(1), 0),
                                            "epoch": nd.w.epoch})
                m = re.match(r"^/notes/([a-z0-9_-]+)$", p)
                if m:
                    who = m.group(1)
                    ns = sorted(((nid, n["face"]) for nid, n in nd.w.notes.items()
                                 if n["owner"] == who), key=lambda x: int(x[0]))
                    return self._send(200, {"notes": [
                        {"nid": a, "face": b,
                         "color": nd.colors.get(a)}    # ★[M-103] 발행자(색)
                        for a, b in ns]})
                m = re.match(r"^/log\?since=(\d+)$", p)
                if m:
                    s = int(m.group(1))
                    return self._send(200, {"entries": nd.w.log[s:s + 500]})
                m = re.match(r"^/cosigs\?since=(\d+)$", p)
                if m:
                    s = int(m.group(1))
                    # ★N-3 — 병합-맵을 seq-정렬 서빙(행-단위 파일 절단의 페이지-경계
                    # seq 서명 누락 봉합 · SDK 커서[seq+1]가 이제 정확)
                    ks = sorted(k for k in list(nd.cosig_map) if k >= s)[:500]
                    rows = [nd.cosig_map.get(k) for k in ks]
                    return self._send(200, {"cosigs": [r for r in rows if r]})
                m = re.match(r"^/jobs\?anchor=([a-z0-9_-]+)$", p)
                if m:
                    a = m.group(1)
                    js = {r: j for r, j in nd.jobs.items()
                          if j["anchor"] == a and j["state"] == "open"
                          and not j.get("delivered")}
                    return self._send(200, {"jobs": js, "epoch": nd.w.epoch})
                if p.startswith("/job/"):
                    ref = p[5:]
                    j = nd.jobs.get(ref)
                    if j is None:
                        return self._send(404, {"error": "미지 ref"})
                    c = nd.w.uw_open.get(ref)         # ★P-4 커버리지 노출
                    cov = ({"covered": True, "uw": c["uw"], "prem": c["prem"]}
                           if c else {"covered": False})
                    if not c and j.get("cover"):      # ★정산 후 이력(맥락-0 C-2)
                        cov["cover_history"] = j["cover"]
                    if ref in nd.ocommits:            # ★[M-164] 재추첨 공개 계수
                        cov["ocommits"] = nd.ocommits[ref]
                    return self._send(200, {"ref": ref, **j, **cov})
            return self._send(404, {"error": "미지 경로"})
        except Exception as e:                   # 경계 격리(A-4) — 노드 생존
            return self._send(400, {"error": f"{type(e).__name__}: {e}"[:200]})

    def do_POST(self):
        nd = self.node
        if not self._rate_ok():
            return self._send(429, {"error": "유량 제한"})
        try:
            body = self._read_json()
            p = self.path
            if p == "/deliver":       # ★B2 — 검증(서브프로세스·재해시)은 락 밖에서
                env = body.get("env")
                output = body.get("output", "")
                # ★H-1ⓑ — 슬롯을 **상태 변경 전에** 잡는다: ocommit(원장 기입)이
                # 먼저 랜딩한 뒤 포화로 되돌리면 고아 커밋이 남는다.
                if not self._slot_acquire():
                    return self._send(503, self._BUSY)
                try:
                    return self._deliver(nd, env, output)
                finally:
                    self._slot_release()
            if p == "/challenge":     # ★P-11([M-126]) — 재검증도 락 밖(B2 동형)
                with nd.lock:         # 1) 짧게: 서명 검증 + 스펙·산출 스냅숏
                    spec, output = nd.challenge_lookup(body)
                # ★H-1ⓐ — 예산은 **서명 검증 뒤에** 깎는다(위조 p 로 남의 예산 소진 방지)
                if not self._chal_budget_ok(body.get("p")):
                    return self._send(429, {
                        "error": f"챌린지 예산 초과 — 주체당 "
                                 f"{self.challenge_budget}건/{self.challenge_window}초"
                                 f"(H-1 재검증 예산)"})
                if not self._slot_acquire():          # ★H-1ⓑ
                    return self._send(503, self._BUSY)
                try:
                    okv, detail = JOBS.verify_output(spec, output)
                finally:
                    self._slot_release()
                with nd.lock:
                    return self._send(200, nd.challenge_commit(body, okv,
                                                               detail))
            with nd.lock:
                if p == "/join":
                    # ★시빌-소진 방어([M-114] REACH-3): identity_budget(128)은 전역·
                    # 단조(EXIT도 슬롯 반환 안 함)라 한 행위자가 수 초에 전량 소진하면
                    # 그 세계의 join이 영구 봉쇄된다 — per-IP 하위 상한으로 속도 제어
                    # (0 = 끔 · 초기 수요-탐침 창에서만 의미 · 운영 다이얼).
                    if self.join_per_ip > 0:
                        ip = self._peer()
                        n = Handler._joins.get(ip, 0)
                        if n >= self.join_per_ip:
                            return self._send(429, {"error": "join 상한/IP — 초기 창의 "
                                                    "시빌 속도 제어(운영자 문의)"})
                        Handler._joins[ip] = n + 1
                    return self._send(200, nd.join(body.get("principal"),
                                                   body.get("pk", "")))
                if p == "/bootstrap":                 # ★[M-103] 상호 신용 교환
                    return self._send(200, nd.bootstrap(body.get("leg")))
                if p == "/issue":                     # ★[M-104] 회전-발행
                    return self._send(200, nd.issue(body.get("env")))
                if p == "/cosig":                     # ★[M-105] D-2 원격 공동-서명 수신
                    return self._send(200, nd.cosig_add(body))
                if p == "/relay":                     # ★[M-162] leg-릴레이 송신
                    return self._send(200, nd.relay_send(body.get("msg"),
                                                         body.get("sig")))
                if p == "/relay/fetch":               # ★[M-162] 수신(읽고-지움)
                    return self._send(200, nd.relay_fetch(body.get("msg"),
                                                          body.get("sig")))
                if p == "/board":                     # ★R2-a — 오프-원장 서명 게시
                    return self._send(200, nd.board_post(body.get("post"),
                                                         body.get("sig")))
                if p == "/accept":                    # ★[M-178] 수락-의견 게시
                    return self._send(200, nd.accept_post(body.get("rec"),
                                                          body.get("sig")))
                if p == "/submit":
                    return self._send(200, nd.submit(body.get("env")))
                if p == "/job":
                    return self._send(200, nd.submit_job(body.get("env"),
                                                         body.get("job")))
                if p == "/block":
                    return self._send(200, nd.block(body.get("legs")))
                if p == "/tick":
                    # ★SEC-1([M-137]): 자기 시계를 가진 노드(배포 = --auto-tick)에서
                    # 외부 틱은 **기한 강제**의 수단이다 — 익명 난타로 에포크를 밀어
                    # 미결 주문을 즉시 시한-사고로 만들 수 있다(이행자 배상 유발·보드
                    # TTL 소각). 시계는 노드의 것으로 못박는다. auto-tick 없는 로컬·
                    # 데모 세계는 그대로 열려 있다(드라이버가 곧 시계).
                    if self.own_clock:
                        return self._send(403, {
                            "error": "tick: 이 노드는 자기 시계로 돈다"
                                     "(--auto-tick) — 외부 틱 불가"})
                    return self._send(200, nd.tick())
            return self._send(404, {"error": "미지 경로"})
        except Fl21Error as e:
            return self._send(400, {"error": str(e)[:200]})
        except Exception as e:                   # 비정규 입력 — 격리·생존(A-4)
            return self._send(400, {"error": f"{type(e).__name__}: {e}"[:200]})


def serve(data_dir, port, auto_tick=0, join_issue=20, bind="127.0.0.1",
          rate_limit=0, genesis_issue=40, bootstrap_cap=BOOT_CAP,
          cosign_local=None, bridge_ref=None, trust_forwarded=False,
          join_per_ip=0, unit_scale=1,
          challenge_budget=0, challenge_window=60,
          verify_slots=0, verify_wait=5.0):
    nd = Node(data_dir, join_issue=join_issue, genesis_issue=genesis_issue,
              bootstrap_cap=bootstrap_cap, cosign_local=cosign_local,
              bridge_ref=bridge_ref, unit_scale=unit_scale)
    Handler.node = nd
    Handler.trust_forwarded = bool(trust_forwarded)   # ★D-5 프록시 뒤 XFF
    Handler.own_clock = auto_tick > 0  # ★SEC-1 — 자기 시계 = 외부 틱 거부
    Handler.rate_limit = rate_limit   # ★D-6
    Handler.join_per_ip = int(join_per_ip)   # ★REACH-3 — 시빌 속도 제어
    Handler._joins = {}
    # ★H-1([M-188]) — 락-밖 재실행의 유계화(0 = 끔 · 배포 시 켬)
    Handler.challenge_budget = int(challenge_budget)
    Handler.challenge_window = float(challenge_window or 60)
    Handler.verify_slots = int(verify_slots)
    Handler.verify_wait = float(verify_wait)
    Handler._chal = {}
    Handler._slots = (threading.BoundedSemaphore(int(verify_slots))
                      if int(verify_slots) > 0 else None)
    srv = ThreadingHTTPServer((bind, port), Handler)   # ★D-5 — 바인딩 선택
    if auto_tick > 0:
        def _tk():
            while True:
                time.sleep(auto_tick)
                try:
                    with nd.lock:
                        nd.tick()
                except Exception as e:   # ★침묵 금지 — 틱 정지는 기한 정산이 멈춘다는 뜻
                    print(json.dumps({"auto_tick_error": str(e)[:150],
                                      "epoch": nd.w.epoch}), file=sys.stderr,
                          flush=True)
        threading.Thread(target=_tk, daemon=True).start()
    return nd, srv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--port", type=int, default=8788)
    ap.add_argument("--auto-tick", type=float, default=0)
    ap.add_argument("--join-issue", type=int, default=20)   # ★자기-IOU 회전 한도
    ap.add_argument("--genesis-issue", type=int, default=40)
    ap.add_argument("--bootstrap-cap", type=int, default=BOOT_CAP)
    ap.add_argument("--cosign-local", default=",".join(COSIGNERS),
                    help="이 노드가 보유한 공동서명 키(쉼표 — D-2 분리 시 부분집합)")
    ap.add_argument("--bridge-ref", default=None,
                    help="세대-연속 참조(U-0 — 프로덕션 창세 = 파일럿 최종 head)")
    ap.add_argument("--trust-forwarded", action="store_true",
                    help="신뢰 프록시(D-5 TLS) 뒤에서만 — rate-limit이 X-Forwarded-For 사용")
    ap.add_argument("--bind", default="127.0.0.1")     # ★D-5(공개는 프록시/TLS 뒤)
    ap.add_argument("--rate-limit", type=int, default=0)  # ★D-6(초당/IP · 배포 시 켬)
    ap.add_argument("--join-per-ip", type=int, default=0,
                    help="join 상한/IP(0 = 끔 · ★공개 초기 = 시빌 속도 제어 REACH-3)")
    ap.add_argument("--unit-scale", type=int, default=1,
                    help="1 AU = 이만큼 기본단위([M-127] — 프로덕션 1000 = mAU)")
    # ★H-1([M-188] RISK-1) — 재검증 자원 유계화(0 = 끔 · ⚠️배포에서 반드시 켠다)
    ap.add_argument("--challenge-budget", type=int, default=0,
                    help="주체당 창-당 챌린지 상한(0 = 끔 · H-1ⓐ)")
    ap.add_argument("--challenge-window", type=float, default=60,
                    help="그 예산의 창(초 · 기본 60)")
    ap.add_argument("--verify-slots", type=int, default=0,
                    help="동시 재실행 상한(0 = 끔 · H-1ⓑ — 포화 = 503)")
    ap.add_argument("--verify-wait", type=float, default=5.0,
                    help="슬롯 대기 상한(초) — 초과 = 503(대기도 자원이다)")
    a = ap.parse_args()
    nd, srv = serve(a.data, a.port, a.auto_tick, a.join_issue,
                    bind=a.bind, rate_limit=a.rate_limit,
                    genesis_issue=a.genesis_issue, bootstrap_cap=a.bootstrap_cap,
                    cosign_local=tuple(x for x in a.cosign_local.split(",") if x),
                    bridge_ref=a.bridge_ref, trust_forwarded=a.trust_forwarded,
                    join_per_ip=a.join_per_ip, unit_scale=a.unit_scale,
                    challenge_budget=a.challenge_budget,
                    challenge_window=a.challenge_window,
                    verify_slots=a.verify_slots, verify_wait=a.verify_wait)
    print(json.dumps({"r1": "up", "port": a.port, "seq": len(nd.w.log),
                      "epoch": nd.w.epoch, "audit": nd.audit()["ok"]},
                     ensure_ascii=False), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
