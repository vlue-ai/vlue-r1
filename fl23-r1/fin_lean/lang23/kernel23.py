#!/usr/bin/env python3
"""kernel23.py — FL2.3 커널 v0.1 ([M-200~201] 착수 — 세대 규율 경유 · lang22 무수정 보존).

★★계보: FL2.0 → FL2.1 → FL2.2(FROZEN — kernel22 · 셀프 20 · 골든 9 · 냉독 9라운드) →
**FL2.3 = FL2.2 정산법 문언-동일 승계 + 「완성의 형태」 델타 8** — 완성 = 법이 ⓐ규모 ⓑ적대
ⓒ키-수명 ⓓ정합에 닫힘(기능 완비 아님 — 네팅·기간·암호형은 수요-결박 회부 유지).
설계 정본 = FL23_DESIGN §8(v0.2)·§9(v0.3 — 직접 리뷰 R-1~R-18 반영) · 스코프 정본 =
core/FL23_SCOPE_RESEARCH_2026-09-02.md · 리뷰 = core/FL23_DESIGN_REVIEW_2026-09-02.md.

  J-3 **EXIT-회수**: identity_budget 을 누적-상한에서 **생존-상한**으로(`size − seats − exited`).
      명부는 append-only(이름 재사용 불가) · EXIT 는 슬롯만 되돌린다.
  J-4 **REKEY**: `REKEY{principal, new_pk, new_sig}` — 현행-키 봉투 서명 + 새-키 소유-증명
      (`new_sig` = 새 키가 DOMAIN‖log_id‖"REKEY"‖p‖new_pk‖old_pk 에 서명). 즉시 발효 · 키-일정은
      로그-파생(검증자: REKEY 엔트리 통과 후 다음 항부터 신-키). 탈취-경쟁은 비-중재(선-회전 수단).
  J-5 **증분 상태 3종 + 소유자 색인**: `_snap`(전-상태 deepcopy) → **저널(undo-log)** ·
      `_invariants`(전-노트 스캔) → **누계 + touched-국소** · `state_root`(전-상태 재해시) →
      **버킷 증분 커밋먼트**(notes 1024 버킷 · 맵은 touched 시 재계산) · `_by_owner` 색인으로
      bal·_seize·EXIT·정산 ①③ 이 O(자기 노트). ⟹ write 비용 O(변경) — 냉독 라운드 6~9 부류의 근치.
  J-6 **상태-상한**: GEN `notes_per_owner_max` — **자발 민트**(SPLIT·EXT_IN·EXT_IN_POOL·IMPORT)만
      검사 · 법-구동 민트(정산 배상·잔돈·반환·에스크로)는 면제(순 노트 수 비-증가). 합법 SPLIT 팽창
      (실측 1,025회 → 17× 과세)의 공간-축 봉합.
  J-7 **인증-거부 기록**: 서명 유효 ∧ nonce 일치인 **비-operator** 봉투가 스키마·창·_apply 에서
      실패하면 **REJECT 엔트리**(env·상태 불변·head 전진·reason 은 정보 필드)를 쓰고 **nonce 를
      소비**한다 — 「실패-op 무한 재생」 비대칭을 구성으로 제거. operator 봉투의 실패는 종전대로
      무기록(노드가 자기 봉투를 먼저 검증할 의무 — 서명자 의무). FORCE 내부 봉투가 인증 후 실패하면
      `included:False` + 내부 서명자 nonce 소비. ★부수: FL2.2 의 잠재 결함 F-K1(REQUEST 내부 봉투가
      _apply 도중 실패하면 부분-변이가 남아 이후 모든 TICK 이 보존식 위반으로 거부 — 시퀀서 웨지 ·
      2026-09-02 재현)을 **세이브포인트**(중첩 저널 마크)로 봉합.
  J-8 **입력-스키마 전문**: op 별 필수 필드·타입 + 제네릭 형태 상한(문자열·정수·리스트·중첩 깊이)을
      `_verify_env` 직후·저널 전에 검사 — [M-189·195·196·197] 동결-예외 4건을 법으로 흡수.
      ★스펙-불투명 원칙 유지: **미지 확장 필드는 거부하지 않는다**(r1 의 spec_sha256·kind 등 —
      커널은 스펙을 해석하지 않고 통째 서명-결박한다) · 형태 상한만 건다.
  J-9 **민트-nid 명시**: `_force.returned[*].nid` · `settled[*].comp_nid` · `change_nids` —
      서비스층 색-귀속 휴리스틱(F-E) 제거.
  J-11 **GENESIS_IMPORT**: 첫 엔트리 전용 · `{snapshot_hash, principals, notes[{owner,face,issuer}],
      F, F_uw, exited}` · `ext_in = Σface + F + F_uw`(보존식) · 색은 커널 노트에 넣지 않는다
      (`issuer` 는 args 에만 — r1 색-엔진의 시드) · 승계 전제 = 열린 청구·커버 0(절차 조건).

  불변(법 승계): S-1 시한-사고 · S-2 ATTEST · U-1 β<1 · U-2 소구 폭포(①불이행 앵커 자유잔고 →
  ②담보 → ③인수자 소구 → ④F_uw → 잔여 short) · U-3 F_uw 분리 · 적정성-결박 흡입 · 검열저항
  REQUEST/FORCE · K-0ⓔ · J-1 잡별 T · J-2 from_public/replay_verify — 전부 **문언-동일 승계**.
  승계-증명 = 골든 9 정산-배분 멀티셋 = FL2.2 벡터와 동일(frontier_vectors.py · golden_compare.py).

지위: ⛔참조 구현 v0.1 — 캐논 아님(동결은 셀프테스트·골든·차등·게이트 전량 후 결정 경유).
정직 한정어(FL2.1 ⓐ~ⓗ 승계 + v0.1): ⓘ REKEY 는 선-회전 수단이지 탈취-후 복구가 아니다 ⓙ REJECT
`reason` 은 head 밖 정보 필드(문구는 법이 아니다 — 리플레이는 「거부 발생 ∧ 상태 불변」만 단언)
ⓚ 상태-상한은 자발 민트에만 걸리므로 법-구동 민트가 상한을 일시 초과할 수 있다(정직 표기 — MERGE 로
회수 가능) ⓛ 버킷 root 는 노트 nid 가 커널 카운터(정수 문자열)라는 사실에 의존한다(import 도 새 nid).
"""
import hashlib
import json
from types import MappingProxyType

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (Ed25519PrivateKey,
                                                               Ed25519PublicKey)

FL23_DOMAIN = b"FL23-v0.1" + b"\x00" * 7
assert len(FL23_DOMAIN) == 16
KEY_TAG23 = b"FL23-KEY-v0.1"

DEFAULT_GEN = {
    "identity_budget": 16,
    "window_L": 3,
    "qual_price": 40,
    "room_c": 32, "room_phi": 2,
    "redeem_T": 4,
    "beta_min_num": 1, "beta_min_den": 2,
    "uw_phi_num": 1, "uw_phi_den": 2,
    "prem_floor_num": 0, "prem_floor_den": 1,
    "fq_mult": 0, "fq_base": 12,
    "redeem_T_max": 0,
    "notes_per_owner_max": 256,      # ★J-6 — 소유자별 유통-노트 상한(자발 민트 한정 · 0 = 끔)
}
_MONEY_FIELDS = {"EXT_IN": ("amount",), "EXT_IN_POOL": ("pool",)}
_LIST_MAX = 1024            # 리스트-인자 길이 상한([M-196/197] 승계 — 이제 스키마의 일부)
_BLOCK_LEGS_MAX = 16        # ★J-8 R-8 — BLOCK 다리 수 상한(노드는 8)
_IMPORT_MAX = 65536         # ★J-11 — 수입 리스트 상한(첫 엔트리 전용)
_STR_MAX = 512              # 제네릭 문자열 상한(스펙-불투명 확장 필드 포함)
_ARGS_KEYS_MAX = 32
_DEPTH_MAX = 6              # BLOCK.args→legs→leg→args→list→scalar = 5 (정당 최대) + 1 여유
_BUCKETS = 1024             # ★J-5 — notes 버킷 수
REJECT_REASON_MAX = 64
_MISSING = object()

OPS = ("REQUEST", "TICK", "FORCE", "JOIN", "EXIT", "EXT_IN", "EXT_IN_POOL", "EXT_OUT",
       "XFER", "SPLIT", "MERGE", "BURN", "QUAL_BUY", "OPEN", "CLOSE", "REDEEM", "DELIVER",
       "REDEEM_CANCEL", "UW", "ATTEST_OK", "ATTEST_FAIL", "BLOCK", "TICKMARK",
       "REKEY", "GENESIS_IMPORT")
# ★J-8 — op 별 필수 필드(타입 술어). 확장 필드는 허용(스펙-불투명) · 형태 상한은 _bound 가 건다.
_S, _I, _L, _D = "str", "int", "list", "dict"
REQ = {
    "REQUEST": {"inner": _D}, "TICK": {}, "FORCE": {"inner": _D}, "TICKMARK": {},
    "JOIN": {"principal": _S, "pk": _S}, "EXIT": {"a": _S},
    "EXT_IN": {"to": _S, "amount": _I}, "EXT_IN_POOL": {"pool": _I, "claims": _D},
    "EXT_OUT": {"frm": _S, "note": _S}, "XFER": {"frm": _S, "to": _S, "note": _S},
    "SPLIT": {"owner": _S, "note": _S, "parts": _L}, "MERGE": {"owner": _S, "notes": _L},
    "BURN": {"owner": _S, "note": _S}, "QUAL_BUY": {"a": _S, "notes": _L},
    "OPEN": {"owner": _S, "rid": _S, "notes": _L},
    "CLOSE": {"rid": _S, "owner": _S, "performer": _S},
    "REDEEM": {"holder": _S, "note": _S, "anchor": _S},
    "DELIVER": {"anchor": _S, "ref": _S}, "REDEEM_CANCEL": {"ref": _S},
    "UW": {"uw": _S, "ref": _S, "cov_notes": _L, "prem": _I},
    "ATTEST_OK": {"ref": _S, "reason": _S}, "ATTEST_FAIL": {"ref": _S, "reason": _S},
    "BLOCK": {"legs": _L},
    "REKEY": {"principal": _S, "new_pk": _S, "new_sig": _S},
    "GENESIS_IMPORT": {"snapshot_hash": _S, "principals": _L, "notes": _L,
                       "F": _I, "F_uw": _I, "exited": _L},
}
_NO_NEST = ("BLOCK", "REQUEST", "FORCE", "TICK", "GENESIS_IMPORT")   # 다리·내부에 금지


class Fl23Error(Exception):
    """경로 거부 — 이 봉투는 상태를 바꾸지 못한다(법-검사 실패). ★J-7: 비-operator 인증 봉투의
    거부는 REJECT 엔트리로 **기록**된다(상태 불변 · nonce 소비)."""


Fl22Error = Fl21Error = Fl23Error        # 하위호환 별칭(승계 코드·게이트 무-churn)


def _canon(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode()


def _pos_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and x >= 1


def _nonneg_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def _hexbytes(s, n, what):
    if not (isinstance(s, str) and len(s) == 2 * n):
        raise Fl23Error(f"{what}: {n}바이트 hex")
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise Fl23Error(f"{what}: hex 아님")


def derive_key(master_seed: int, principal: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(KEY_TAG23 + b"|" + str(int(master_seed)).encode()
                          + b"|" + principal.encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


class ChainRegistry:
    """지문-체인 레지스트리 — 추가 = 새 링크(과거 결박 불변). ★J-4: rekey 도 링크다(kind="rekey")."""

    def __init__(self):
        self._pk = {}
        self.links = []
        self.fp = "genesis"

    def _link(self, principal, pk, tag):
        h = hashlib.sha256()
        h.update(self.fp.encode() if self.fp == "genesis" else bytes.fromhex(self.fp))
        h.update(b"\x00" + principal.encode() + b"\x00" + pk + tag)
        self.fp = h.hexdigest()
        self._pk[principal] = pk
        self.links.append((principal, pk.hex(), self.fp, "join" if tag == b"\x01" else "rekey"))
        return self.fp

    def extend(self, principal, pk_bytes):
        if principal in self._pk:
            raise Fl23Error(f"레지스트리: {principal} 재등록 거부")
        pk = bytes(pk_bytes)
        if len(pk) != 32:
            raise Fl23Error(f"pk 는 32바이트(받음 {len(pk)})")
        return self._link(principal, pk, b"\x01")

    def rekey(self, principal, pk_bytes):
        if principal not in self._pk:
            raise Fl23Error(f"레지스트리: 미지 주체 {principal} 회전 불가")
        pk = bytes(pk_bytes)
        if len(pk) != 32:
            raise Fl23Error(f"pk 는 32바이트(받음 {len(pk)})")
        if pk == self._pk[principal]:
            raise Fl23Error("REKEY: 같은 키")
        return self._link(principal, pk, b"\x02")

    def pk(self, principal):
        return self._pk.get(principal)

    def size(self):
        return len(self._pk)

    def pk_root(self):
        return hashlib.sha256(_canon(
            {p: v.hex() for p, v in self._pk.items()})).hexdigest()

    def snap(self):
        return (dict(self._pk), list(self.links), self.fp)

    def restore(self, s):
        self._pk, self.links, self.fp = dict(s[0]), list(s[1]), s[2]


def log_id_of(fp0: str, label: str) -> bytes:
    return hashlib.sha256(FL23_DOMAIN + fp0.encode() + b"|" + label.encode()).digest()


class World:
    """FL2.3 참조 세계 — 상태는 이 클래스가 사유하고, 변경은 submit()/tick() 경로뿐이다.
    ★J-5: 모든 변이는 저널 프리미티브(_note_*·_mset·_mdel·_lappend·_lpop0·_sset)를 경유한다 —
    직접 대입은 규율 위반(게이트 T-PRIM 이 잔존 0 을 단언)."""

    SEATS = ("operator",)
    _STATE = ("notes", "note_ctr", "locked_rooms", "room_owner", "redeem_pending",
              "uw_open", "exited", "F", "F_uw", "F_peak", "S", "ext_in", "ext_out",
              "qual_burn", "Q", "nonces", "pending", "epoch")
    _MAPS = ("locked_rooms", "room_owner", "redeem_pending", "uw_open", "qual_burn", "Q",
             "nonces")
    _LISTS = ("exited", "pending")
    _SCALARS = ("note_ctr", "F", "F_uw", "F_peak", "S", "ext_in", "ext_out", "epoch")

    def __init__(self, master_seed=2, label="fl23-ref",
                 genesis_agents=("a0", "a1", "a2", "a3"), gen=None,
                 bridge_ref=None):
        if gen:
            unknown = set(gen) - set(DEFAULT_GEN)
            if unknown:
                raise Fl23Error(f"GEN: 미지 파라미터 {sorted(unknown)}")
        self._genesis = (master_seed, label, tuple(genesis_agents),
                         tuple(sorted((gen or {}).items())), bridge_ref)
        self.GEN = MappingProxyType({**DEFAULT_GEN, **(gen or {})})
        self.bridge_ref = bridge_ref
        self.reg = ChainRegistry()
        self._keys = {}
        for p in self.SEATS + tuple(genesis_agents):
            k = derive_key(master_seed, p)
            self._keys[p] = k
            self.reg.extend(p, k.public_key().public_bytes_raw())
        self.fp0 = self.reg.fp
        self.log_id = log_id_of(self.fp0, label)
        self._blank_state(genesis_agents)

    def _blank_state(self, genesis_agents):
        self.notes = {}
        self.note_ctr = 0
        self.locked_rooms = {}
        self.room_owner = {}
        self.redeem_pending = {}
        self.uw_open = {}
        self.exited = []
        self.F = 0
        self.F_uw = 0
        self.F_peak = 0
        self.S = 0
        self.ext_in = 0
        self.ext_out = 0
        self.qual_burn = {a: 0 for a in genesis_agents}
        self.Q = {a: 0 for a in genesis_agents}
        self.nonces = {}
        self.epoch = 0
        self.pending = []
        self.log = []
        self._init_derived()

    # ── ★J-5 파생 색인·다이제스트 캐시 ──
    def _init_derived(self):
        self._by_owner = {}
        self._owner_face = {}
        self._face_total = 0
        self._bkt_members = [set() for _ in range(_BUCKETS)]
        self._bkt = [None] * _BUCKETS
        self._mdig = {}
        self._journal = None
        self._reg_marked = False
        self._txn = None                      # ★서비스층 원자 구간(begin_txn/rollback_txn) — 커밋 저널 누적
        for nid, n in self.notes.items():
            self._idx_add(nid, n["owner"], n["face"])

    def _idx_add(self, nid, owner, face):
        self._by_owner.setdefault(owner, set()).add(nid)
        self._owner_face[owner] = self._owner_face.get(owner, 0) + face
        self._face_total += face
        b = int(nid) % _BUCKETS
        self._bkt_members[b].add(nid)
        self._bkt[b] = None

    def _idx_del(self, nid, owner, face):
        s = self._by_owner.get(owner)
        if s is not None:
            s.discard(nid)
            if not s:
                del self._by_owner[owner]
        self._owner_face[owner] = self._owner_face.get(owner, 0) - face
        if self._owner_face[owner] == 0:
            del self._owner_face[owner]
        self._face_total -= face
        b = int(nid) % _BUCKETS
        self._bkt_members[b].discard(nid)
        self._bkt[b] = None

    # ── ★J-5 저널 프리미티브(모든 변이는 여기로) ──
    def _jpush(self, rec):
        if self._journal is not None:
            self._journal.append(rec)

    def _note_raw_put(self, nid, rec):
        old = self.notes.get(nid)
        if old is not None:
            self._idx_del(nid, old["owner"], old["face"])
        self.notes[nid] = rec
        self._idx_add(nid, rec["owner"], rec["face"])

    def _note_raw_del(self, nid):
        old = self.notes.pop(nid)
        self._idx_del(nid, old["owner"], old["face"])

    def _note_set(self, nid, owner, face):
        old = self.notes.get(nid)
        self._jpush(("note", nid, dict(old) if old is not None else None))
        self._note_raw_put(nid, {"owner": owner, "face": face})

    def _note_del(self, nid):
        self._jpush(("note", nid, dict(self.notes[nid])))
        self._note_raw_del(nid)

    def _note_owner(self, nid, owner):
        n = self.notes[nid]
        self._jpush(("note", nid, dict(n)))
        self._note_raw_put(nid, {"owner": owner, "face": n["face"]})

    def _mset(self, name, k, v):
        d = getattr(self, name)
        self._jpush(("map", name, k, d.get(k, _MISSING)))
        d[k] = v
        self._mdig[name] = None

    def _mdel(self, name, k):
        d = getattr(self, name)
        self._jpush(("map", name, k, d.pop(k)))
        self._mdig[name] = None

    def _lappend(self, name, v):
        self._jpush(("lappend", name))
        getattr(self, name).append(v)
        self._mdig[name] = None

    def _lpop0(self, name):
        v = getattr(self, name).pop(0)
        self._jpush(("lpop0", name, v))
        self._mdig[name] = None
        return v

    def _sset(self, name, v):
        self._jpush(("scalar", name, getattr(self, name)))
        setattr(self, name, v)

    def _sadd(self, name, dv):
        self._sset(name, getattr(self, name) + dv)

    def _reg_mark(self):
        if self._journal is not None and not self._reg_marked:
            self._jpush(("reg", self.reg.snap()))
            self._reg_marked = True

    def _rollback(self, mark=0):
        j = self._journal
        while len(j) > mark:
            rec = j.pop()
            kind = rec[0]
            if kind == "note":
                _, nid, old = rec
                if old is None:
                    self._note_raw_del(nid)
                else:
                    self._note_raw_put(nid, old)
            elif kind == "map":
                _, name, k, old = rec
                d = getattr(self, name)
                if old is _MISSING:
                    d.pop(k, None)
                else:
                    d[k] = old
                self._mdig[name] = None
            elif kind == "lappend":
                getattr(self, rec[1]).pop()
                self._mdig[rec[1]] = None
            elif kind == "lpop0":
                getattr(self, rec[1]).insert(0, rec[2])
                self._mdig[rec[1]] = None
            elif kind == "scalar":
                setattr(self, rec[1], rec[2])
            elif kind == "reg":
                self.reg.restore(rec[1])
                self._reg_marked = False

    def _touched(self):
        """저널에서 touched 키 집합 — 국소 불변식의 대상."""
        t = {"note": set(), "map": {}}
        for rec in self._journal:
            if rec[0] == "note":
                t["note"].add(rec[1])
            elif rec[0] == "map":
                t["map"].setdefault(rec[1], set()).add(rec[2])
        return t

    # ── 노트·의무 헬퍼(법 문언 승계) ──
    def _mint(self, owner, face, voluntary=False):
        if not _pos_int(face):
            raise Fl23Error("mint: 액면 ≥ 1 정수")
        cap = self.GEN["notes_per_owner_max"]
        if voluntary and cap > 0 and len(self._by_owner.get(owner, ())) + 1 > cap:
            raise Fl23Error(f"노트-수 상한({cap}) — {owner} 의 유통 노트가 상한이다"
                            f"(MERGE 로 슬롯을 회수하라)")
        nid = str(self.note_ctr)
        self._sset("note_ctr", self.note_ctr + 1)
        self._note_set(nid, owner, face)
        return nid

    def bal(self, a):
        return self._owner_face.get(a, 0)

    def obl(self, a):
        return (sum(1 for o in self.room_owner.values() if o == a)
                + sum(1 for rp in self.redeem_pending.values() if rp["anchor"] == a)
                + sum(1 for c in self.uw_open.values() if c["uw"] == a))

    def _own(self, nid, a):
        n = self.notes.get(nid)
        return n is not None and n["owner"] == a

    def _real(self, a):
        return self.reg.pk(a) is not None and a not in self.exited

    def _consume(self, ids, a, exact):
        if len(set(ids)) != len(ids):
            raise Fl23Error("노트 중복 지정")
        tot = 0
        for nid in ids:
            if not self._own(nid, a):
                raise Fl23Error(f"노트 {nid}는 {a} 소유 아님")
            tot += self.notes[nid]["face"]
        if exact is not None and tot != exact:
            raise Fl23Error(f"액면 합 {tot} ≠ 요구 {exact}(SPLIT 선행)")
        for nid in ids:
            self._note_del(nid)
        return tot

    # ── 정산 폭포 헬퍼(U-2 — 전부 결정론 · 문언 승계) ──
    def _prorate(self, avail, needs):
        tot = sum(needs.values())
        if tot <= avail:
            return dict(needs)
        out = {r: avail * n // tot for r, n in needs.items()}
        left = avail - sum(out.values())
        for r in sorted(needs):
            if left <= 0:
                break
            if out[r] < needs[r]:
                out[r] += 1
                left -= 1
        return out

    def _seize(self, q, amount, change_nids):
        """자유-잔고 소구 — q 의 자유 노트를 정렬 순으로 소비하고 잔돈을 재발행(★J-9 잔돈 nid 기록)."""
        if amount <= 0:
            return 0
        ids = sorted(self._by_owner.get(q, ()), key=int)
        take, tot = [], 0
        for nid in ids:
            if tot >= amount:
                break
            take.append(nid)
            tot += self.notes[nid]["face"]
        if not take:
            return 0
        for nid in take:
            self._note_del(nid)
        got = min(tot, amount)
        if tot > got:
            change_nids.append(self._mint(q, tot - got))
        return got

    def _close_cov(self, ref):
        c = self.uw_open.get(ref)
        if c:
            for nid in c["cov"]:
                self._note_owner(nid, c["uw"])
            self._mdel("uw_open", ref)

    def _settle(self):
        """S-1 시한-사고 일괄 정산 — FL2.2 문언 승계 + ★J-9 민트-nid 명시."""
        T = self.GEN["redeem_T"]
        if T <= 0:
            return None
        matured = sorted(ref for ref, rp in self.redeem_pending.items()
                         if rp["failed"] or
                         (self.epoch - rp["t0"]) >= rp.get("T", T))
        if not matured:
            return None
        returned, returned_nids, covered, change_nids = [], [], [], []
        for ref in matured:
            if ref in self.uw_open:
                covered.append(ref)
                continue
            rp = self.redeem_pending[ref]
            self._mdel("redeem_pending", ref)
            self._note_owner(rp["nid"], rp["holder"])
            returned.append(ref)                              # FL2.2 형태 유지(소비자 무-churn)
            returned_nids.append({"ref": ref, "nid": rp["nid"]})   # ★J-9 민트/반환 nid 명시
        settled = []
        if covered:
            need = {r: self.notes[self.redeem_pending[r]["nid"]]["face"] for r in covered}
            rem = dict(need)
            paid = {r: {"anchor": 0, "cov": 0, "uw": 0, "fund": 0} for r in covered}
            by_anchor = {}
            for r in covered:
                by_anchor.setdefault(self.redeem_pending[r]["anchor"], []).append(r)
            for a in sorted(by_anchor):
                grp = [r for r in by_anchor[a] if rem[r] > 0]
                if not grp:
                    continue
                alloc = self._prorate(self.bal(a), {r: rem[r] for r in grp})
                self._seize(a, sum(alloc.values()), change_nids)
                for r in grp:
                    paid[r]["anchor"] += alloc[r]
                    rem[r] -= alloc[r]
            for r in covered:
                c = self.uw_open[r]
                tot = sum(self.notes[n]["face"] for n in c["cov"])
                for n in c["cov"]:
                    self._note_del(n)
                self._mset("uw_open", r, {**c, "cov": []})
                take = min(tot, rem[r])
                if tot - take > 0:
                    change_nids.append(self._mint(c["uw"], tot - take))
                paid[r]["cov"] += take
                rem[r] -= take
            by_uw = {}
            for r in covered:
                by_uw.setdefault(self.uw_open[r]["uw"], []).append(r)
            for u in sorted(by_uw):
                grp = [r for r in by_uw[u] if rem[r] > 0]
                if not grp:
                    continue
                alloc = self._prorate(self.bal(u), {r: rem[r] for r in grp})
                self._seize(u, sum(alloc.values()), change_nids)
                for r in grp:
                    paid[r]["uw"] += alloc[r]
                    rem[r] -= alloc[r]
            grp = [r for r in covered if rem[r] > 0]
            if grp:
                demand = sum(rem[r] for r in grp)
                self._sset("F_peak", max(self.F_peak, demand))
                alloc = self._prorate(self.F_uw, {r: rem[r] for r in grp})
                for r in grp:
                    self._sadd("F_uw", -alloc[r])
                    paid[r]["fund"] += alloc[r]
                    rem[r] -= alloc[r]
            for r in covered:
                rp = self.redeem_pending[r]
                self._mdel("redeem_pending", r)
                self._mdel("uw_open", r)
                comp = need[r] - rem[r]
                comp_nid = self._mint(rp["holder"], comp) if comp > 0 else None
                self._sadd("S", self._consume([rp["nid"]], f"@redeem:{r}", None))
                settled.append({"ref": r, "comp": comp, "short": rem[r],
                                "comp_nid": comp_nid, **paid[r]})
        return {"returned": returned, "settled": settled,
                "returned_nids": returned_nids, "change_nids": change_nids}

    # ── 정준 상태·서명 ──
    def _gen_root(self):
        return hashlib.sha256(_canon(dict(self.GEN))).hexdigest()

    def _bucket_digest(self, b):
        if self._bkt[b] is None:
            items = [[nid, self.notes[nid]["owner"], self.notes[nid]["face"]]
                     for nid in sorted(self._bkt_members[b], key=int)]
            self._bkt[b] = hashlib.sha256(_canon(items)).hexdigest()
        return self._bkt[b]

    def _notes_root(self):
        h = hashlib.sha256()
        for b in range(_BUCKETS):
            h.update(bytes.fromhex(self._bucket_digest(b)))
        return h.hexdigest()

    def _map_digest(self, name):
        if self._mdig.get(name) is None:
            self._mdig[name] = hashlib.sha256(_canon(getattr(self, name))).hexdigest()
        return self._mdig[name]

    def state_root(self):
        """★J-5 — 버킷 증분 커밋먼트. 값은 FL2.2 정의와 다르다(세대 · DOMAIN 결박)."""
        st = {"notes_root": self._notes_root(),
              "scalars": {s: getattr(self, s) for s in self._SCALARS},
              "fp": self.reg.fp, "pk_root": self.reg.pk_root(),
              "gen_root": self._gen_root(), "bridge_ref": self.bridge_ref}
        for name in self._MAPS + self._LISTS:
            st[name + "_root"] = self._map_digest(name)
        return hashlib.sha256(FL23_DOMAIN + _canon(st)).hexdigest()

    def _root_full(self):
        """캐시 전량 무효화 후 재계산(검증자 시작점·audit 종단 대조)."""
        self._bkt = [None] * _BUCKETS
        self._mdig = {}
        return self.state_root()

    def _sig_msg(self, body, nonce):
        return (FL23_DOMAIN + self.log_id + _canon(body)
                + int(nonce).to_bytes(8, "big"))

    def sign_env(self, principal, typ, args, epoch=None, nonce=None):
        n = self.nonces.get(principal, 0) if nonce is None else nonce
        body = {"typ": typ, "args": args, "p": principal,
                "epoch": self.epoch if epoch is None else epoch}
        sig = self._keys[principal].sign(self._sig_msg(body, n))
        return {**body, "nonce": n, "sig": sig.hex()}

    def rekey_msg(self, principal, new_pk_bytes):
        """★J-4 소유-증명 메시지(새 키가 서명) — old_pk 결박으로 회전마다 유일."""
        return (FL23_DOMAIN + self.log_id + b"REKEY" + principal.encode()
                + bytes(new_pk_bytes) + self.reg.pk(principal))

    def rekey_local(self, principal, new_priv):
        """서명 세계용 — 레지스트리 무접촉(REKEY 커밋 뒤 노드가 호출)."""
        self._keys[principal] = new_priv

    # ── 불변식 ──
    def _invariants_local(self, t):
        """★J-5 — touched 한정 국소 불변식 + 누계 보존식(O(변경))."""
        if self._face_total + self.F + self.F_uw + self.S != self.ext_in - self.ext_out:
            raise Fl23Error(f"법 ②: 보존 붕괴 {self._face_total + self.F + self.F_uw + self.S}"
                            f" != {self.ext_in - self.ext_out}")
        if min(self.F, self.F_uw, self.F_peak, self.S, self.ext_in, self.ext_out) < 0:
            raise Fl23Error("음수 회계 항목")
        for nid in t["note"]:
            n = self.notes.get(nid)
            if n is None:
                continue
            if not _pos_int(n["face"]):
                raise Fl23Error("노트 액면 ≥ 1 위반")
            o = n["owner"]
            if o.startswith("@room:") and o[6:] not in self.locked_rooms:
                raise Fl23Error(f"구조: 고아 방-에스크로 노트 {nid}")
            if o.startswith("@redeem:") and o[8:] not in self.redeem_pending:
                raise Fl23Error(f"구조: 고아 상환-에스크로 노트 {nid}")
            if o.startswith("@uw:") and o[4:] not in self.uw_open:
                raise Fl23Error(f"구조: 고아 담보-에스크로 노트 {nid}")
        rids = t["map"].get("locked_rooms", set()) | t["map"].get("room_owner", set())
        for rid in rids:
            if (rid in self.locked_rooms) != (rid in self.room_owner):
                raise Fl23Error("구조: room_owner ↔ locked_rooms 키 불일치")
            if rid in self.locked_rooms and any(
                    self.notes.get(i, {}).get("owner") != f"@room:{rid}"
                    for i in self.locked_rooms[rid]):
                raise Fl23Error(f"구조: 방 {rid} 에스크로 노트 소유 어긋남")
        refs = t["map"].get("redeem_pending", set()) | t["map"].get("uw_open", set())
        for ref in refs:
            if ref in self.uw_open and ref not in self.redeem_pending:
                raise Fl23Error("구조: 청구 없는 커버리지(uw_open ⊄ redeem_pending)")
            rp = self.redeem_pending.get(ref)
            if rp is not None:
                if self.notes.get(rp["nid"], {}).get("owner") != f"@redeem:{ref}":
                    raise Fl23Error(f"구조: 상환 {ref} 에스크로 노트 소유 어긋남")
                if rp["t0"] > self.epoch or not isinstance(rp["failed"], bool):
                    raise Fl23Error(f"구조: 상환 {ref} 시계·판정 필드 이상")
                _t = rp.get("T")
                if _t is not None and not _pos_int(_t):
                    raise Fl23Error(f"구조: 상환 {ref} T 필드 이상")
            c = self.uw_open.get(ref)
            if c is not None and any(self.notes.get(i, {}).get("owner") != f"@uw:{ref}"
                                     for i in c["cov"]):
                raise Fl23Error(f"구조: 커버리지 {ref} 에스크로 소유 어긋남")
        qp = self.GEN["qual_price"]
        for a in t["map"].get("Q", set()) | t["map"].get("qual_burn", set()):
            if self.Q.get(a, 0) * qp > self.qual_burn.get(a, 0):
                raise Fl23Error(f"법 ①: 자격 보존 붕괴 {a}")

    def _invariants(self):
        """전-상태 불변식(FL2.2 문언) — audit()·리플레이 종단·게이트에서만."""
        face = sum(n["face"] for n in self.notes.values())
        if any(not _pos_int(n["face"]) for n in self.notes.values()):
            raise Fl23Error("노트 액면 ≥ 1 위반")
        total = face + self.F + self.F_uw + self.S
        if total != self.ext_in - self.ext_out:
            raise Fl23Error(f"법 ②: 보존 붕괴 {total} != {self.ext_in - self.ext_out}")
        if face != self._face_total:
            raise Fl23Error("색인: 누계 불일치")
        qp = self.GEN["qual_price"]
        for a, q in self.Q.items():
            if q * qp > self.qual_burn.get(a, 0):
                raise Fl23Error(f"법 ①: 자격 보존 붕괴 {a}")
        if min(self.F, self.F_uw, self.F_peak, self.S, self.ext_in, self.ext_out) < 0:
            raise Fl23Error("음수 회계 항목")
        if set(self.room_owner) != set(self.locked_rooms):
            raise Fl23Error("구조: room_owner ↔ locked_rooms 키 불일치")
        if not set(self.uw_open) <= set(self.redeem_pending):
            raise Fl23Error("구조: 청구 없는 커버리지(uw_open ⊄ redeem_pending)")
        for nid, n in self.notes.items():
            o = n["owner"]
            if o.startswith("@room:") and o[6:] not in self.locked_rooms:
                raise Fl23Error(f"구조: 고아 방-에스크로 노트 {nid}")
            if o.startswith("@redeem:") and o[8:] not in self.redeem_pending:
                raise Fl23Error(f"구조: 고아 상환-에스크로 노트 {nid}")
            if o.startswith("@uw:") and o[4:] not in self.uw_open:
                raise Fl23Error(f"구조: 고아 담보-에스크로 노트 {nid}")
        for rid, ids in self.locked_rooms.items():
            if any(self.notes.get(i, {}).get("owner") != f"@room:{rid}" for i in ids):
                raise Fl23Error(f"구조: 방 {rid} 에스크로 노트 소유 어긋남")
        for ref, rp in self.redeem_pending.items():
            if self.notes.get(rp["nid"], {}).get("owner") != f"@redeem:{ref}":
                raise Fl23Error(f"구조: 상환 {ref} 에스크로 노트 소유 어긋남")
            if rp["t0"] > self.epoch or not isinstance(rp["failed"], bool):
                raise Fl23Error(f"구조: 상환 {ref} 시계·판정 필드 이상")
            _t = rp.get("T")
            if _t is not None and not _pos_int(_t):
                raise Fl23Error(f"구조: 상환 {ref} T 필드 이상")
        for ref, c in self.uw_open.items():
            if any(self.notes.get(i, {}).get("owner") != f"@uw:{ref}" for i in c["cov"]):
                raise Fl23Error(f"구조: 커버리지 {ref} 에스크로 소유 어긋남")

    # ── ★J-8 입력-스키마 전문 ──
    @staticmethod
    def _bound(v, depth=0, list_max=_LIST_MAX):
        if depth > _DEPTH_MAX:
            raise Fl23Error("스키마: 중첩 깊이 초과")
        if v is None or isinstance(v, bool):
            return
        if isinstance(v, int):
            if abs(v) >= 1 << 63:
                raise Fl23Error("스키마: 정수 범위")
            return
        if isinstance(v, str):
            if len(v) > _STR_MAX:
                raise Fl23Error(f"스키마: 문자열 > {_STR_MAX}")
            return
        if isinstance(v, list):
            if len(v) > list_max:
                raise Fl23Error(f"스키마: 리스트-인자 {len(v)} > 상한 {list_max}")
            for x in v:
                World._bound(x, depth + 1, list_max)
            return
        if isinstance(v, dict):
            if len(v) > max(_ARGS_KEYS_MAX, list_max if depth == 0 else _ARGS_KEYS_MAX):
                raise Fl23Error("스키마: 키 수 초과")
            for k, x in v.items():
                if not isinstance(k, str) or len(k) > 64:
                    raise Fl23Error("스키마: 키 형식")
                World._bound(x, depth + 1, list_max)
            return
        raise Fl23Error(f"스키마: 허용되지 않는 값 타입 {type(v).__name__}")

    @staticmethod
    def _env_shape(env, what="봉투"):
        if not isinstance(env, dict) or set(env) != {"typ", "args", "p", "epoch", "nonce", "sig"}:
            raise Fl23Error(f"스키마: {what} 필드 집합")
        if env["typ"] not in OPS:
            raise Fl23Error(f"미지 타입 {env['typ']} — 경로 밖 연산은 없다")
        if not (isinstance(env["p"], str) and 1 <= len(env["p"]) <= 64):
            raise Fl23Error(f"스키마: {what} 주체명")
        if not _nonneg_int(env["epoch"]) or not _nonneg_int(env["nonce"]):
            raise Fl23Error(f"스키마: {what} epoch/nonce")
        if not (isinstance(env["sig"], str) and len(env["sig"]) == 128):
            raise Fl23Error(f"스키마: {what} 서명 형식")
        if not isinstance(env["args"], dict):
            raise Fl23Error(f"스키마: {what} args 는 객체")

    @classmethod
    def _schema(cls, env, nested=False):
        typ, args = env["typ"], env["args"]
        if nested and typ in _NO_NEST:
            raise Fl23Error(f"스키마: {typ} 은 다리/내부에 올 수 없다")
        lm = _IMPORT_MAX if typ == "GENESIS_IMPORT" else _LIST_MAX
        cls._bound(args, 0, lm)
        for fld, kind in REQ[typ].items():
            if fld not in args:
                raise Fl23Error(f"스키마: {typ}.{fld} 필수")
            v = args[fld]
            ok = {_S: isinstance(v, str), _I: _nonneg_int(v) or (isinstance(v, int) and not isinstance(v, bool)),
                  _L: isinstance(v, list), _D: isinstance(v, dict)}[kind]
            if not ok:
                raise Fl23Error(f"스키마: {typ}.{fld} 타입({kind})")
        if typ == "BLOCK":
            legs = args["legs"]
            if not 1 <= len(legs) <= _BLOCK_LEGS_MAX:
                raise Fl23Error(f"스키마: BLOCK 다리 1~{_BLOCK_LEGS_MAX}")
            for lg in legs:
                cls._env_shape(lg, "다리")
                cls._schema(lg, nested=True)
        # REQUEST/FORCE 내부 봉투는 여기서 검사하지 않는다 — FL2.2 법 문언 승계(「REQUEST 는 검열저항을
        # 위해 inner 를 미검증 적재」) · 형태·스키마 검사는 FORCE 시점 _force_apply 안에서(실패 = included:False
        # + 세이브포인트 롤백 · FORCE 자체는 거부되지 않으므로 _drain 이 웨지되지 않는다 — F-K1).

    # ── 단일 강제 기입 경로 ──
    def submit(self, env):
        self._drain()
        return self._commit(env)

    def request(self, inner_env):
        return self._commit(self.sign_env("operator", "REQUEST", {"inner": inner_env}))

    def tick(self):
        self._commit(self.sign_env("operator", "TICK", {}))
        self._drain()

    def _drain(self):
        L = self.GEN["window_L"]
        while self.pending and (self.epoch - self.pending[0][0]) >= L:
            self._commit(self.sign_env("operator", "FORCE",
                                       {"inner": self.pending[0][1]}))

    def _verify_env(self, env, window=True):
        p = env["p"]
        body = {k: env[k] for k in ("typ", "args", "p", "epoch")}
        pk = self.reg.pk(p)
        if pk is None:
            raise Fl23Error(f"신원: 미지 주체 {p}(체인 밖)")
        if p in self.exited and env["typ"] not in ("REQUEST", "TICK", "FORCE"):
            raise Fl23Error(f"퇴장 신원 {p}은 발화 불가")
        try:
            Ed25519PublicKey.from_public_bytes(pk).verify(
                bytes.fromhex(env["sig"]), self._sig_msg(body, env["nonce"]))
        except (InvalidSignature, ValueError, TypeError):
            raise Fl23Error(f"서명 검증 실패: {p} {env['typ']}")
        if env["nonce"] != self.nonces.get(p, 0):
            raise Fl23Error(f"nonce 위반: {p}")
        if window:
            if env["epoch"] > self.epoch:
                raise Fl23Error(f"법 ③: 선행 기입 {env['epoch']} > {self.epoch}")
            if self.epoch - env["epoch"] > self.GEN["window_L"]:
                raise Fl23Error(f"법 ④: 창 밖 소급 {env['epoch']} ≪ {self.epoch}")

    def _head(self, prev, entry, fields):
        return hashlib.sha256(prev.encode() + _canon({k: entry[k] for k in fields})).hexdigest()

    def _commit(self, env, replay=False):
        # ① 형태(무상태 · 무기록) → ② 인증(서명·nonce · 무기록) → ③ 창 → 스키마 → _apply(★J-7 기록 대상)
        try:
            self._env_shape(env)
        except Fl23Error:
            raise
        except Exception as e:
            raise Fl23Error(f"봉투 형식: {type(e).__name__}")
        try:
            self._verify_env(env, window=False)
        except Fl23Error:
            raise
        except Exception as e:
            raise Fl23Error(f"봉투 형식: {type(e).__name__}")
        p, typ, args = env["p"], env["typ"], env["args"]
        self._journal, self._reg_marked = [], False
        force_outcome = None
        try:
            if env["epoch"] > self.epoch:
                raise Fl23Error(f"법 ③: 선행 기입 {env['epoch']} > {self.epoch}")
            if self.epoch - env["epoch"] > self.GEN["window_L"]:
                raise Fl23Error(f"법 ④: 창 밖 소급 {env['epoch']} ≪ {self.epoch}")
            self._schema(env)
            force_outcome = self._apply(typ, args, p)
            self._mset("nonces", p, env["nonce"] + 1)
            self._invariants_local(self._touched())
        except Exception as e:
            self._rollback(0)
            self._journal = None
            err = e if isinstance(e, Fl23Error) else \
                Fl23Error(f"비정규 예외 거부({typ}): {type(e).__name__}: {e}")
            if p != "operator":                       # ★J-7 — 인증된 거부는 기록 · nonce 소비
                self._reject_entry(env, str(err), replay)
            raise err
        if self._txn is not None:
            self._txn["recs"].extend(self._journal)
        self._journal = None
        entry = {"seq": len(self.log), "env": env, "fp": self.reg.fp,
                 "w_epoch": self.epoch, "state_root": self.state_root(),
                 "prev": self.log[-1]["head"] if self.log else "genesis"}
        if force_outcome is not None:
            entry["_force"] = force_outcome
        fields = ("env", "fp", "w_epoch", "state_root") + (("_force",) if force_outcome is not None else ())
        entry["head"] = self._head(entry["prev"], entry, fields)
        if not replay:
            entry["head_sig"] = self._keys["operator"].sign(
                FL23_DOMAIN + bytes.fromhex(entry["head"])).hex()
        self.log.append(entry)
        return entry

    def _reject_entry(self, env, reason, replay):
        p = env["p"]
        if self._txn is not None:
            self._txn["recs"].append(("map", "nonces", p, self.nonces.get(p, _MISSING)))
        self.nonces[p] = env["nonce"] + 1
        self._mdig["nonces"] = None
        entry = {"seq": len(self.log), "kind": "REJECT", "env": env, "fp": self.reg.fp,
                 "w_epoch": self.epoch, "state_root": self.state_root(),
                 "prev": self.log[-1]["head"] if self.log else "genesis",
                 "reason": reason[:REJECT_REASON_MAX]}
        entry["head"] = self._head(entry["prev"], entry, ("env", "fp", "w_epoch", "state_root", "kind"))
        if not replay:
            entry["head_sig"] = self._keys["operator"].sign(
                FL23_DOMAIN + bytes.fromhex(entry["head"])).hex()
        self.log.append(entry)
        return entry

    # ── ★서비스층 다중-커밋 원자 구간(deepcopy 없음 — J-5 보존) ──
    def begin_txn(self):
        """여러 submit 을 하나의 원자 단위로: 실패 시 rollback_txn() 이 그 사이의 모든 변이(REJECT 항·nonce 포함)를
        되감고 로그를 잘라낸다. r1 의 EXT_IN↔BLOCK(bootstrap)·요청↔발행(issue) 원자성이 여기 선다."""
        if self._txn is not None:
            raise Fl23Error("txn: 중첩 불가")
        self._txn = {"recs": [], "log_len": len(self.log), "reg": self.reg.snap()}

    def commit_txn(self):
        self._txn = None

    def rollback_txn(self):
        t = self._txn
        if t is None:
            return
        self._txn = None
        saved, self._journal = self._journal, t["recs"]
        try:
            self._rollback(0)
        finally:
            self._journal = saved
        self.reg.restore(t["reg"])
        del self.log[t["log_len"]:]
        self._mdig = {}

    def _force_apply(self, inner):
        if not self.pending or self.pending[0][1] != inner:
            raise Fl23Error("FORCE: pending 선두 불일치")
        self._lpop0("pending")
        mark = len(self._journal)
        authed = False
        try:
            self._env_shape(inner, "내부 봉투")
            self._verify_env(inner, window=False)    # 법 ⑦이 법 ④를 넘긴다
            authed = True
            self._schema(inner, nested=True)
            self._apply(inner["typ"], inner["args"], inner["p"])
            self._mset("nonces", inner["p"], inner["nonce"] + 1)
            return {"included": True, "typ": inner["typ"]}
        except Exception as e:
            self._rollback(mark)                      # ★세이브포인트(F-K1 봉합) — 부분-변이 0
            if authed and inner["p"] != "operator":   # ★J-7 — 인증된 내부 실패도 nonce 소비
                self._mset("nonces", inner["p"], inner["nonce"] + 1)
            return {"included": False, "why": f"{type(e).__name__}: {e}"[:60],
                    "typ": inner.get("typ", "?") if isinstance(inner, dict) else "?"}

    def _apply(self, typ, args, p):
        g = self.GEN
        for fld in _MONEY_FIELDS.get(typ, ()):
            if not _nonneg_int(args.get(fld)):
                raise Fl23Error(f"{typ}.{fld}: 음수/비정수 금액 거부")

        if typ == "REQUEST":
            if p != "operator":
                raise Fl23Error("REQUEST: 시퀀서 좌석")
            self._lappend("pending", [self.epoch, args["inner"]])
        elif typ == "TICK":
            if p != "operator":
                raise Fl23Error("TICK: 시퀀서 좌석")
            self._sset("epoch", self.epoch + 1)
            return self._settle()
        elif typ == "FORCE":
            if p != "operator":
                raise Fl23Error("FORCE: 시퀀서 좌석")
            return self._force_apply(args["inner"])
        elif typ == "JOIN":
            if p != "operator":
                raise Fl23Error("JOIN: 운영자 좌석 후원")
            new = args["principal"]
            if new.startswith("@"):
                raise Fl23Error("JOIN: 예약 접두 '@' 주체 거부")
            if self.reg.pk(new) is not None:
                raise Fl23Error(f"JOIN: {new} 재등록 거부(이름 재사용 불가 — 이력-세탁 차단)")
            # ★J-3 생존-상한: 퇴장 슬롯은 되돌아온다(이름 재사용은 reg 가 거부)
            if self.reg.size() - len(self.SEATS) - len(self.exited) >= g["identity_budget"]:
                raise Fl23Error("JOIN: identity_budget 소진")
            self._reg_mark()
            self.reg.extend(new, _hexbytes(args["pk"], 32, "JOIN.pk"))
            for d in ("qual_burn", "Q"):
                if new not in getattr(self, d):
                    self._mset(d, new, 0)
        elif typ == "EXIT":
            a = args["a"]
            if p != a:
                raise Fl23Error("EXIT: 행위자 = 본인")
            if self.obl(a) > 0:
                raise Fl23Error(f"EXIT: 미결 의무 {self.obl(a)}")
            if self.bal(a) > 0:
                raise Fl23Error(f"EXIT: 잔여 노트 {self.bal(a)}")
            if any(rp["holder"] == a for rp in self.redeem_pending.values()):
                raise Fl23Error("EXIT: 미결 상환(holder) — 회수 불가 방지")
            if a in self.exited:
                raise Fl23Error("EXIT: 이미 퇴장")
            self._lappend("exited", a)
        elif typ == "EXT_IN":
            if p != "operator":
                raise Fl23Error("EXT_IN: 유입 문 = 운영자-서명 법 사건")
            if not self._real(args["to"]):
                raise Fl23Error("EXT_IN: 대상이 미등록/퇴장")
            self._sadd("ext_in", args["amount"])
            self._mint(args["to"], args["amount"], voluntary=True)
        elif typ == "EXT_IN_POOL":
            if p != "operator":
                raise Fl23Error("EXT_IN_POOL: 운영자-서명")
            pool, claims = args["pool"], args["claims"]
            if not all(_nonneg_int(v) for v in claims.values()):
                raise Fl23Error("EXT_IN_POOL: 음수 청구")
            if not all(self._real(a) for a in claims):
                raise Fl23Error("EXT_IN_POOL: 미등록/퇴장 청구자")
            tot = sum(claims.values())
            if tot == 0:
                raise Fl23Error("EXT_IN_POOL: 청구 총합 0")
            self._sadd("ext_in", pool)
            rem = pool
            for a in sorted(claims):
                alloc = (pool * claims[a] // tot) if tot > pool else claims[a]
                alloc = min(alloc, rem)
                if alloc > 0:
                    self._mint(a, alloc, voluntary=True)
                rem -= alloc
            self._sadd("F", rem)
        elif typ == "EXT_OUT":
            a, nid = args["frm"], args["note"]
            if p != a:
                raise Fl23Error("EXT_OUT: 행위자 = 보유자")
            if self.obl(a) > 0:
                raise Fl23Error(f"유출 문: {a} 미결 의무 — 후순위")
            face = self._consume([nid], a, None)
            self._sadd("ext_out", face)
        elif typ == "XFER":
            frm, to, nid = args["frm"], args["to"], args["note"]
            if p != frm:
                raise Fl23Error("XFER: 행위자 = 보유자")
            if not self._real(to):
                raise Fl23Error("XFER: 수취인 무효")
            if not self._own(nid, frm):
                raise Fl23Error("XFER: 미소유 노트")
            self._note_owner(nid, to)
        elif typ == "SPLIT":
            owner, nid, parts = args["owner"], args["note"], args["parts"]
            if p != owner:
                raise Fl23Error("SPLIT: 행위자 = 보유자")
            if not all(_pos_int(x) for x in parts) or len(parts) < 2:
                raise Fl23Error("SPLIT: 부분 ≥ 1 정수 · 둘 이상")
            face = self._consume([nid], owner, None)
            if sum(parts) != face:
                raise Fl23Error(f"SPLIT: 부분 합 {sum(parts)} ≠ 액면 {face}")
            for f in parts:
                self._mint(owner, f, voluntary=True)
        elif typ == "MERGE":
            owner, ids = args["owner"], args["notes"]
            if p != owner:
                raise Fl23Error("MERGE: 행위자 = 보유자")
            if len(ids) < 2:
                raise Fl23Error("MERGE: 둘 이상")
            self._mint(owner, self._consume(ids, owner, None), voluntary=True)
        elif typ == "BURN":
            owner, nid = args["owner"], args["note"]
            if p != owner:
                raise Fl23Error("BURN: 행위자 = 보유자")
            self._sadd("S", self._consume([nid], owner, None))
        elif typ == "QUAL_BUY":
            a, ids = args["a"], args["notes"]
            if p != a:
                raise Fl23Error("QUAL_BUY: 행위자 = 취득자")
            self._sadd("S", self._consume(ids, a, g["qual_price"]))
            self._mset("qual_burn", a, self.qual_burn.get(a, 0) + g["qual_price"])
            self._mset("Q", a, self.Q.get(a, 0) + 1)
        elif typ == "OPEN":
            owner, rid, ids = args["owner"], args["rid"], args["notes"]
            c, phi = g["room_c"], g["room_phi"]
            if p != owner:
                raise Fl23Error("OPEN: 행위자 = 소유자")
            if rid in self.locked_rooms:
                raise Fl23Error("OPEN: rid 중복")
            self._consume(ids, owner, c + phi)
            esc = self._mint(f"@room:{rid}", c)
            self._mset("locked_rooms", rid, [esc])
            self._mset("room_owner", rid, owner)
            self._sadd("F", phi)
        elif typ == "CLOSE":
            rid, owner, perf = args["rid"], args["owner"], args["performer"]
            if rid not in self.locked_rooms:
                raise Fl23Error("CLOSE: 미지 방")
            if self.room_owner.get(rid) != owner or p != owner:
                raise Fl23Error("CLOSE: 소유권 불일치")
            if self.reg.pk(perf) is None or perf in self.exited:
                raise Fl23Error("CLOSE: 수임자 무효")
            for nid in self.locked_rooms[rid]:
                self._note_owner(nid, perf)
            self._mdel("locked_rooms", rid)
            self._mdel("room_owner", rid)
        elif typ == "REDEEM":
            holder, nid, anchor = args["holder"], args["note"], args["anchor"]
            if p != holder:
                raise Fl23Error("REDEEM: 행위자 = 보유자")
            if not self._real(anchor):
                raise Fl23Error("REDEEM: 앵커 무효")
            if not self._own(nid, holder):
                raise Fl23Error("REDEEM: 미소유 노트")
            ref = hashlib.sha256(f"{self.log_id.hex()}|{nid}|{self.epoch}".encode()
                                 ).hexdigest()[:16]
            if ref in self.redeem_pending:
                raise Fl23Error("REDEEM: ref 중복")
            Tj = args.get("T")
            if Tj is not None:
                if g["redeem_T"] <= 0:
                    raise Fl23Error("REDEEM.T: 사고-채널 OFF 세계에선 잡별 시한 불허")
                if not _pos_int(Tj):
                    raise Fl23Error("REDEEM.T: 양의 정수")
                if Tj <= g["window_L"]:
                    raise Fl23Error("REDEEM.T: T_j > window_L 필수"
                                    "(강제-포함이 시한을 이긴다 — 법-조항)")
                if g["redeem_T_max"] > 0 and Tj > g["redeem_T_max"]:
                    raise Fl23Error(f"REDEEM.T: T_j ≤ redeem_T_max({g['redeem_T_max']})")
            self._note_owner(nid, f"@redeem:{ref}")
            self._mset("redeem_pending", ref, {"holder": holder, "nid": nid,
                                               "anchor": anchor, "t0": self.epoch,
                                               "failed": False,
                                               "T": Tj if Tj is not None
                                               else (g["redeem_T"] if g["redeem_T"] > 0
                                                     else None)})
        elif typ == "DELIVER":
            anchor, ref = args["anchor"], args["ref"]
            if p != anchor:
                raise Fl23Error("DELIVER: 행위자 = 앵커")
            rp = self.redeem_pending.get(ref)
            if rp is None or rp["anchor"] != anchor:
                raise Fl23Error("DELIVER: 미지 상환 청구")
            if rp["failed"]:
                raise Fl23Error("DELIVER: 실패 판정된 청구는 이행 종결 불가(정산 대기)")
            self._close_cov(ref)
            self._sadd("S", self._consume([rp["nid"]], f"@redeem:{ref}", None))
            self._mdel("redeem_pending", ref)
        elif typ == "REDEEM_CANCEL":
            ref = args["ref"]
            rp = self.redeem_pending.get(ref)
            if rp is None or p != rp["holder"]:
                raise Fl23Error("REDEEM_CANCEL: 청구자 아님")
            self._close_cov(ref)
            self._note_owner(rp["nid"], rp["holder"])
            self._mdel("redeem_pending", ref)
        elif typ == "UW":
            uwp, ref = args["uw"], args["ref"]
            cov_ids, prem = args["cov_notes"], args["prem"]
            fund_ids = args.get("prem_fund_notes", [])
            if p != uwp:
                raise Fl23Error("UW: 행위자 = 인수자")
            if g["redeem_T"] <= 0:
                raise Fl23Error("UW: 사고 채널 OFF 세계(redeem_T=0)에선 인수 없음")
            rp = self.redeem_pending.get(ref)
            if rp is None:
                raise Fl23Error("UW: 미지 상환 청구")
            if ref in self.uw_open:
                raise Fl23Error("UW: 이미 인수된 청구(v0.1 단일 인수)")
            if rp["failed"]:
                raise Fl23Error("UW: 이미 실패 판정된 청구")
            if uwp in (rp["holder"], rp["anchor"]):
                raise Fl23Error("UW: 자기-당사자 인수 금지(법 ⑤ 계보)")
            if rp["holder"] == rp["anchor"]:
                raise Fl23Error("UW: 자기-상환 청구는 인수 불가(법 ⑤ 계보)")
            if not _nonneg_int(prem):
                raise Fl23Error("UW: 보험료 비정수/음수")
            exposure = self.notes[rp["nid"]]["face"]
            if prem * g["prem_floor_den"] < exposure * g["prem_floor_num"]:
                raise Fl23Error("UW: 요율 하한 미달(prem_floor)")
            if not cov_ids or len(set(cov_ids)) != len(cov_ids):
                raise Fl23Error("UW: 담보 노트 공백/중복")
            if not isinstance(fund_ids, list):
                raise Fl23Error("UW: prem_fund_notes 는 리스트")
            if set(cov_ids) & set(fund_ids):
                raise Fl23Error("UW: 담보 노트와 기금 노트는 서로소여야 한다")
            cov = 0
            for nid in cov_ids:
                if not self._own(nid, uwp):
                    raise Fl23Error(f"UW: 담보 노트 {nid} 미소유")
                cov += self.notes[nid]["face"]
            if cov > exposure:
                raise Fl23Error("UW: β > 1(과담보) 금지 — β ∈ (0,1]")
            if cov * g["beta_min_den"] < exposure * g["beta_min_num"]:
                raise Fl23Error("UW: β_min 미달(인가 문턱)")
            prem_f = prem * g["uw_phi_num"] // g["uw_phi_den"]
            if g["fq_mult"] > 0 and \
               self.F_uw + prem_f > g["fq_mult"] * max(self.F_peak, g["fq_base"]):
                prem_f = 0
            self._sadd("F_uw", self._consume(fund_ids, uwp, prem_f))
            for nid in cov_ids:
                self._note_owner(nid, f"@uw:{ref}")
            self._mset("uw_open", ref, {"uw": uwp, "cov": list(cov_ids), "prem": prem})
        elif typ in ("ATTEST_OK", "ATTEST_FAIL"):
            if p != "operator":
                raise Fl23Error("ATTEST: v0.1 검증자 좌석 = operator(정직 한정어 ⓐ)")
            if g["redeem_T"] <= 0:
                raise Fl23Error("ATTEST: 사고 채널 OFF 세계(redeem_T=0)")
            ref = args["ref"]
            rp = self.redeem_pending.get(ref)
            if rp is None:
                raise Fl23Error("ATTEST: 미지 상환 청구")
            role = args.get("role")
            if role is not None and role not in ("producer", "attester"):
                raise Fl23Error("ATTEST: role ∈ {producer, attester}(선택 귀속 필드)")
            reason = args.get("reason")
            if not isinstance(reason, str) or not (1 <= len(reason) <= 64):
                raise Fl23Error("ATTEST: reason_code는 1~64자 문자열(발화지 판정 아님)")
            if typ == "ATTEST_FAIL":
                if rp["failed"]:
                    raise Fl23Error("ATTEST_FAIL: 이미 실패 기록")
                self._mset("redeem_pending", ref, {**rp, "failed": True})
        elif typ == "BLOCK":
            return self._apply_block(args["legs"], p)
        elif typ == "TICKMARK":
            pass
        elif typ == "REKEY":                          # ★J-4
            if args["principal"] != p:
                raise Fl23Error("REKEY: 본인 키만 회전한다")
            new_pk = _hexbytes(args["new_pk"], 32, "REKEY.new_pk")
            new_sig = _hexbytes(args["new_sig"], 64, "REKEY.new_sig")
            if self.reg.pk(p) is None:
                raise Fl23Error("REKEY: 미지 주체")
            try:
                Ed25519PublicKey.from_public_bytes(new_pk).verify(new_sig, self.rekey_msg(p, new_pk))
            except (InvalidSignature, ValueError):
                raise Fl23Error("REKEY: 새 키 소유-증명 실패")
            self._reg_mark()
            self.reg.rekey(p, new_pk)
        elif typ == "GENESIS_IMPORT":                 # ★J-11
            if p != "operator":
                raise Fl23Error("GENESIS_IMPORT: 운영자-서명")
            if self.log:
                raise Fl23Error("GENESIS_IMPORT: 첫 엔트리 전용")
            snap = {"principals": args["principals"], "notes": args["notes"],
                    "F": args["F"], "F_uw": args["F_uw"], "exited": args["exited"]}
            if hashlib.sha256(_canon(snap)).hexdigest() != args["snapshot_hash"]:
                raise Fl23Error("GENESIS_IMPORT: snapshot_hash 불일치")
            if not (_nonneg_int(args["F"]) and _nonneg_int(args["F_uw"])):
                raise Fl23Error("GENESIS_IMPORT: F/F_uw 비정수")
            names = []
            for it in args["principals"]:
                if not (isinstance(it, dict) and isinstance(it.get("p"), str)):
                    raise Fl23Error("GENESIS_IMPORT: principals 형식")
                if it["p"].startswith("@") or not (1 <= len(it["p"]) <= 64):
                    raise Fl23Error("GENESIS_IMPORT: 주체명")
                names.append(it["p"])
            if len(set(names)) != len(names):
                raise Fl23Error("GENESIS_IMPORT: 주체 중복")
            if not all(isinstance(x, str) and x in names for x in args["exited"]):
                raise Fl23Error("GENESIS_IMPORT: exited ⊄ principals")
            if len(names) - len(args["exited"]) > g["identity_budget"] - \
                    (self.reg.size() - len(self.SEATS)):
                raise Fl23Error("GENESIS_IMPORT: identity_budget 초과")
            self._reg_mark()
            for it in args["principals"]:
                self.reg.extend(it["p"], _hexbytes(it.get("pk"), 32, "GENESIS_IMPORT.pk"))
                for d in ("qual_burn", "Q"):
                    if it["p"] not in getattr(self, d):
                        self._mset(d, it["p"], 0)
            for x in args["exited"]:
                self._lappend("exited", x)
            total = 0
            for it in args["notes"]:
                if not (isinstance(it, dict) and isinstance(it.get("owner"), str)
                        and isinstance(it.get("issuer"), str) and _pos_int(it.get("face"))):
                    raise Fl23Error("GENESIS_IMPORT: notes 형식({owner,face,issuer})")
                if not self._real(it["owner"]):
                    raise Fl23Error(f"GENESIS_IMPORT: 미등록/퇴장 소유자 {it['owner']}")
                self._mint(it["owner"], it["face"], voluntary=True)
                total += it["face"]
            self._sset("F", args["F"])
            self._sset("F_uw", args["F_uw"])
            self._sset("ext_in", total + args["F"] + args["F_uw"])
        else:
            raise Fl23Error(f"미지 타입 {typ} — 경로 밖 연산은 없다")
        return None

    def _apply_block(self, legs, submitter):
        if not isinstance(legs, list) or not legs:
            raise Fl23Error("BLOCK: 다리 목록 비었음")
        for leg in legs:
            if leg["p"] == submitter:
                raise Fl23Error("BLOCK: 제출자는 다리 서명자를 겸할 수 없다(nonce 이중 사용)")
            self._verify_env(leg)
            self._apply(leg["typ"], leg["args"], leg["p"])
            self._mset("nonces", leg["p"], leg["nonce"] + 1)
        return {"block_legs": len(legs)}

    # ── ★J-2 승계 — H7 시드-독립 공개 생성자(검증-전용) ──
    @classmethod
    def from_public(cls, genesis_pks, label, genesis_agents, gen=None, bridge_ref=None):
        if gen:
            unknown = set(gen) - set(DEFAULT_GEN)
            if unknown:
                raise Fl23Error(f"GEN: 미지 파라미터 {sorted(unknown)}")
        w = cls.__new__(cls)
        w._genesis = (None, label, tuple(genesis_agents),
                      tuple(sorted((gen or {}).items())), bridge_ref)
        w.GEN = MappingProxyType({**DEFAULT_GEN, **(gen or {})})
        w.bridge_ref = bridge_ref
        w.reg = ChainRegistry()
        w._keys = {}
        for p in cls.SEATS + tuple(genesis_agents):
            if p not in genesis_pks:
                raise Fl23Error(f"from_public: {p} 공개키 누락")
            w.reg.extend(p, bytes.fromhex(genesis_pks[p]))
        w.fp0 = w.reg.fp
        w.log_id = log_id_of(w.fp0, label)
        w._blank_state(genesis_agents)
        return w

    def _replay_into(self, entries, verify_sig=True):
        """공용 리플레이 코어 — REJECT 엔트리·REKEY 키-일정 포함. 성공 = {"ok": True, ...}."""
        prev = "genesis"
        op_pk = self.reg.pk("operator")
        warn = 0
        for e in entries:
            if not (isinstance(e, dict) and isinstance(e.get("prev"), str)
                    and isinstance(e.get("head"), str)
                    and isinstance(e.get("state_root"), str)
                    and isinstance(e.get("env"), dict)):
                return {"ok": False,
                        "why": f"엔트리 형식 비정형 seq {e.get('seq') if isinstance(e, dict) else '?'}"}
            is_rej = e.get("kind") == "REJECT"
            try:
                r = self._commit(e["env"], replay=True)
                if is_rej:
                    return {"ok": False, "why": f"거부 기대했으나 수용 seq {e.get('seq')}"}
            except Fl23Error as ex:
                if not is_rej:
                    return {"ok": False, "why": f"리플레이 거부 seq {e.get('seq')}: {ex}"}
                if not self.log or self.log[-1].get("kind") != "REJECT" \
                        or self.log[-1]["env"] is not e["env"]:
                    return {"ok": False, "why": f"REJECT 재유도 실패 seq {e.get('seq')}(operator 거부는 기록되지 않는다)"}
                r = self.log[-1]
                if r.get("reason") != e.get("reason"):
                    warn += 1
            except Exception:
                return {"ok": False, "why": f"엔트리 처리 예외 seq {e.get('seq')}"}
            try:
                bind_bad = (r["state_root"] != e["state_root"] or r["head"] != e["head"]
                            or e["prev"] != prev or r["w_epoch"] != e.get("w_epoch")
                            or r.get("_force") != e.get("_force"))
            except Exception:
                return {"ok": False, "why": f"결박 필드 비정형 seq {e.get('seq')}"}
            if bind_bad:
                return {"ok": False, "why": f"결박 불일치 seq {e.get('seq')}"}
            if verify_sig:
                if "head_sig" not in e:
                    return {"ok": False, "why": f"헤드 서명 부재 seq {e.get('seq')}"}
                try:
                    Ed25519PublicKey.from_public_bytes(op_pk).verify(
                        bytes.fromhex(e["head_sig"]), FL23_DOMAIN + bytes.fromhex(e["head"]))
                except (InvalidSignature, ValueError, TypeError):
                    return {"ok": False, "why": f"헤드 서명 불일치/비정형 seq {e.get('seq')}"}
            env = e["env"]
            if not is_rej and env.get("typ") == "REKEY" and env.get("p") == "operator":
                op_pk = bytes.fromhex(env["args"]["new_pk"])      # ★J-4 키-일정: 다음 항부터
            prev = e["head"]
        return {"ok": True, "entries": len(entries), "reason_warn": warn,
                "state_root": self.state_root(), "head": prev,
                "fp0": self.fp0, "log_id": self.log_id.hex()}

    def replay_verify(self, entries):
        """★H7 — 공개 세계 위 로그 전량 재검증(봉투 법-검사·head-사슬·state_root·_force·
        운영자 head_sig(키-일정 포함)·REJECT 재유도). 성공 = 전-상태가 공개 재료만으로 재구성."""
        r = self._replay_into(entries, verify_sig=True)
        if r["ok"]:
            try:
                self._invariants()
            except Fl23Error as ex:
                return {"ok": False, "why": f"종단 불변식: {ex}"}
            if self._root_full() != r["state_root"]:
                return {"ok": False, "why": "증분 root ≠ 전량 root(캐시 결함)"}
        return r

    def audit(self):
        seed, label, agents, genconf, bridge = self._genesis
        if seed is None:
            raise Fl23Error("공개 세계(from_public)는 replay_verify로 검증한다")
        w = World(seed, label, agents, gen=dict(genconf), bridge_ref=bridge)
        r = w._replay_into(self.log, verify_sig=True)
        if not r["ok"]:
            return r
        # ★경로-밖 직접 변조(K-0ⓔ)는 저널 프리미티브를 거치지 않아 다이제스트 캐시가 낡을 수 있다 —
        # audit 는 live 측을 **전량 재계산**으로 대조한다(kernel22 의 「state_root = 항상 전량」 의미론을 여기서 복원).
        if w._root_full() != self._root_full():
            return {"ok": False,
                    "why": "★살아 있는 상태 ≠ 리플레이 상태 — 경로 밖 기입 검출(K-0ⓔ)"}
        try:
            self._invariants()
        except Fl23Error as ex:
            return {"ok": False, "why": f"불변식: {ex}"}
        return {"ok": True, "entries": len(self.log), "reason_warn": r["reason_warn"]}
