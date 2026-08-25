#!/usr/bin/env python3
"""kernel21.py — FL2.1 캐논 커널 ★FROZEN v1.0 ([M-83]) · 참조 구현 v0.3.

⚙️★★★**FL2.1 동결(2026-08-22 · [M-83] · 사용자 재가)**: 이 커널의 FL2.1 범위(FL2.0 전량
승계 + S-1 시한-사고 · S-2 ATTEST · U-1 β<1 인수 · U-2 소구 폭포 · U-3 F_uw 분리·적정성-
결박 흡입)가 정본 승격·동결됐다 — 동결-시점 증거: 셀프테스트 18/18 + RG-1~8 전량 + 골든
벡터 9종 바이트-불변 + lab 정합(C1-v2·C2-v2) PASS + 큰 그림 리뷰 렌즈 네 라운드 봉합
([M-80] 결함 0) + ★동결-경계 연구([M-81~82] R-EDGE 744런 — T3 법-충돌 0 · 전 잔여 축
정책-층/차세대 분류). ★이후 변경은 세대 규율([증보 15]): FL2.1 무수정 보존 · 변경은
FL2.2 트리(차세대 회부 [M-83] §2 — 입장-지문·소득-내생·노출-상한 절충·k-연속·환급형·
부분-불투명)로 · 결정(M-n) 경유. 정리 캐논 = FR-1~4(core/FL21_CAMPAIGN_RECORD §3).

지위: ⚙️**FL2.1 캐논(FROZEN)**. 이하 원문은 [M-69] 착수 · [M-70] · [M-74] · [M-80] 사료.

⚙️★**v0.3([M-80] · 큰 그림 리뷰 렌즈 봉합)**: 네 독립 리뷰 렌즈(구조-명세 정합·강건성·
  경제 정합·명세 정직)가 낸 결함을 봉합했다 — F1 담보∩기금 노트 서로소 강제 · F2·F5 비정규
  예외 롤백(`_commit`/`_force_apply`가 non-Fl21Error도 잡아 audit 파손 봉합) · ★F3 DELIVER가
  ATTEST_FAIL 판정을 지우던 구멍 봉합(판정 내구성 — S-2를 「끌 수 없는 방어」로) · F6 흡입-
  결박 단발 초과 봉합(F_uw ≤ cap 보장) · epoch _STATE 결박(롤백 원자성) · ATTEST role 선택
  검증. 자인 ⓖⓗ 추가(입장 심사 무방비·소구 judgment-proof = [정리 C] 인수판). 셀프 18/18.

⚙️★**v0.2([M-74] · R-FRONT2)**: ★**적정성-결박 흡입** — [정리 FR-1](도관-저수지 배타 ·
  R-FRONT 1단계)의 병목 축. 커널이 ★**관측-최대 F-층 충격 `F_peak`**(정산 틱당 기금-층
  수요의 지평 최대 — 값 8 「지평 최대」 절차 계보)를 상태로 관측하고, ★**기금 흡입(UW의
  prem_f)을 `F_uw < fq_mult × max(F_peak, fq_base)`에 결박**한다(초과 적립 정지 — 저수지
  방지 · 지급은 무제한). `fq_mult = 0`(기본) = 흡입-결박 없음(v0.1 의미론 보존).
  ⚠️리뷰 상-1 정합: 이것은 적립 **상한** 관리지 「F ≥ 전액」 강제가 아니다(자동-공집합
  경로 아님) · 정산 폭포·골든 벡터 무변경.

지위: ⛔**참조 구현 초안 — 캐논 아님 · 동결 아님**. ★**FL2.0(FROZEN v1.0) 무접촉·임포트 0**
(새 세대는 새 뿌리 — lang2가 v1.1에 했던 그대로). 설계 정본 =
[FL21_DESIGN v0.2](../lang2/FL21_DESIGN_2026-08-21.md) · 리뷰 = core/FL21_DESIGN_REVIEW.

★FL2.0 위에 더한 것([M-69] 개정 순서 0~1 = 최소 인수 루프의 커널 몫):
  U-0 세대 브리지 자리: FL21 전용 DOMAIN(세대 식별자 — FL2.0 서명은 여기서 바이트-검증
      불가) + genesis `bridge_ref`(FL2.0 최종 head 참조-앵커 — 실 참조·이관은 동결 시).
  S-1 ★시한-사고: REDEEM→DELIVER 시한 `redeem_T`(GEN) 초과 = ★커널-파생 미이행 사건
      (발화 불요 · 판정 토큰 0 — [정리 A] 무위험). 미부보 청구 = 시간초과-반환(FL2.0 자인
      잔여의 해소) · 부보 청구 = 배상 폭포. 정산은 TICK 적용 안에서 법-구동·일괄(강제 다리 —
      끌 수 없는 방어)이고 결과는 엔트리 `_force` 필드로 head 해시에 결박된다.
  S-2 ★ATTEST_OK/FAIL 발화(G2-4a 문언 그대로): (ref, role, reason) · reason은 발화지 판정
      아님 · ⛔요율 입력 비활성(G2-4c — 사유-판 심기 검증 후) · FAIL은 청구를 조기 성숙시킬
      뿐 정산 규칙은 시한-사고와 동일 경로.
  U-1 ★부분 담보 β: UW의 `cov ≤ exposure` ∧ `cov·β_den ≥ exposure·β_num`(GEN β_min —
      인가 문턱 · 정수-정확). β는 인수자 자본 결박 한정(앵커 처리량 = 유동성 = S-1 소관).
  U-2 ★지급불능 3법 + 소구 순서(조항화된 폭포): ★가해자(앵커) 자유 잔고 우선(법 ⑥ 승계)
      → 담보 에스크로 → 인수자 자유 잔고(소구 강제 다리) → F_uw → 비례(층-내 비례 배분 ·
      F_uw 자기적용 포함) + 지급불능 기입(정산 기록의 `short`).
  U-3 ★F_uw 분리: 방 고정비 `F`와 별도 스칼라(요율 수입 + 배상 지출 — [R-139] 이중 부담
      방지). 보존식 = `Σface + F + F_uw + S == ext_in − ext_out`. UW의 선언 보험료 `prem`
      중 GEN 몫(`uw_phi`)이 인수자 노트 소각으로 F_uw에 적립된다. GEN `prem_floor` =
      요율 하한 다이얼(프런티어 §3 v0.2의 요율 축 — 기본 0).

정직 한정어(v0.1):
  ⓐ attester = 시퀀서 좌석(operator) 단일 — 검증자 추첨·복수화는 G2-6a 후속.
  ⓑ DELIVER-후 기망 인도(엉터리 계산)는 미포착 — ATTEST_FAIL은 pending 중에만 유효.
     기망 포착은 ATT_COMMIT(커밋-리빌)·사유-판 심기 소관(개정 순서 4번).
  ⓒ 적정성(`F_uw ≥ μ+3σ 충격`)은 ★측정-게이트지 커널 매-발화 불변식이 아니다(리뷰 상-1 —
     전액-커버 독해는 시스템-β=1 회귀). 커널은 F_uw 회계·폭포 순서만 강제한다.
  ⓓ `prem`은 선언 가격(개설-계열 발화의 가격 토큰 — G2-5c 허용면)이고 실지급은 노트-흐름
     창발([M-65]) — 홀더→인수자 지불은 XFER/BLOCK 몫. ★[M-80] 명확화: 커널엔 홀더→인수자
     보험료 매입 결박이 없다. `prem_f`(=prem·uw_phi)는 ★인수자 자기적립이고 `prem_floor`는
     인수자 자기적립 하한이지 홀더-지불 시장 요율 결박이 아니다(요율 축 측정은 lab 소관).
  ⓔ 정산은 청구 노트를 소각하고 잔여 청구를 소멸시킨다(배상 ≤ 액면 + 지급불능 기입 —
     비례 청산의 종결성). 대안(청구권 승계)은 미구현 등재.
  ⓕ 단일 운영자 헤드 키·참조-형 결정론 키 승계(FL2.0 자인 그대로).
  ⓖ ★[M-80] 입장 심사 없음 — JOIN 무상(Q 불요)·UW에 자격/이력 검사 없음 ⟹ [정리 C]의
     공모-파산(judgment-proof) 축에 구현된 방어가 0이다. 방어는 U-6(입장 심사 — R-ENTRY
     라운드 후속)까지 미구현. β_min은 [정리 C]가 방어 불가를 증명한 다이얼이지 방어가 아니다.
  ⓗ ★[M-80] 소구(U-2 ③층)는 「자유 잔고」 압류라, 앵커·인수자가 정산 전 XFER로 자산을
     빼돌리면 무력화된다 = ★judgment-proof의 인수판([정리 C] 커널 실재). 커널로 못 막는다
     (β를 올려 담보로 가두면 β=1 회귀 = 인수 아님 — [정리 U]). 방어는 ⓖ와 같은 입장 심사
     축. ⟹ 소구는 「강제 다리」가 아니라 「자유-잔고 소구 시도」다(설계 문언 하향).
     ⚙️★[M-82 R-EDGE] 재해석: 이 「못 막음」은 결함이 아니라 ★인수업의 존재 조건이다 —
     가해자-층이 노출을 감당하면 기금은 무접촉(E1 탈락)이고 도피가 기금을 부활시킨다
     ([정리 FR-4] 후보). 실측 노출 = 인수층 전가 한정(홀더 회수 무감 — O2 1.0).
"""
import copy
import hashlib
import json
from types import MappingProxyType

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (Ed25519PrivateKey,
                                                               Ed25519PublicKey)

FL21_DOMAIN = b"FL21-v0.1" + b"\x00" * 7
assert len(FL21_DOMAIN) == 16
KEY_TAG21 = b"FL21-KEY-v0.1"

DEFAULT_GEN = {
    "identity_budget": 16,
    "window_L": 3,
    "qual_price": 40,
    "room_c": 32, "room_phi": 2,
    # ── FL2.1 신설 다이얼(세대 내 불변 — 스윕은 세계 단위 · G2-0b) ──
    "redeem_T": 4,            # S-1 시한(에포크) — window_L보다 커야 강제 포함이 시한을 이긴다
    "beta_min_num": 1, "beta_min_den": 2,     # U-1 인가 문턱(값 1 = 0.5 · 정수-정확)
    "uw_phi_num": 1, "uw_phi_den": 2,         # U-3 보험료 중 F_uw 몫
    "prem_floor_num": 0, "prem_floor_den": 1,  # §3 v0.2 요율 하한(기본 없음 — 측정 축)
    "fq_mult": 0, "fq_base": 12,               # ★v0.2 적정성-결박 흡입(0 = 끔 = v0.1)
}
_MONEY_FIELDS = {"EXT_IN": ("amount",), "EXT_IN_POOL": ("pool",)}


class Fl21Error(Exception):
    """경로 거부 — 이 엔트리는 로그에 진입하지 못한다(법-검사 실패)."""


def _canon(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode()


def _pos_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and x >= 1


def _nonneg_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def derive_key(master_seed: int, principal: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(KEY_TAG21 + b"|" + str(int(master_seed)).encode()
                          + b"|" + principal.encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


class ChainRegistry:
    """지문-체인 레지스트리 — 추가 = 새 링크(과거 결박 불변)."""

    def __init__(self):
        self._pk = {}
        self.links = []
        self.fp = "genesis"

    def extend(self, principal, pk_bytes):
        if principal in self._pk:
            raise Fl21Error(f"레지스트리: {principal} 재등록 거부")
        pk = bytes(pk_bytes)
        h = hashlib.sha256()
        h.update(self.fp.encode() if self.fp == "genesis" else bytes.fromhex(self.fp))
        h.update(b"\x00" + principal.encode() + b"\x00" + pk + b"\x01")
        self.fp = h.hexdigest()
        self._pk[principal] = pk
        self.links.append((principal, pk.hex(), self.fp))
        return self.fp

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
    return hashlib.sha256(FL21_DOMAIN + fp0.encode() + b"|" + label.encode()).digest()


class World:
    """FL2.1 참조 세계 — 상태는 이 클래스가 사유하고, 변경은 submit()/tick() 경로뿐이다."""

    SEATS = ("operator",)
    _STATE = ("notes", "note_ctr", "locked_rooms", "room_owner", "redeem_pending",
              "uw_open", "exited", "F", "F_uw", "F_peak", "S", "ext_in", "ext_out",
              "qual_burn", "Q", "nonces", "pending", "epoch")   # ★[M-80] epoch 롤백 원자성

    def __init__(self, master_seed=2, label="fl21-ref",
                 genesis_agents=("a0", "a1", "a2", "a3"), gen=None,
                 bridge_ref=None):
        if gen:
            unknown = set(gen) - set(DEFAULT_GEN)
            if unknown:
                raise Fl21Error(f"GEN: 미지 파라미터 {sorted(unknown)}")
        self._genesis = (master_seed, label, tuple(genesis_agents),
                         tuple(sorted((gen or {}).items())), bridge_ref)
        self.GEN = MappingProxyType({**DEFAULT_GEN, **(gen or {})})
        self.bridge_ref = bridge_ref          # U-0: FL2.0 최종 head 참조-앵커(동결 시 실값)
        self.reg = ChainRegistry()
        self._keys = {}
        for p in self.SEATS + tuple(genesis_agents):
            k = derive_key(master_seed, p)
            self._keys[p] = k
            self.reg.extend(p, k.public_key().public_bytes_raw())
        self.fp0 = self.reg.fp
        self.log_id = log_id_of(self.fp0, label)
        self.notes = {}
        self.note_ctr = 0
        self.locked_rooms = {}
        self.room_owner = {}
        self.redeem_pending = {}
        self.uw_open = {}                     # ref → {uw, cov[노트], prem}
        self.exited = []
        self.F = 0                            # 방 고정비 적립(FL2.0 승계)
        self.F_uw = 0                         # ★U-3 인수 기금(요율 수입 + 배상 지출 — 분리)
        self.F_peak = 0                       # ★v0.2 관측-최대 F-층 충격(지평 최대 — 값 8 계보)
        self.S = 0
        self.ext_in = 0
        self.ext_out = 0
        self.qual_burn = {a: 0 for a in genesis_agents}
        self.Q = {a: 0 for a in genesis_agents}
        self.nonces = {}
        self.epoch = 0
        self.pending = []
        self.log = []

    # ── 노트·의무 헬퍼 ──
    def _mint(self, owner, face):
        if not _pos_int(face):
            raise Fl21Error("mint: 액면 ≥ 1 정수")
        nid = str(self.note_ctr)
        self.note_ctr += 1
        self.notes[nid] = {"owner": owner, "face": face}
        return nid

    def bal(self, a):
        return sum(n["face"] for n in self.notes.values() if n["owner"] == a)

    def obl(self, a):
        """★미결 의무 = 소유 열린 방 + 상환 앵커 지목 수 + ★인수 커버리지(I-1 확장) —
        파생 함수라 EXIT(§1-d)와 유출 문(G2-3b)이 자동으로 같이 닫힌다."""
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
            raise Fl21Error("노트 중복 지정")
        tot = 0
        for nid in ids:
            if not self._own(nid, a):
                raise Fl21Error(f"노트 {nid}는 {a} 소유 아님")
            tot += self.notes[nid]["face"]
        if exact is not None and tot != exact:
            raise Fl21Error(f"액면 합 {tot} ≠ 요구 {exact}(SPLIT 선행)")
        for nid in ids:
            del self.notes[nid]
        return tot

    # ── 정산 폭포 헬퍼(U-2 — 전부 결정론) ──
    def _prorate(self, avail, needs):
        """층-내 비례 배분(법 ⑧ 형식) — 바닥 나눗셈 잔여는 정렬 순으로 채워
        층이 min(avail, Σneed)을 정확히 낸다."""
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

    def _seize(self, q, amount):
        """자유-잔고 소구(U-2 ③층 — 자인 ⓗ: 정산-전 이탈 자산엔 닿지 않는다) — q의
        자유 노트를 정렬 순으로 소비하고 잔돈을 재발행. 회수액을 반환한다(호출자가
        반드시 같은 액수를 지급으로 재발행 — 보존)."""
        if amount <= 0:
            return 0
        ids = sorted((nid for nid, n in self.notes.items() if n["owner"] == q),
                     key=int)
        take, tot = [], 0
        for nid in ids:
            if tot >= amount:
                break
            take.append(nid)
            tot += self.notes[nid]["face"]
        if not take:
            return 0
        for nid in take:
            del self.notes[nid]
        got = min(tot, amount)
        if tot > got:
            self._mint(q, tot - got)
        return got

    def _close_cov(self, ref):
        """커버리지 정상 종결(DELIVER/CANCEL) — 에스크로가 인수자에게 돌아간다."""
        c = self.uw_open.pop(ref, None)
        if c:
            for nid in c["cov"]:
                self.notes[nid]["owner"] = c["uw"]

    def _settle(self):
        """S-1 시한-사고 일괄 정산(TICK 적용 내 법-구동 — 강제 다리 · 결과는 엔트리에 결박).

        성숙 = 시한 초과 ∨ ATTEST_FAIL. 미부보 = 시간초과-반환. 부보 = U-2 폭포:
        ①가해자(앵커) 우선 → ②담보 에스크로 → ③인수자 소구 → ④F_uw → 잔여 = 지급불능
        기입(배상 ≤ 액면 · 청구 노트 소각 — 종결성). 공유 층은 비례(_prorate)."""
        T = self.GEN["redeem_T"]
        if T <= 0:
            return None
        matured = sorted(ref for ref, rp in self.redeem_pending.items()
                         if rp["failed"] or (self.epoch - rp["t0"]) >= T)
        if not matured:
            return None
        returned, covered = [], []
        for ref in matured:
            if ref in self.uw_open:
                covered.append(ref)
                continue
            rp = self.redeem_pending.pop(ref)
            self.notes[rp["nid"]]["owner"] = rp["holder"]   # 시간초과-반환(FL2.0 잔여 해소)
            returned.append(ref)
        settled = []
        if covered:
            need = {r: self.notes[self.redeem_pending[r]["nid"]]["face"]
                    for r in covered}
            rem = dict(need)
            paid = {r: {"anchor": 0, "cov": 0, "uw": 0, "fund": 0} for r in covered}
            # ① 가해자(앵커) 우선 — 법 ⑥ 승계 · 앵커별 비례
            by_anchor = {}
            for r in covered:
                by_anchor.setdefault(self.redeem_pending[r]["anchor"], []).append(r)
            for a in sorted(by_anchor):
                grp = [r for r in by_anchor[a] if rem[r] > 0]
                if not grp:
                    continue
                alloc = self._prorate(self.bal(a), {r: rem[r] for r in grp})
                self._seize(a, sum(alloc.values()))
                for r in grp:
                    paid[r]["anchor"] += alloc[r]
                    rem[r] -= alloc[r]
            # ② 담보 에스크로(청구 전용 — 잔여는 인수자 반환)
            for r in covered:
                c = self.uw_open[r]
                tot = sum(self.notes[n]["face"] for n in c["cov"])
                for n in c["cov"]:
                    del self.notes[n]
                c["cov"] = []
                take = min(tot, rem[r])
                if tot - take > 0:
                    self._mint(c["uw"], tot - take)
                paid[r]["cov"] += take
                rem[r] -= take
            # ③ 인수자 소구(자유 잔고 강제 다리) — 인수자별 비례
            by_uw = {}
            for r in covered:
                by_uw.setdefault(self.uw_open[r]["uw"], []).append(r)
            for u in sorted(by_uw):
                grp = [r for r in by_uw[u] if rem[r] > 0]
                if not grp:
                    continue
                alloc = self._prorate(self.bal(u), {r: rem[r] for r in grp})
                self._seize(u, sum(alloc.values()))
                for r in grp:
                    paid[r]["uw"] += alloc[r]
                    rem[r] -= alloc[r]
            # ④ F_uw — 전역 비례(부족 = 비례 자기적용 · G2-7c-ⓒ)
            grp = [r for r in covered if rem[r] > 0]
            if grp:
                demand = sum(rem[r] for r in grp)    # ★F-층 수요(지급+부족이 될 총량)
                self.F_peak = max(self.F_peak, demand)   # v0.2 — 지평 최대 관측
                alloc = self._prorate(self.F_uw, {r: rem[r] for r in grp})
                for r in grp:
                    self.F_uw -= alloc[r]
                    paid[r]["fund"] += alloc[r]
                    rem[r] -= alloc[r]
            # 종결 — 배상 발행 + 청구 노트 소각 + 지급불능 기입
            for r in covered:
                rp = self.redeem_pending.pop(r)
                del self.uw_open[r]
                comp = need[r] - rem[r]
                if comp > 0:
                    self._mint(rp["holder"], comp)
                self.S += self._consume([rp["nid"]], f"@redeem:{r}", None)
                settled.append({"ref": r, "comp": comp, "short": rem[r],
                                **paid[r]})
        return {"returned": returned, "settled": settled}

    # ── 정준 상태·서명 ──
    def _gen_root(self):
        return hashlib.sha256(_canon(dict(self.GEN))).hexdigest()

    def state_root(self):
        st = {k: getattr(self, k) for k in self._STATE}
        st["epoch"] = self.epoch
        st["fp"] = self.reg.fp
        st["pk_root"] = self.reg.pk_root()
        st["gen_root"] = self._gen_root()
        st["bridge_ref"] = self.bridge_ref             # U-0 결박
        return hashlib.sha256(_canon(st)).hexdigest()

    def _sig_msg(self, body, nonce):
        return (FL21_DOMAIN + self.log_id + _canon(body)
                + int(nonce).to_bytes(8, "big"))

    def sign_env(self, principal, typ, args, epoch=None, nonce=None):
        n = self.nonces.get(principal, 0) if nonce is None else nonce
        body = {"typ": typ, "args": args, "p": principal,
                "epoch": self.epoch if epoch is None else epoch}
        sig = self._keys[principal].sign(self._sig_msg(body, n))
        return {**body, "nonce": n, "sig": sig.hex()}

    def _snap(self):
        return ({k: copy.deepcopy(getattr(self, k)) for k in self._STATE},
                self.reg.snap())

    def _restore(self, s):
        for k, v in s[0].items():
            setattr(self, k, v)
        self.reg.restore(s[1])

    def _invariants(self):
        face = sum(n["face"] for n in self.notes.values())
        if any(not _pos_int(n["face"]) for n in self.notes.values()):
            raise Fl21Error("노트 액면 ≥ 1 위반")
        total = face + self.F + self.F_uw + self.S
        if total != self.ext_in - self.ext_out:
            raise Fl21Error(f"법 ②: 보존 붕괴 {total} != {self.ext_in - self.ext_out}")
        qp = self.GEN["qual_price"]
        for a, q in self.Q.items():
            if q * qp > self.qual_burn.get(a, 0):
                raise Fl21Error(f"법 ①: 자격 보존 붕괴 {a}")
        if min(self.F, self.F_uw, self.F_peak, self.S,
               self.ext_in, self.ext_out) < 0:
            raise Fl21Error("음수 회계 항목")
        # ★구조 정합성(FL2.0 승계 + 인수층)
        if set(self.room_owner) != set(self.locked_rooms):
            raise Fl21Error("구조: room_owner ↔ locked_rooms 키 불일치")
        if not set(self.uw_open) <= set(self.redeem_pending):
            raise Fl21Error("구조: 청구 없는 커버리지(uw_open ⊄ redeem_pending)")
        for nid, n in self.notes.items():
            o = n["owner"]
            if o.startswith("@room:") and o[6:] not in self.locked_rooms:
                raise Fl21Error(f"구조: 고아 방-에스크로 노트 {nid}")
            if o.startswith("@redeem:") and o[8:] not in self.redeem_pending:
                raise Fl21Error(f"구조: 고아 상환-에스크로 노트 {nid}")
            if o.startswith("@uw:") and o[4:] not in self.uw_open:
                raise Fl21Error(f"구조: 고아 담보-에스크로 노트 {nid}")
        for rid, ids in self.locked_rooms.items():
            if any(self.notes.get(i, {}).get("owner") != f"@room:{rid}" for i in ids):
                raise Fl21Error(f"구조: 방 {rid} 에스크로 노트 소유 어긋남")
        for ref, rp in self.redeem_pending.items():
            if self.notes.get(rp["nid"], {}).get("owner") != f"@redeem:{ref}":
                raise Fl21Error(f"구조: 상환 {ref} 에스크로 노트 소유 어긋남")
            if rp["t0"] > self.epoch or not isinstance(rp["failed"], bool):
                raise Fl21Error(f"구조: 상환 {ref} 시계·판정 필드 이상")
        for ref, c in self.uw_open.items():
            if any(self.notes.get(i, {}).get("owner") != f"@uw:{ref}"
                   for i in c["cov"]):
                raise Fl21Error(f"구조: 커버리지 {ref} 에스크로 소유 어긋남")

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
            raise Fl21Error(f"신원: 미지 주체 {p}(체인 밖)")
        if p in self.exited and env["typ"] not in ("REQUEST", "TICK", "FORCE"):
            raise Fl21Error(f"퇴장 신원 {p}은 발화 불가")
        try:
            Ed25519PublicKey.from_public_bytes(pk).verify(
                bytes.fromhex(env["sig"]), self._sig_msg(body, env["nonce"]))
        except (InvalidSignature, ValueError):
            raise Fl21Error(f"서명 검증 실패: {p} {env['typ']}")
        if env["nonce"] != self.nonces.get(p, 0):
            raise Fl21Error(f"nonce 위반: {p}")
        if window:
            if env["epoch"] > self.epoch:
                raise Fl21Error(f"법 ③: 선행 기입 {env['epoch']} > {self.epoch}")
            if self.epoch - env["epoch"] > self.GEN["window_L"]:
                raise Fl21Error(f"법 ④: 창 밖 소급 {env['epoch']} ≪ {self.epoch}")

    def _commit(self, env, replay=False):
        self._verify_env(env)
        snap = self._snap()
        force_outcome = None
        try:
            force_outcome = self._apply(env["typ"], env["args"], env["p"])
            self.nonces[env["p"]] = env["nonce"] + 1
            self._invariants()
        except Fl21Error:
            self._restore(snap)
            raise
        except Exception as e:                       # ★[M-80 F1·F5] 비정규 예외도 롤백
            # K-0ⓔ 철학: 부정형 입력은 「경로 밖」이므로 거부한다. 좁은 except가
            # KeyError 등을 놓쳐 상태를 파손(audit 영구 실패)하던 구멍의 봉합 —
            # 원인 타입을 보존해 진짜 버그가 조용히 삼켜지지 않게 한다.
            self._restore(snap)
            raise Fl21Error(f"비정규 예외 거부({env['typ']}): {type(e).__name__}: {e}")
        entry = {"seq": len(self.log), "env": env, "fp": self.reg.fp,
                 "w_epoch": self.epoch, "state_root": self.state_root(),
                 "prev": self.log[-1]["head"] if self.log else "genesis"}
        if force_outcome is not None:
            entry["_force"] = force_outcome          # 법-구동 결과(FORCE·정산) head 결박
        entry["head"] = hashlib.sha256(
            entry["prev"].encode() + _canon({k: entry[k] for k in
                                             ("env", "fp", "w_epoch", "state_root")}
                                            | ({"_force": force_outcome}
                                               if force_outcome is not None else {}))
        ).hexdigest()
        if not replay:
            entry["head_sig"] = self._keys["operator"].sign(
                FL21_DOMAIN + bytes.fromhex(entry["head"])).hex()
        self.log.append(entry)
        return entry

    def _force_apply(self, inner):
        if not self.pending or self.pending[0][1] != inner:
            raise Fl21Error("FORCE: pending 선두 불일치")
        self.pending.pop(0)
        try:
            self._verify_env(inner, window=False)    # 법 ⑦이 법 ④를 넘긴다
            self._apply(inner["typ"], inner["args"], inner["p"])
            self.nonces[inner["p"]] = inner["nonce"] + 1
            return {"included": True, "typ": inner["typ"]}
        except Exception as e:                       # ★[M-80 F2] 부정형 릴레이 inner 강등
            # REQUEST는 검열저항을 위해 inner를 미검증 적재하므로, 부정형 inner가
            # 강제-포함 시 non-Fl21Error를 낼 수 있다. 크래시 대신 「거부 기록」으로
            # 강등한다(pending은 이미 pop됨 — 로그에 included:False로 남는다).
            return {"included": False, "why": f"{type(e).__name__}: {e}"[:60],
                    "typ": inner.get("typ", "?") if isinstance(inner, dict) else "?"}

    def _apply(self, typ, args, p):
        g = self.GEN
        for fld in _MONEY_FIELDS.get(typ, ()):
            if not _nonneg_int(args.get(fld)):
                raise Fl21Error(f"{typ}.{fld}: 음수/비정수 금액 거부")

        if typ == "REQUEST":
            if p != "operator":
                raise Fl21Error("REQUEST: 시퀀서 좌석")
            self.pending.append([self.epoch, args["inner"]])
        elif typ == "TICK":
            if p != "operator":
                raise Fl21Error("TICK: 시퀀서 좌석")
            self.epoch += 1
            return self._settle()                    # ★S-1 일괄 정산(법-구동 · 결과 결박)
        elif typ == "FORCE":
            if p != "operator":
                raise Fl21Error("FORCE: 시퀀서 좌석")
            return self._force_apply(args["inner"])
        elif typ == "JOIN":
            if p != "operator":
                raise Fl21Error("JOIN: 운영자 좌석 후원")
            new = args["principal"]
            if new.startswith("@"):
                raise Fl21Error("JOIN: 예약 접두 '@' 주체 거부")
            if self.reg.size() - len(self.SEATS) >= g["identity_budget"]:
                raise Fl21Error("JOIN: identity_budget 소진")
            self.reg.extend(new, bytes.fromhex(args["pk"]))
            for d in (self.qual_burn, self.Q):
                d.setdefault(new, 0)
        elif typ == "EXIT":                          # §1-d — 잔여·의무(커버리지 포함)·미결 상환 0
            a = args["a"]
            if p != a:
                raise Fl21Error("EXIT: 행위자 = 본인")
            if self.obl(a) > 0:
                raise Fl21Error(f"EXIT: 미결 의무 {self.obl(a)}")
            if self.bal(a) > 0:
                raise Fl21Error(f"EXIT: 잔여 노트 {self.bal(a)}")
            if any(rp["holder"] == a for rp in self.redeem_pending.values()):
                raise Fl21Error("EXIT: 미결 상환(holder) — 회수 불가 방지")
            if a in self.exited:
                raise Fl21Error("EXIT: 이미 퇴장")
            self.exited.append(a)
        elif typ == "EXT_IN":
            if p != "operator":
                raise Fl21Error("EXT_IN: 유입 문 = 운영자-서명 법 사건")
            if not self._real(args["to"]):
                raise Fl21Error("EXT_IN: 대상이 미등록/퇴장")
            self.ext_in += args["amount"]
            self._mint(args["to"], args["amount"])
        elif typ == "EXT_IN_POOL":
            if p != "operator":
                raise Fl21Error("EXT_IN_POOL: 운영자-서명")
            pool, claims = args["pool"], args["claims"]
            if not all(_nonneg_int(v) for v in claims.values()):
                raise Fl21Error("EXT_IN_POOL: 음수 청구")
            if not all(self._real(a) for a in claims):
                raise Fl21Error("EXT_IN_POOL: 미등록/퇴장 청구자")
            tot = sum(claims.values())
            if tot == 0:
                raise Fl21Error("EXT_IN_POOL: 청구 총합 0")
            self.ext_in += pool
            rem = pool
            for a in sorted(claims):
                alloc = (pool * claims[a] // tot) if tot > pool else claims[a]
                alloc = min(alloc, rem)
                if alloc > 0:
                    self._mint(a, alloc)
                rem -= alloc
            self.F += rem
        elif typ == "EXT_OUT":
            a, nid = args["frm"], args["note"]
            if p != a:
                raise Fl21Error("EXT_OUT: 행위자 = 보유자")
            if self.obl(a) > 0:
                raise Fl21Error(f"유출 문: {a} 미결 의무 — 후순위")
            face = self._consume([nid], a, None)
            self.ext_out += face
        elif typ == "XFER":
            frm, to, nid = args["frm"], args["to"], args["note"]
            if p != frm:
                raise Fl21Error("XFER: 행위자 = 보유자")
            if not self._real(to):
                raise Fl21Error("XFER: 수취인 무효")
            if not self._own(nid, frm):
                raise Fl21Error("XFER: 미소유 노트")
            self.notes[nid]["owner"] = to
        elif typ == "SPLIT":
            owner, nid, parts = args["owner"], args["note"], args["parts"]
            if p != owner:
                raise Fl21Error("SPLIT: 행위자 = 보유자")
            if not all(_pos_int(x) for x in parts) or len(parts) < 2:
                raise Fl21Error("SPLIT: 부분 ≥ 1 정수 · 둘 이상")
            face = self._consume([nid], owner, None)
            if sum(parts) != face:
                raise Fl21Error(f"SPLIT: 부분 합 {sum(parts)} ≠ 액면 {face}")
            for f in parts:
                self._mint(owner, f)
        elif typ == "MERGE":
            owner, ids = args["owner"], args["notes"]
            if p != owner:
                raise Fl21Error("MERGE: 행위자 = 보유자")
            if len(ids) < 2:
                raise Fl21Error("MERGE: 둘 이상")
            self._mint(owner, self._consume(ids, owner, None))
        elif typ == "BURN":
            owner, nid = args["owner"], args["note"]
            if p != owner:
                raise Fl21Error("BURN: 행위자 = 보유자")
            self.S += self._consume([nid], owner, None)
        elif typ == "QUAL_BUY":
            a, ids = args["a"], args["notes"]
            if p != a:
                raise Fl21Error("QUAL_BUY: 행위자 = 취득자")
            self.S += self._consume(ids, a, g["qual_price"])
            self.qual_burn[a] += g["qual_price"]
            self.Q[a] += 1
        elif typ == "OPEN":
            owner, rid, ids = args["owner"], args["rid"], args["notes"]
            c, phi = g["room_c"], g["room_phi"]
            if p != owner:
                raise Fl21Error("OPEN: 행위자 = 소유자")
            if rid in self.locked_rooms:
                raise Fl21Error("OPEN: rid 중복")
            self._consume(ids, owner, c + phi)
            esc = self._mint(f"@room:{rid}", c)
            self.locked_rooms[rid] = [esc]
            self.room_owner[rid] = owner
            self.F += phi
        elif typ == "CLOSE":
            rid, owner, perf = args["rid"], args["owner"], args["performer"]
            if rid not in self.locked_rooms:
                raise Fl21Error("CLOSE: 미지 방")
            if self.room_owner.get(rid) != owner or p != owner:
                raise Fl21Error("CLOSE: 소유권 불일치")
            if self.reg.pk(perf) is None or perf in self.exited:
                raise Fl21Error("CLOSE: 수임자 무효")
            for nid in self.locked_rooms.pop(rid):
                self.notes[nid]["owner"] = perf
            del self.room_owner[rid]
        elif typ == "REDEEM":                        # §2 — ★t0·failed 필드(S-1)
            holder, nid, anchor = args["holder"], args["note"], args["anchor"]
            if p != holder:
                raise Fl21Error("REDEEM: 행위자 = 보유자")
            if not self._real(anchor):
                raise Fl21Error("REDEEM: 앵커 무효")
            if not self._own(nid, holder):
                raise Fl21Error("REDEEM: 미소유 노트")
            ref = hashlib.sha256(f"{self.log_id.hex()}|{nid}|{self.epoch}".encode()
                                 ).hexdigest()[:16]
            if ref in self.redeem_pending:
                raise Fl21Error("REDEEM: ref 중복")
            self.notes[nid]["owner"] = f"@redeem:{ref}"
            self.redeem_pending[ref] = {"holder": holder, "nid": nid,
                                        "anchor": anchor, "t0": self.epoch,
                                        "failed": False}
        elif typ == "DELIVER":                       # §2 — 이행 ⟹ 커버리지 종결 + 소각
            anchor, ref = args["anchor"], args["ref"]
            if p != anchor:
                raise Fl21Error("DELIVER: 행위자 = 앵커")
            rp = self.redeem_pending.get(ref)
            if rp is None or rp["anchor"] != anchor:
                raise Fl21Error("DELIVER: 미지 상환 청구")
            if rp["failed"]:                         # ★[M-80 F3] 판정 내구성
                # 이미 ATTEST_FAIL로 미이행 판정된 청구를 피고인 앵커가 DELIVER로
                # 무효화하던 구멍의 봉합 — S-2(사고 채널)를 「끌 수 없는 방어」로 만든다.
                # 판정은 법이지 정산으로 덮이지 않는다([정리 A] 계보).
                raise Fl21Error("DELIVER: 실패 판정된 청구는 이행 종결 불가(정산 대기)")
            self._close_cov(ref)
            self.S += self._consume([rp["nid"]], f"@redeem:{ref}", None)
            del self.redeem_pending[ref]
        elif typ == "REDEEM_CANCEL":
            ref = args["ref"]
            rp = self.redeem_pending.get(ref)
            if rp is None or p != rp["holder"]:
                raise Fl21Error("REDEEM_CANCEL: 청구자 아님")
            self._close_cov(ref)
            self.notes[rp["nid"]]["owner"] = rp["holder"]
            del self.redeem_pending[ref]
        elif typ == "UW":                            # ★U-1 부분 담보 인수(개설-계열 발화)
            uwp, ref = args["uw"], args["ref"]
            cov_ids, prem = args["cov_notes"], args["prem"]
            fund_ids = args.get("prem_fund_notes", [])
            if p != uwp:
                raise Fl21Error("UW: 행위자 = 인수자")
            if g["redeem_T"] <= 0:
                raise Fl21Error("UW: 사고 채널 OFF 세계(redeem_T=0)에선 인수 없음")
            rp = self.redeem_pending.get(ref)
            if rp is None:
                raise Fl21Error("UW: 미지 상환 청구")
            if ref in self.uw_open:
                raise Fl21Error("UW: 이미 인수된 청구(v0.1 단일 인수)")
            if rp["failed"]:
                raise Fl21Error("UW: 이미 실패 판정된 청구")
            if uwp in (rp["holder"], rp["anchor"]):
                raise Fl21Error("UW: 자기-당사자 인수 금지(법 ⑤ 계보)")
            if rp["holder"] == rp["anchor"]:
                raise Fl21Error("UW: 자기-상환 청구는 인수 불가(법 ⑤ 계보)")
            if not _nonneg_int(prem):
                raise Fl21Error("UW: 보험료 비정수/음수")
            exposure = self.notes[rp["nid"]]["face"]
            if prem * g["prem_floor_den"] < exposure * g["prem_floor_num"]:
                raise Fl21Error("UW: 요율 하한 미달(prem_floor)")
            if not cov_ids or len(set(cov_ids)) != len(cov_ids):
                raise Fl21Error("UW: 담보 노트 공백/중복")
            if set(cov_ids) & set(fund_ids):         # ★[M-80 F1] 담보∩기금 서로소 강제
                raise Fl21Error("UW: 담보 노트와 기금 노트는 서로소여야 한다")
            cov = 0
            for nid in cov_ids:
                if not self._own(nid, uwp):
                    raise Fl21Error(f"UW: 담보 노트 {nid} 미소유")
                cov += self.notes[nid]["face"]
            if cov > exposure:
                raise Fl21Error("UW: β > 1(과담보) 금지 — β ∈ (0,1]")
            if cov * g["beta_min_den"] < exposure * g["beta_min_num"]:
                raise Fl21Error("UW: β_min 미달(인가 문턱)")
            prem_f = prem * g["uw_phi_num"] // g["uw_phi_den"]
            if g["fq_mult"] > 0 and \
               self.F_uw + prem_f > g["fq_mult"] * max(self.F_peak, g["fq_base"]):
                prem_f = 0                   # ★v0.2 적정성-결박 흡입 — 상한 넘길 적립 정지
                # ⚙️[M-80 F6] 증분을 사전 검사에 포함 — F_uw ≤ cap 보장(단발 초과 봉합).
                # 측정 세계는 prem_f ≤ 1이라 구 게이트(F_uw ≥ cap)와 행동 동일(판정 불변).
            self.F_uw += self._consume(fund_ids, uwp, prem_f)   # F_uw 몫(정확액 — SPLIT 선행)
            for nid in cov_ids:
                self.notes[nid]["owner"] = f"@uw:{ref}"
            self.uw_open[ref] = {"uw": uwp, "cov": list(cov_ids), "prem": prem}
        elif typ in ("ATTEST_OK", "ATTEST_FAIL"):    # ★S-2(G2-4a) — reason은 판정 아님
            if p != "operator":
                raise Fl21Error("ATTEST: v0.1 검증자 좌석 = operator(정직 한정어 ⓐ)")
            if g["redeem_T"] <= 0:
                raise Fl21Error("ATTEST: 사고 채널 OFF 세계(redeem_T=0)")
            ref = args["ref"]
            rp = self.redeem_pending.get(ref)
            if rp is None:
                raise Fl21Error("ATTEST: 미지 상환 청구")
            role = args.get("role")                   # ★[M-80] G2-4a (ref, role, reason)
            if role is not None and role not in ("producer", "attester"):
                raise Fl21Error("ATTEST: role ∈ {producer, attester}(선택 귀속 필드)")
            # role은 선택 — 제공되면 검증되고 args로 로그 env(head)에 결박된다(명세 정합).
            reason = args.get("reason")
            if not isinstance(reason, str) or not (1 <= len(reason) <= 64):
                raise Fl21Error("ATTEST: reason_code는 1~64자 문자열(발화지 판정 아님)")
            if typ == "ATTEST_FAIL":
                if rp["failed"]:
                    raise Fl21Error("ATTEST_FAIL: 이미 실패 기록")
                rp["failed"] = True                  # 조기 성숙 — 정산은 TICK 일괄
        elif typ == "BLOCK":
            return self._apply_block(args["legs"], p)
        elif typ == "TICKMARK":
            pass
        else:
            raise Fl21Error(f"미지 타입 {typ} — 경로 밖 연산은 없다")
        return None

    def _apply_block(self, legs, submitter):
        """원자 all-or-nothing(§5-b · FL2.0 승계) — 임의 흐름 허용(가격은 노트-흐름 창발)."""
        if not isinstance(legs, list) or not legs:
            raise Fl21Error("BLOCK: 다리 목록 비었음")
        for leg in legs:
            if leg["p"] == submitter:
                raise Fl21Error("BLOCK: 제출자는 다리 서명자를 겸할 수 없다(nonce 이중 사용)")
            self._verify_env(leg)
            self._apply(leg["typ"], leg["args"], leg["p"])
            self.nonces[leg["p"]] = leg["nonce"] + 1
        return {"block_legs": len(legs)}

    def audit(self):
        seed, label, agents, genconf, bridge = self._genesis
        w = World(seed, label, agents, gen=dict(genconf), bridge_ref=bridge)
        prev = "genesis"
        for e in self.log:
            try:
                r = w._commit(e["env"], replay=True)
            except Fl21Error as ex:
                return {"ok": False, "why": f"리플레이 거부 seq {e['seq']}: {ex}"}
            if r["state_root"] != e["state_root"] or r["head"] != e["head"] \
               or e["prev"] != prev or r["w_epoch"] != e["w_epoch"] \
               or r.get("_force") != e.get("_force"):
                return {"ok": False, "why": f"결박 불일치 seq {e['seq']}"}
            prev = e["head"]
        if w.state_root() != self.state_root():
            return {"ok": False,
                    "why": "★살아 있는 상태 ≠ 리플레이 상태 — 경로 밖 기입 검출(K-0ⓔ)"}
        op_pk = self.reg.pk("operator")
        for e in self.log:
            if "head_sig" not in e:
                return {"ok": False, "why": f"헤드 서명 부재 seq {e['seq']}"}
            try:
                Ed25519PublicKey.from_public_bytes(op_pk).verify(
                    bytes.fromhex(e["head_sig"]), FL21_DOMAIN + bytes.fromhex(e["head"]))
            except (InvalidSignature, ValueError):
                return {"ok": False, "why": f"헤드 서명 불일치 seq {e['seq']}"}
        return {"ok": True, "entries": len(self.log)}
