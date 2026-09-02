#!/usr/bin/env python3
"""kernel23_gates_fl23.py — FL2.3 신설 게이트(델타 8 + F-K1 + 「치환은 assert」 + 차등).
승계 20 은 kernel23_selftest.py · 이 파일은 세대가 더한 것만 잰다. 실행: python3 kernel23_gates_fl23.py
→ FL23_GATES_PASS. 정본 = FL23_DESIGN §8·§9 · core/FL23_SCOPE_RESEARCH §6(술어 1·3·5·6·7)."""
import hashlib
import json
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from kernel23 import (World, Fl23Error, derive_key, _canon, _LIST_MAX,      # noqa: E402
                      _BLOCK_LEGS_MAX, FL23_DOMAIN)


def _in(w, who, amt):
    w.submit(w.sign_env("operator", "EXT_IN", {"to": who, "amount": amt}))


def _ln(w, owner):
    return max((nid for nid, n in w.notes.items() if n["owner"] == owner), key=int)


def _split(w, owner, nid, parts):
    w.submit(w.sign_env(owner, "SPLIT", {"owner": owner, "note": nid, "parts": parts}))


def _pk(seed, name):
    return derive_key(seed, name).public_key().public_bytes_raw().hex()


def _try(w, env):
    try:
        w.submit(env)
        return None
    except Fl23Error as e:
        return str(e)


def _state_sans_nonce(w):
    """★J-7: 인증-거부는 nonce 를 소비하므로 「상태 불변」은 nonce 를 제외한 상태로 잰다."""
    return _canon({"notes": w.notes, "maps": {m: getattr(w, m) for m in World._MAPS if m != "nonces"},
                   "lists": {l: getattr(w, l) for l in World._LISTS},
                   "scalars": {s: getattr(w, s) for s in World._SCALARS}, "fp": w.reg.fp})


def _redeem(w, holder, nid, anchor):
    w.submit(w.sign_env(holder, "REDEEM", {"holder": holder, "note": nid, "anchor": anchor}))
    return next(r for r, rp in w.redeem_pending.items() if rp["nid"] == nid)


def gate_TBUDGET():
    """★J-3 EXIT-회수 — identity_budget 은 생존-상한 · 이름 재사용 불가 · 퇴장 신원 발화 금지."""
    out = {}
    w = World(gen={"identity_budget": 5})           # 창세 4 + 1 자리
    j = lambda n: w.sign_env("operator", "JOIN", {"principal": n, "pk": _pk(99, n)})
    out["JOIN b1 성공"] = _try(w, j("b1")) is None
    w.rekey_local("b1", derive_key(99, "b1"))       # 시험용 서명 키 등록(레지스트리 무접촉)
    out["JOIN b2 소진 거부"] = "identity_budget" in (_try(w, j("b2")) or "")
    out["EXIT b1"] = _try(w, w.sign_env("b1", "EXIT", {"a": "b1"})) is None
    out["★회수 후 JOIN b2 성공"] = _try(w, j("b2")) is None
    out["이름 재사용 거부(b1)"] = "재등록" in (_try(w, j("b1")) or "")
    out["퇴장 신원 발화 금지"] = "퇴장" in (_try(w, w.sign_env("b1", "TICKMARK", {})) or "")
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TREKEY():
    """★J-4 REKEY — 소유-증명·즉시 발효·구-키 거부·제3자 회전 거부·키-일정 리플레이·operator 회전."""
    out = {}
    w = World()
    _in(w, "a1", 10)
    new_priv = derive_key(7, "a1-next")
    new_pk = new_priv.public_key().public_bytes_raw()
    new_sig = new_priv.sign(w.rekey_msg("a1", new_pk)).hex()
    # 제3자 회전 시도(a2 가 a1 을) → 인증된 실패 = REJECT 기록
    n0 = len(w.log)
    r = _try(w, w.sign_env("a2", "REKEY", {"principal": "a1", "new_pk": new_pk.hex(), "new_sig": new_sig}))
    out["제3자 회전 거부"] = r is not None and "본인" in r and len(w.log) == n0 + 1 and w.log[-1].get("kind") == "REJECT"
    # 소유-증명 위조
    r = _try(w, w.sign_env("a1", "REKEY", {"principal": "a1", "new_pk": new_pk.hex(), "new_sig": "00" * 64}))
    out["소유-증명 부재 거부"] = r is not None and "소유-증명" in r
    # 정당 회전
    out["REKEY 수용"] = _try(w, w.sign_env("a1", "REKEY", {"principal": "a1", "new_pk": new_pk.hex(), "new_sig": new_sig})) is None
    out["레지스트리 신-키"] = w.reg.pk("a1") == new_pk and w.reg.links[-1][3] == "rekey"
    # 구-키 서명 → 미인증 거부(무기록)
    n1 = len(w.log)
    r = _try(w, w.sign_env("a1", "TICKMARK", {}))    # _keys 는 아직 구-키
    out["구-키 거부(무기록)"] = r is not None and "서명 검증 실패" in r and len(w.log) == n1
    w.rekey_local("a1", new_priv)
    out["신-키 수리"] = _try(w, w.sign_env("a1", "XFER", {"frm": "a1", "to": "a2", "note": _ln(w, "a1")})) is None
    # operator 회전 — 노드 임계구역 절차의 커널 몫
    op_new = derive_key(7, "op-next"); op_pk = op_new.public_key().public_bytes_raw()
    op_sig = op_new.sign(w.rekey_msg("operator", op_pk)).hex()
    out["operator REKEY 수용"] = _try(w, w.sign_env("operator", "REKEY", {"principal": "operator", "new_pk": op_pk.hex(), "new_sig": op_sig})) is None
    w.rekey_local("operator", op_new)
    _in(w, "a3", 4)                                   # 신-키 head_sig 항
    w.tick()
    # 키-일정 리플레이: 창세 재료만으로 전-로그 검증(REKEY 이후 항은 신-키로 head_sig 검증)
    pks = {p: derive_key(2, p).public_key().public_bytes_raw().hex() for p in ("operator", "a0", "a1", "a2", "a3")}
    pub = World.from_public(pks, "fl23-ref", ("a0", "a1", "a2", "a3"))
    rr = pub.replay_verify(w.log)
    out["★키-일정 공개 리플레이"] = rr["ok"] is True and rr["state_root"] == w.state_root()
    # 변조: operator REKEY 항의 new_pk 를 바꾸면 이후 head_sig 검증이 깨져야
    import copy as _c
    bad = _c.deepcopy(w.log)
    k = next(i for i, e in enumerate(bad) if e["env"]["typ"] == "REKEY" and e["env"]["p"] == "operator")
    bad[k]["env"]["args"]["new_pk"] = _pk(5, "x")
    pub2 = World.from_public(pks, "fl23-ref", ("a0", "a1", "a2", "a3"))
    out["키-일정 변조 검출"] = pub2.replay_verify(bad)["ok"] is False
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TROOTINC():
    """★J-5 증분 root == 전량 root · 거부 op 는 root 불변 · 색인 누계 == 스캔."""
    import random
    out = {}
    w = World(gen={"redeem_T": 4})
    rng = random.Random(5)
    agents = ("a0", "a1", "a2", "a3")
    for a in agents:
        _in(w, a, 40)
    roots_ok = True
    for i in range(120):
        s0 = _state_sans_nonce(w)
        a = rng.choice(agents)
        mine = [nid for nid, n in w.notes.items() if n["owner"] == a]
        try:
            if not mine or rng.random() < 0.15:
                w.submit(w.sign_env(a, "XFER", {"frm": a, "to": "a0", "note": "99999"}))   # 무효
            elif rng.random() < 0.5:
                nid = rng.choice(mine); f = w.notes[nid]["face"]
                _split(w, a, nid, [1, f - 1] if f > 1 else [1, 1])
            elif rng.random() < 0.7 and len(mine) >= 2:
                w.submit(w.sign_env(a, "MERGE", {"owner": a, "notes": mine[:2]}))
            else:
                w.submit(w.sign_env(a, "XFER", {"frm": a, "to": rng.choice(agents), "note": rng.choice(mine)}))
            if rng.random() < 0.1:
                w.tick()
        except Fl23Error:
            roots_ok &= (_state_sans_nonce(w) == s0)     # 거부 = 상태 불변(nonce 소비·REJECT 항 제외)
            roots_ok &= (w.log[-1]["state_root"] == w.state_root())   # REJECT 항의 root == 현재 root
        if i % 17 == 0:
            roots_ok &= (w._root_full() == w.state_root())
    out["★증분 root == 전량 root · 거부 시 불변"] = roots_ok
    out["색인 누계 == 스캔"] = w._face_total == sum(n["face"] for n in w.notes.values()) and \
        all(w.bal(a) == sum(n["face"] for n in w.notes.values() if n["owner"] == a) for a in agents)
    try:
        w._invariants(); out["전-상태 불변식"] = True
    except Fl23Error:
        out["전-상태 불변식"] = False
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TNOTECAP():
    """★J-6 상태-상한 — 자발 민트만 검사 · 법-구동 민트(배상)는 면제 · MERGE 로 회수."""
    out = {}
    w = World(gen={"notes_per_owner_max": 3, "redeem_T": 4})
    _in(w, "a1", 30)
    _split(w, "a1", _ln(w, "a1"), [10, 10, 10])
    out["상한 내 SPLIT 수용(3)"] = len([1 for n in w.notes.values() if n["owner"] == "a1"]) == 3
    r = _try(w, w.sign_env("a1", "SPLIT", {"owner": "a1", "note": _ln(w, "a1"), "parts": [5, 5]}))
    out["★상한 초과 SPLIT 거부"] = r is not None and "노트-수 상한" in r and "MERGE" in r
    r = _try(w, w.sign_env("operator", "EXT_IN", {"to": "a1", "amount": 1}))
    out["상한 초과 EXT_IN 거부"] = r is not None and "노트-수 상한" in r
    ids = sorted(nid for nid, n in w.notes.items() if n["owner"] == "a1")
    out["MERGE 회수"] = _try(w, w.sign_env("a1", "MERGE", {"owner": "a1", "notes": ids[:2]})) is None
    big = _ln(w, "a1"); f = w.notes[big]["face"]
    out["회수 후 SPLIT 수용"] = _try(w, w.sign_env("a1", "SPLIT", {"owner": "a1", "note": big, "parts": [f // 2, f - f // 2]})) is None
    # 법-구동 민트 면제: a1 이 상한(3)에 있을 때 부보 청구가 정산되며 배상이 a1 에게 민트돼야 한다
    w2 = World(gen={"notes_per_owner_max": 3, "redeem_T": 4})
    _in(w2, "a1", 30)
    _split(w2, "a1", _ln(w2, "a1"), [10, 10, 10])
    ids2 = sorted((nid for nid, n in w2.notes.items() if n["owner"] == "a1"), key=int)
    ref = _redeem(w2, "a1", ids2[0], "a0")           # a1 live 2 + 에스크로 1
    _in(w2, "a1", 1)                                 # a1 다시 3 = 상한
    _in(w2, "a2", 20)
    _split(w2, "a2", _ln(w2, "a2"), [10, 10])
    cov = [nid for nid, n in w2.notes.items() if n["owner"] == "a2"][:1]
    w2.submit(w2.sign_env("a2", "UW", {"uw": "a2", "ref": ref, "cov_notes": cov, "prem": 0}))
    for _ in range(4):
        w2.tick()
    rec = [e for e in w2.log if e["env"]["typ"] == "TICK" and "_force" in e][-1]["_force"]["settled"][0]
    out["★법-구동 배상 민트 면제(상한 초과 허용)"] = rec["comp"] == 10 and w2.notes[rec["comp_nid"]]["owner"] == "a1" and \
        len([1 for n in w2.notes.values() if n["owner"] == "a1"]) == 4 and w2.audit()["ok"]
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TREJECT():
    """★J-7 인증-거부 기록 — 비-operator 실패 = REJECT 항 + nonce 소비 + 상태 불변 · operator 실패 = 무기록 ·
    같은 봉투 재생 = nonce 거부(무기록) · 공개 리플레이가 REJECT 를 재유도 · 변조 검출."""
    out = {}
    w = World()
    _in(w, "a0", 10)
    nid = _ln(w, "a0")
    s0, n0, non0 = _state_sans_nonce(w), len(w.log), w.nonces.get("a1", 0)
    env = w.sign_env("a1", "XFER", {"frm": "a1", "to": "a0", "note": nid})   # 미소유 → _apply 실패
    r = _try(w, env)
    e = w.log[-1]
    out["★REJECT 항 기록"] = r is not None and len(w.log) == n0 + 1 and e.get("kind") == "REJECT" and e["env"] is env
    out["nonce 소비"] = w.nonces.get("a1") == non0 + 1
    out["상태 불변(nonce 제외)"] = _state_sans_nonce(w) == s0 and e["state_root"] == w.state_root()
    out["reason 정보 필드"] = "미소유" in e["reason"] and "reason" not in json.dumps(e["head"])
    r2 = _try(w, env)                                  # 같은 봉투 재생
    out["★재생 = nonce 거부·무기록"] = r2 is not None and "nonce" in r2 and len(w.log) == n0 + 1
    # operator 실패는 무기록
    n1 = len(w.log)
    r3 = _try(w, w.sign_env("operator", "EXT_IN", {"to": "ghost", "amount": 1}))
    out["operator 실패 무기록"] = r3 is not None and len(w.log) == n1 and w.nonces.get("operator", 0) == w.nonces.get("operator", 0)
    # 스키마 실패도 인증됐으면 REJECT
    r4 = _try(w, w.sign_env("a1", "SPLIT", {"owner": "a1", "note": nid}))   # parts 누락
    out["스키마 실패 = REJECT"] = r4 is not None and "스키마" in r4 and w.log[-1].get("kind") == "REJECT"
    w.tick()
    pks = {p: derive_key(2, p).public_key().public_bytes_raw().hex() for p in ("operator", "a0", "a1", "a2", "a3")}
    pub = World.from_public(pks, "fl23-ref", ("a0", "a1", "a2", "a3"))
    rr = pub.replay_verify(w.log)
    out["★공개 리플레이가 REJECT 재유도"] = rr["ok"] is True and rr["state_root"] == w.state_root() and rr["reason_warn"] == 0
    import copy as _c
    bad = _c.deepcopy(w.log)
    k = next(i for i, x in enumerate(bad) if x.get("kind") == "REJECT")
    bad[k]["env"]["args"]["note"] = "77"
    pub2 = World.from_public(pks, "fl23-ref", ("a0", "a1", "a2", "a3"))
    out["REJECT 변조 검출"] = pub2.replay_verify(bad)["ok"] is False
    del bad[k]                                        # REJECT 항 삭제 → prev 사슬/상태 불일치
    pub3 = World.from_public(pks, "fl23-ref", ("a0", "a1", "a2", "a3"))
    out["REJECT 삭제 검출"] = pub3.replay_verify(bad)["ok"] is False
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TSCHEMA():
    """★J-8 입력-스키마 — 필수 필드·타입·상한·다리 수·중첩 금지 · 확장 필드 허용(스펙-불투명) · 형태 실패는 무상태."""
    out = {}
    w = World()
    _in(w, "a1", 20)
    nid = _ln(w, "a1")
    # ★봉투는 제출 직전에 서명한다 — J-7 이 거부마다 nonce 를 소비하므로 미리 서명한 묶음은 뒤에서 nonce-불일치가 된다
    bad = [
        ("필수 누락", lambda: w.sign_env("a1", "XFER", {"frm": "a1", "note": nid})),
        ("타입", lambda: w.sign_env("a1", "SPLIT", {"owner": "a1", "note": nid, "parts": "1,1"})),
        ("리스트 상한", lambda: w.sign_env("a1", "MERGE", {"owner": "a1", "notes": ["1"] * (_LIST_MAX + 1)})),
        ("문자열 상한", lambda: w.sign_env("a1", "TICKMARK", {"kind": "x" * 600})),
        ("다리 수", lambda: w.sign_env("operator", "BLOCK", {"legs": [w.sign_env("a1", "TICKMARK", {})] * (_BLOCK_LEGS_MAX + 1)})),
        ("중첩 BLOCK", lambda: w.sign_env("operator", "BLOCK", {"legs": [w.sign_env("a1", "BLOCK", {"legs": []})]})),
    ]
    for name, mk in bad:
        s0 = _state_sans_nonce(w)
        r = _try(w, mk())
        out[f"거부: {name}"] = r is not None and ("스키마" in r or "다리" in r) and _state_sans_nonce(w) == s0
    # 확장 필드는 통과(r1 의 spec_sha256 등 — 커널은 스펙을 해석하지 않는다)
    out["★확장 필드 허용(스펙-불투명)"] = _try(w, w.sign_env("a1", "REDEEM", {"holder": "a1", "note": nid, "anchor": "a0",
                                                                     "spec_sha256": "ab" * 32, "k": 4})) is None
    # 봉투 형태(여분 키) = 미인증 무기록
    n0 = len(w.log)
    env = w.sign_env("a1", "TICKMARK", {}); env["extra"] = 1
    r = _try(w, env)
    out["봉투 여분 키 = 형태 거부·무기록"] = r is not None and "필드 집합" in r and len(w.log) == n0
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TIMPORT():
    """★J-11 GENESIS_IMPORT — 첫 엔트리 전용 · 스냅샷 해시 결박 · 보존식(ext_in = Σface+F+F_uw) · 예산 · 리플레이."""
    out = {}
    snap = {"principals": [{"p": "z1", "pk": _pk(11, "z1")}, {"p": "z2", "pk": _pk(11, "z2")}],
            "notes": [{"owner": "z1", "face": 10, "issuer": "z1"}, {"owner": "a0", "face": 5, "issuer": "z2"}],
            "F": 3, "F_uw": 4, "exited": ["z2"]}
    h = hashlib.sha256(_canon(snap)).hexdigest()
    w = World(gen={"identity_budget": 8})
    out["★수입 수용(첫 엔트리)"] = _try(w, w.sign_env("operator", "GENESIS_IMPORT", {"snapshot_hash": h, **snap})) is None
    out["보존식 ext_in = Σface+F+F_uw"] = (w.ext_in, w.F, w.F_uw, w.bal("z1"), w.bal("a0")) == (22, 3, 4, 10, 5)
    out["exited 수입"] = "z2" in w.exited and "퇴장" in (_try(w, w.sign_env("operator", "EXT_IN", {"to": "z2", "amount": 1})) or "")
    out["두 번째 수입 거부"] = "첫 엔트리" in (_try(w, w.sign_env("operator", "GENESIS_IMPORT", {"snapshot_hash": h, **snap})) or "")
    w2 = World(gen={"identity_budget": 8})
    out["해시 불일치 거부"] = "snapshot_hash" in (_try(w2, w2.sign_env("operator", "GENESIS_IMPORT", {"snapshot_hash": "00" * 32, **snap})) or "")
    snap3 = {**snap, "notes": [{"owner": "z2", "face": 1, "issuer": "z2"}]}
    h3 = hashlib.sha256(_canon(snap3)).hexdigest()
    out["퇴장 소유자 노트 거부"] = "퇴장" in (_try(w2, w2.sign_env("operator", "GENESIS_IMPORT", {"snapshot_hash": h3, **snap3})) or "")
    snap4 = {**snap, "principals": [{"p": f"q{i}", "pk": _pk(11, f"q{i}")} for i in range(6)], "exited": []}
    snap4["notes"] = []
    h4 = hashlib.sha256(_canon(snap4)).hexdigest()
    out["identity_budget 초과 거부"] = "identity_budget" in (_try(w2, w2.sign_env("operator", "GENESIS_IMPORT", {"snapshot_hash": h4, **snap4})) or "")
    _in(w, "z1", 2); w.tick()
    pks = {p: derive_key(2, p).public_key().public_bytes_raw().hex() for p in ("operator", "a0", "a1", "a2", "a3")}
    pub = World.from_public(pks, "fl23-ref", ("a0", "a1", "a2", "a3"), gen={"identity_budget": 8})
    rr = pub.replay_verify(w.log)
    out["★공개 리플레이(수입 포함)"] = rr["ok"] is True and rr["state_root"] == w.state_root()
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TFORCEFIX():
    """★F-K1 봉합 — REQUEST 내부 봉투가 _apply 도중 실패해도 부분-변이 0 · 이후 TICK 정상 · included:False ·
    내부 서명자 nonce 소비(J-7)."""
    out = {}
    w = World()
    _in(w, "a0", 10)
    nid = _ln(w, "a0")
    inner = w.sign_env("a0", "SPLIT", {"owner": "a0", "note": nid, "parts": [1, 1]})   # 합 불일치 — 소비 후 실패
    w.request(inner)
    ok = True
    for _ in range(6):
        try:
            w.tick()
        except Fl23Error:
            ok = False
    out["★TICK 웨지 없음(6틱)"] = ok and w.epoch == 6
    out["부분-변이 0(노트 생존)"] = nid in w.notes and w.notes[nid]["face"] == 10
    fo = [e["_force"] for e in w.log if e["env"]["typ"] == "FORCE"]
    out["included:False 기록"] = len(fo) == 1 and fo[0]["included"] is False
    out["내부 서명자 nonce 소비"] = w.nonces.get("a0") == inner["nonce"] + 1
    out["pending 소진"] = not w.pending
    out["audit"] = w.audit()["ok"]
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TPRIM():
    """★「치환은 assert」 — _apply/_settle/헬퍼에 직접 대입 잔존 0(저널 프리미티브 경유 100%)."""
    sys.path.insert(0, _HERE)
    import diff_storm23
    bad = diff_storm23.prim_audit()
    return {"직접 대입 잔존": bad, "pass": bad == []}


def gate_TJOURNAL():
    """★술어 3 차등 — kernel22‖kernel23 무작위 폭풍(시드 3 × 150 op): 수용/거부 열·잔고 멀티셋·_force 동일."""
    r = subprocess.run([sys.executable, os.path.join(_HERE, "diff_storm23.py"), "11,22,33", "150"],
                       capture_output=True, text=True, timeout=900)
    last = [ln for ln in r.stdout.splitlines() if ln.startswith("{")]
    ok = bool(last) and json.loads(last[-1]).get("DIFF_STORM_PASS") is True
    return {"tail": r.stdout.splitlines()[-4:], "pass": ok}


def run_all():
    out = {"T-BUDGET 생존-상한(J-3)": gate_TBUDGET(), "T-REKEY 키-회전(J-4)": gate_TREKEY(),
           "T-ROOTINC 증분root(J-5)": gate_TROOTINC(), "T-NOTECAP 상태-상한(J-6)": gate_TNOTECAP(),
           "T-REJECT 인증-거부기록(J-7)": gate_TREJECT(), "T-SCHEMA 입력-스키마(J-8)": gate_TSCHEMA(),
           "T-IMPORT 승계수입(J-11)": gate_TIMPORT(), "T-FORCEFIX 웨지봉합(F-K1)": gate_TFORCEFIX(),
           "T-PRIM 치환assert": gate_TPRIM(), "T-JOURNAL 차등(술어3)": gate_TJOURNAL()}
    return out


def main():
    out = run_all()
    out["verdict"] = {k: v["pass"] for k, v in out.items()}
    out["verdict"]["FL23_GATES_PASS"] = all(out["verdict"].values())
    os.makedirs(os.path.join(_HERE, "results"), exist_ok=True)
    with open(os.path.join(_HERE, "results", "kernel23_gates_fl23.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=1, default=str)
    print(json.dumps(out["verdict"], ensure_ascii=False, indent=1))
    for k, v in out.items():
        if k != "verdict" and not v["pass"]:
            print("FAIL", k, json.dumps({a: b for a, b in v.items() if b is not True}, ensure_ascii=False, default=str)[:400])
    return 0 if out["verdict"]["FL23_GATES_PASS"] else 1


if __name__ == "__main__":
    sys.exit(main())
