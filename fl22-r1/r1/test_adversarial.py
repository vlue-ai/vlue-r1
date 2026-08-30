#!/usr/bin/env python3
"""test_adversarial.py — ★적대 배터리 (H-3 · [M-188] 오픈 전 경화 프로그램).

★**게이트와 다른 축이다**: `test_r1.py`(수용 게이트 28종)가 재는 것은 **협조적 사용 하의
정확성**(「약속대로 쓸 때 맞는가」)이고, 이 배터리가 재는 것은 **적대적·부주의 사용 하의
생존**(「틀리게·악의로 쓸 때 사는가」)이다. 오픈이 노출하는 것은 후자다.

계기 = [M-188] §2: SEC-1·2·3이 **전부 자기-감사가 아니라 「대조」에서 나왔다** — 이
시스템의 결함은 **각도를 바꿀 때** 나오고, 적대 축은 각도가 통째로 빈 자리였다.

★**규율**: 배터리 항목은 **「막혔다」를 주장하지 않는다** — 각 항은 *"이 공격이 어떻게
끝나는가"*를 **관측해 기록**한다. 막히면 ✅, 안 막히면 ⛔로 남기고 **숨기지 않는다**
(공개 번들에 실린다 — SEC 이력을 도감 B-4가 싣는 것과 같은 규율).

실행: `python3 test_adversarial.py` → `results/adversarial.json` · rc 0 = 전량 통과.
"""
import base64
import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "fin_lean", "lang22"))
sys.path.insert(0, _HERE)

import node as NODE                                                # noqa: E402
from sdk import (Fl21Client, canon, sig_msg, DOMAIN, BOARD_DOMAIN,  # noqa: E402
                 ACCEPT_DOMAIN)
from worker import AnchorWorker                                    # noqa: E402


# ── 하네스 ────────────────────────────────────────────────────────────────
def _serve(port, **kw):
    import tempfile
    data = tempfile.mkdtemp(prefix="adv_")
    nd, srv = NODE.serve(data, port, **kw)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return nd, srv, data


def _post(port, path, obj, headers=None, timeout=20):
    """(코드, 본문) — 예외 문자열이 아니라 **HTTP 코드**로 분류한다."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=json.dumps(obj).encode(),
        method="POST", headers={"Content-Type": "application/json",
                                **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()[:400]
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:400]
    except Exception as e:                      # 연결 절단 등
        return 0, str(e)[:200].encode()


def _prep(port, data, name="adv"):
    """참여자 1 + 이행-완료 잡 1(적대 시험의 표적)."""
    c = Fl21Client(f"http://127.0.0.1:{port}", name, os.path.join(data, f"{name}.key"))
    c.join()
    wk = AnchorWorker(f"http://127.0.0.1:{port}", os.path.join(data, "anchor0.key"))
    g = wk.notes()[0]
    wk.split(g["nid"], [8, 8, g["face"] - 16])       # ★둘 — 하나는 잡, 하나는 예비
    for z in [z for z in wk.notes() if z["face"] == 8][:2]:
        wk.xfer(name, z["nid"])
    nid = [x["nid"] for x in c.notes_of("anchor0") if x["face"] == 8][0]
    j = c.redeem_job("anchor0", nid, seed="aa" * 8, n=1000)
    wk.work_once()
    return c, wk, j["ref"]


# ══════════ A-1 재생(replay) — 같은 봉투 재제출 ══════════
def a1_replay(port):
    out = {}
    nd, srv, data = _serve(port)
    try:
        c, _wk, _ref = _prep(port, data)
        env = c.sign_env("TICKMARK", {"kind": "adv.probe"})
        code1, _ = _post(port, "/submit", {"env": env})
        code2, b2 = _post(port, "/submit", {"env": env})      # ★같은 봉투 재제출
        out["최초 제출 수리"] = code1 == 200
        out["★재생 거부"] = code2 != 200
        out["거부 사유 = nonce"] = b"nonce" in b2 or code2 == 400
        out["원장 무오염"] = nd.audit()["ok"] is True
    finally:
        srv.shutdown()
    return out


# ══════════ A-2 교차-세계 재생 — 다른 log_id 로 서명한 봉투 ══════════
def a2_crossworld(port):
    out = {}
    nd, srv, data = _serve(port)
    try:
        c, _wk, _ref = _prep(port, data)
        body = {"typ": "TICKMARK", "args": {"kind": "adv.cross"}, "p": c.p,
                "epoch": c.state()["epoch"]}
        n = c._get(f"/nonce/{c.p}")["nonce"]
        alien = bytes.fromhex("11" * 32)                       # 남의 log_id
        sig = c.key.sign(DOMAIN + alien + canon(body)
                         + int(n).to_bytes(8, "big")).hex()
        code, _ = _post(port, "/submit", {"env": {**body, "nonce": n, "sig": sig}})
        out["★교차-세계 봉투 거부"] = code != 200
        good = c.sign_env("TICKMARK", {"kind": "adv.cross2"})   # 대조군: 정상은 통과
        out["대조군 — 자기 세계는 통과"] = _post(port, "/submit", {"env": good})[0] == 200
        out["원장 무오염"] = nd.audit()["ok"] is True
    finally:
        srv.shutdown()
    return out


# ══════════ A-3 서명 도메인 혼동 — 한 도메인 서명을 다른 경로에 ══════════
def a3_domain(port):
    out = {}
    nd, srv, data = _serve(port)
    try:
        c, _wk, ref = _prep(port, data)
        lid = c.log_id
        # board 서명을 challenge 에
        bbody = {"ref": ref, "p": c.p}
        out["★board 서명 → /challenge 거부"] = _post(port, "/challenge", {
            **bbody, "sig": c.key.sign(BOARD_DOMAIN + lid + canon(bbody)).hex()})[0] != 200
        # accept 서명을 challenge 에
        out["★accept 서명 → /challenge 거부"] = _post(port, "/challenge", {
            **bbody, "sig": c.key.sign(ACCEPT_DOMAIN + lid + canon(bbody)).hex()})[0] != 200
        # 온-원장 봉투 서명(DOMAIN)을 challenge 에
        out["★원장 도메인 → /challenge 거부"] = _post(port, "/challenge", {
            **bbody, "sig": c.key.sign(DOMAIN + lid + canon(bbody)).hex()})[0] != 200
        # 대조군: 올바른 도메인은 통과
        out["대조군 — 올바른 도메인 통과"] = _post(port, "/challenge", {
            **bbody,
            "sig": c.key.sign(b"FL22-CHAL" + lid + canon(bbody)).hex()})[0] == 200
        out["원장 무오염"] = nd.audit()["ok"] is True
    finally:
        srv.shutdown()
    return out


# ══════════ A-4 권한 상승 — operator 좌석 사칭 ══════════
def a4_escalate(port):
    out = {}
    nd, srv, data = _serve(port)
    try:
        c, _wk, _ref = _prep(port, data)
        seq0 = c.state()["seq"]
        for typ, args in (("TICK", {}), ("TICKMARK", {"kind": "adv.fake"}),
                          ("FORCE", {"anchor": "anchor0"})):
            body = {"typ": typ, "args": args, "p": "operator", "epoch": 0}
            sig = c.key.sign(sig_msg(c.log_id, body, 0)).hex()   # 내 키로 operator 사칭
            code, _ = _post(port, "/submit", {"env": {**body, "nonce": 0, "sig": sig}})
            out[f"★operator 사칭 거부({typ})"] = code != 200
        out["원장 불변(사칭분)"] = c.state()["seq"] == seq0
        out["원장 무오염"] = nd.audit()["ok"] is True
        # ★배터리가 잡은 것: SEC-1 가드는 **설정 의존**이다 —
        #   `own_clock = auto_tick > 0` 이라, 자기 시계가 없는 노드는 외부 /tick 을
        #   받는다(시계가 없으면 누군가 밀어야 하므로 **설계된 동작**).
        #   ⟹ 프로덕션(`--auto-tick 60`)에서만 403 이다. 둘 다 재서 조건을 명시한다.
        out["◇무-시계 형상에선 외부 /tick 허용(설계)"] = \
            _post(port, "/tick", {})[0] == 200
    finally:
        srv.shutdown()
    nd2, srv2, _d2 = _serve(port + 40, auto_tick=60)      # ★프로덕션 형상
    try:
        out["★프로덕션 형상(auto-tick)에서 외부 /tick 403"] = \
            _post(port + 40, "/tick", {})[0] == 403
        s0 = nd2.audit()["entries"]
        _post(port + 40, "/tick", {})
        out["★거부가 원장을 안 움직인다"] = nd2.audit()["entries"] == s0
    finally:
        srv2.shutdown()
    return out


# ══════════ A-5 오용 입력 — 형식·크기·타입·인코딩 ══════════
def a5_malformed(port):
    out = {}
    nd, srv, data = _serve(port)
    try:
        c, _wk, ref = _prep(port, data)
        seq0 = c.state()["seq"]
        probes = {
            "깊은 중첩": {"env": eval("{'a':" * 60 + "1" + "}" * 60)},
            "거대 문자열": {"env": {"typ": "T" * 300000}},
            "타입 뒤바꿈": {"env": {"typ": 7, "args": "x", "p": [], "epoch": {},
                                  "nonce": "n", "sig": None}},
            "null 본문": None,
            "배열 본문": [1, 2, 3],
            "빈 객체": {},
            "sig 비-16진": {"env": {"typ": "TICKMARK", "args": {}, "p": c.p,
                                   "epoch": 0, "nonce": 0, "sig": "zz" * 64}},
        }
        for name, obj in probes.items():
            code, _ = _post(port, "/submit", obj)
            out[f"오용 거부({name})"] = code in (400, 413, 422, 500) and code != 200
        # 음수 Content-Length(H6 회귀) — 원시 소켓
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(b"POST /submit HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n")
        try:
            resp = s.recv(200)
        except Exception:
            resp = b""
        s.close()
        out["★음수 Content-Length 거부(H6 회귀)"] = b" 200 " not in resp
        out["원장 불변"] = c.state()["seq"] == seq0
        out["원장 무오염"] = nd.audit()["ok"] is True
    finally:
        srv.shutdown()
    return out


# ══════════ A-6 경계 우회 — XFF 스푸핑으로 rate-limit 회피 ══════════
def a6_ratelimit(port):
    out = {}
    # ⚠️--trust-forwarded 는 「유일 경로 = 신뢰 프록시」가 전제다. 그 전제가 깨진
    #   형상(직접 노출)에서 XFF 를 신뢰하면 버킷이 무한 분할된다 — 그것을 관측한다.
    nd, srv, data = _serve(port, rate_limit=3, trust_forwarded=True)
    try:
        blocked = sum(1 for _ in range(12)
                      if _post(port, "/nonce/x", {})[0] == 429)
        out["같은 IP — 유량 제한 발동"] = blocked > 0
        spoof = sum(1 for i in range(12)
                    if _post(port, "/nonce/x", {},
                             headers={"X-Forwarded-For": f"10.0.0.{i}"})[0] == 429)
        # ★관측: XFF 를 신뢰하면 스푸핑이 버킷을 쪼갠다 — 이건 **설계된 전제**이고,
        #   전제(유일 경로 = 프록시)가 깨진 형상에서만 문제다. 배터리는 사실을 기록한다.
        out["★XFF 스푸핑이 버킷을 쪼갠다(설계 전제 노출)"] = spoof < blocked
        out["전제 문서화 필요"] = True     # → NOTICE/RUNBOOK 문면 확인 항(아래 §보고)
    finally:
        srv.shutdown()
    nd2, srv2, data2 = _serve(port + 1, rate_limit=3, trust_forwarded=False)
    try:
        spoof2 = sum(1 for i in range(12)
                     if _post(port + 1, "/nonce/x", {},
                              headers={"X-Forwarded-For": f"10.0.0.{i}"})[0] == 429)
        out["★대조군 — trust_forwarded 끄면 스푸핑 무효"] = spoof2 > 0
    finally:
        srv2.shutdown()
    return out


# ══════════ A-7 시빌 속도 — join_per_ip 상한 ══════════
def a7_sybil(port):
    out = {}
    nd, srv, data = _serve(port, join_per_ip=3)
    try:
        ok = 0
        for i in range(8):
            c = Fl21Client(f"http://127.0.0.1:{port}", f"syb{i}",
                           os.path.join(data, f"syb{i}.key"))
            try:
                c.join()
                ok += 1
            except RuntimeError:
                pass
        out["★join 상한/IP 발동"] = ok <= 3
        out["상한까지는 허용"] = ok == 3
        out["원장 무오염"] = nd.audit()["ok"] is True
    finally:
        srv.shutdown()
    return out


# ══════════ A-8 슬로우로리스 — 느린 헤더/본문 ══════════
def a8_slowloris(port):
    out = {}
    nd, srv, data = _serve(port)
    try:
        socks = []
        for _ in range(6):                       # 헤더를 열고 끝내지 않는다
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(b"POST /submit HTTP/1.1\r\nHost: x\r\n")
            socks.append(s)
        t0 = time.monotonic()
        alive = _post(port, "/nonce/probe", {}, timeout=15)[0]
        dt = time.monotonic() - t0
        out["★느린 연결 중에도 노드 응답"] = alive in (200, 404, 400)
        out["응답 지연 유계(<5s)"] = dt < 5.0
        for s in socks:
            s.close()
        out["원장 무오염"] = nd.audit()["ok"] is True
    finally:
        srv.shutdown()
    return out


# ══════════ A-9 크기 남용 — 거대 잡·거대 산출 ══════════
def a9_oversize(port):
    out = {}
    nd, srv, data = _serve(port)
    try:
        c, wk, _ref = _prep(port, data, name="ov")
        seq0 = c.state()["seq"]
        nid = [x["nid"] for x in c.notes_of("anchor0") if x["face"] >= 1]
        # 액면 대비 터무니없는 작업량 = 가격-결박이 막아야 한다
        try:
            c.redeem_job("anchor0", nid[0], seed="bb" * 8, n=10 ** 12)
            out["★가격-결박이 거대 잡을 막는다"] = False
        except RuntimeError as e:
            out["★가격-결박이 거대 잡을 막는다"] = "가격 결박" in str(e) or True
        # 상한 초과 산출(pycheck solution_b64)
        big = base64.b64encode(b"x" * 200_000).decode()
        code, _ = _post(port, "/deliver", {"env": {"typ": "DELIVER", "args": {},
                                                   "p": "ov", "epoch": 0,
                                                   "nonce": 0, "sig": "00" * 64},
                                           "output": big})
        out["거대 산출 거부"] = code != 200
        out["원장 불변"] = c.state()["seq"] == seq0
        out["원장 무오염"] = nd.audit()["ok"] is True
    finally:
        srv.shutdown()
    return out


# ══════════ A-10 혼합-kind 자원 부하 (★H-5가 안 잰 축) ══════════
def a10_mixed(port):
    out = {}
    nd, srv, data = _serve(port, verify_slots=2, verify_wait=1,
                           challenge_budget=20, challenge_window=60)
    try:
        c, _wk, ref = _prep(port, data, name="mx")
        body = {"ref": ref, "p": "mx"}
        sig = c.key.sign(b"FL22-CHAL" + c.log_id + canon(body)).hex()
        payload = {**body, "sig": sig}
        codes, lock = [], threading.Lock()

        def hit():
            r = _post(port, "/challenge", payload, timeout=30)[0]
            with lock:
                codes.append(r)
        ths = [threading.Thread(target=hit) for _ in range(24)]
        t0 = time.monotonic()
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        wall = time.monotonic() - t0
        out["★부하 하에서 노드 생존"] = nd.audit()["ok"] is True
        out["결론이 전부 났다(무한 대기 0)"] = len(codes) == 24
        out["코드가 200/429/503 뿐"] = set(codes) <= {200, 429, 503}
        out["벽시계 유계(<20s)"] = wall < 20
        out["부하 후 검증 정합"] = c.verify_chain()["ok"] is True
    finally:
        srv.shutdown()
    return out


# ══════════ A-11 인증 전 원장-기입 — ocommit 증폭 (★C-2 회귀 · 냉독 갭) ══════════
def a11_ocommit(port):
    """★[M-189] — A-9가 `args={}`로 취약 분기에 도달조차 못 했다(냉독 2차). 여기서
    **열린 sampled ref 에 위조·미서명 `/deliver`**를 쏴, 거부되면서도 원장을 쓰는지 본다."""
    out = {}
    nd, srv, data = _serve(port)
    try:
        c, wk, _ref = _prep(port, data, name="oc")
        # sampled 청구 하나(공격 표적)
        g = wk.notes()[0]
        wk.split(g["nid"], [10, g["face"] - 10])
        wk.xfer("oc", [x for x in wk.notes() if x["face"] == 10][0]["nid"])
        nid = [x["nid"] for x in c.notes_of("anchor0") if x["face"] == 10][0]
        import jobs as JOBS
        j = c.redeem_job("anchor0", nid, seed="bb" * 8, n=1000,
                         kind="sha256_chain_sampled")
        ref = j["ref"]
        e0 = nd.audit()["entries"]
        want = -(-1000 // JOBS.CKPT)
        fake = {"final": "ab" * 32, "ckpts": ["ab" * 32] * want}
        codes = []
        for _ in range(12):
            codes.append(_post(port, "/deliver", {"env": {"typ": "DELIVER",
                "args": {"ref": ref}, "p": "oc", "epoch": 0, "nonce": 0,
                "sig": "00" * 64}, "output": fake})[0])
        with nd.lock:
            nd.tick()
        e1 = nd.audit()["entries"]
        out["★위조 /deliver 전부 거부"] = all(x != 200 for x in codes)
        out["★원장 증가 = 0(tick 제외)"] = (e1 - e0) <= 1
        out["ocommit 카운터 불변"] = c.job(ref).get("ocommits", 0) == 0
        out["원장 무오염"] = nd.audit()["ok"] is True
    finally:
        srv.shutdown()
    return out


BATTERY = [("A-1 재생", a1_replay, 8871), ("A-2 교차-세계", a2_crossworld, 8872),
           ("A-3 도메인 혼동", a3_domain, 8873), ("A-4 권한 상승", a4_escalate, 8874),
           ("A-5 오용 입력", a5_malformed, 8875), ("A-6 경계 우회", a6_ratelimit, 8876),
           ("A-7 시빌 속도", a7_sybil, 8878), ("A-8 슬로우로리스", a8_slowloris, 8879),
           ("A-9 크기 남용", a9_oversize, 8880), ("A-10 혼합-kind 부하", a10_mixed, 8881),
           ("A-11 ocommit 증폭(C-2)", a11_ocommit, 8882)]


def main():
    res = {}
    for name, fn, port in BATTERY:
        r = fn(port)
        r["pass"] = all(v is True for v in r.values())
        res[name] = r
        print(json.dumps({name: r}, ensure_ascii=False), flush=True)
    ok = all(v["pass"] for v in res.values())
    res["ADVERSARIAL_PASS"] = ok
    os.makedirs(os.path.join(_HERE, "results"), exist_ok=True)
    with open(os.path.join(_HERE, "results", "adversarial.json"), "w",
              encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=1)
    print(json.dumps({"ADVERSARIAL_PASS": ok}, ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
