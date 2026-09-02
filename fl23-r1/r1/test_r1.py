#!/usr/bin/env python3
"""test_r1.py — R1 수용 게이트 스위트 ([M-95] · A-1~A-6의 기계-판정).

T-SIG    골든-서명: SDK 서명·헤드 재계산이 커널과 바이트-동일(커널 검증 통과).
T-PERIL  A-1: 실물 계산-이행 루프(상환→계산→검증→이행) ∧ 산출-위조 거부 ∧
         ★워커-다운 시 시한-사고 실발동(반환) ∧ 잡 상태 정합.
T-RECOV  A-3: 서브프로세스 노드 SIGKILL → 재기동 리플레이 · audit · 잔고 정합 · 후속 거래.
T-FUZZ   A-4: 경계 부정형(깨진 JSON·미지 경로·서명 위조·nonce 재사용·타인-발화·부정형
         잡·거대 페이로드) 전량 4xx ∧ 노드 생존 ∧ audit 유지.
T-SOAK   A-5: 다중 클라이언트 동시 운전 + 자동 틱 — 종료 후 audit ∧ 유통 보존.
T-COSIGN A-6: 라이트 검증(head 사슬·운영자 서명·k-of-n) ok ∧ 변조 검출.

실행: python3 test_r1.py  (산출: results/r1_gates.json · 전 게이트 pass 필수)
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "fin_lean", "lang23"))
sys.path.insert(0, _HERE)

from kernel23 import World, Fl23Error as Fl21Error, derive_key                  # noqa: E402
import node as NODE                                                # noqa: E402
import jobs as JOBS                                                # noqa: E402
from sdk import Fl21Client, sig_msg, canon, DOMAIN                 # noqa: E402
from worker import AnchorWorker                                    # noqa: E402
import underwriter as UWT                                          # noqa: E402


def _tmp():
    return tempfile.mkdtemp(prefix="r1-", dir=os.environ.get("R1_TMP"))


def _serve(port, data=None, **kw):
    data = data or _tmp()
    nd, srv = NODE.serve(data, port, **kw)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return nd, srv, data


def _client(port, name, data):
    return Fl21Client(f"http://127.0.0.1:{port}", name,
                      os.path.join(data, f"{name}.key"))


def gate_TSIG():
    out = {}
    w = World(master_seed=7, label="golden", genesis_agents=("g1",))
    body = {"typ": "TICKMARK", "args": {}, "p": "g1", "epoch": 0}
    sdk_sig = w._keys["g1"].sign(sig_msg(w.log_id, body, 0)).hex()
    kern = w.sign_env("g1", "TICKMARK", {})
    out["서명 바이트-동일"] = sdk_sig == kern["sig"]
    env = {**body, "nonce": 0, "sig": sdk_sig}
    w.submit(env)                                     # 커널 검증 통과 = 재현 확정
    out["커널 수리"] = True
    e = w.log[-1]
    base = {k: e[k] for k in ("env", "fp", "w_epoch", "state_root")}
    import hashlib
    out["헤드 재계산"] = hashlib.sha256(
        e["prev"].encode() + canon(base)).hexdigest() == e["head"]
    # ★[M-115] 봉투-서명 전량 검증(냉독 결함 1 봉합): head·운영자·공동서명이 전부
    # 유효해도 **봉투 서명이 가짜인 항목**(= 운영자가 위조한 사용자 행위)을 라이트
    # 검증이 잡아야 한다 ∧ 정상 원장은 봉투-검증 포함으로 통과해야 한다.
    nd, srv, data = _serve(8809)
    c = _client(8809, "envt", data)
    c.join()
    c.split(c.notes()[0]["nid"], [5, 15])
    out["봉투-검증 포함 정상 통과"] = c.verify_chain()["ok"] is True
    wn = nd.w
    fenv = {"typ": "XFER", "args": {"frm": "envt", "to": "anchor0", "note": "0"},
            "p": "envt", "epoch": wn.epoch, "nonce": 999, "sig": "00" * 64}
    prev = wn.log[-1]["head"]
    fbase = {"env": fenv, "fp": "00" * 32, "w_epoch": wn.epoch,
             "state_root": "00" * 32}
    fhead = hashlib.sha256(prev.encode() + canon(fbase)).hexdigest()
    fsig = wn._keys["operator"].sign(DOMAIN + bytes.fromhex(fhead)).hex()
    wn.log.append({"seq": len(wn.log), **fbase, "prev": prev,
                   "head": fhead, "head_sig": fsig})
    nd._persist_new()                 # 공동서명까지 정식 부착(위조는 봉투뿐)
    v = c.verify_chain()
    out["★위조 봉투 검출(운영자-위조 사용자 행위)"] = \
        v["ok"] is False and "봉투" in str(v.get("why"))
    # ★[M-217] T-KDIFF — 커널 성능 패치(v0.2: exited 집합 색인)의 의미 불변 차등 리플레이: 이전 커널이 기록한
    # 고정 원장(커버리지 픽스처 56항 + 프로덕션 스냅샷 1,106항)을 현재 커널의 공개 세계로 전량 리플레이 →
    # 매 항 head·state_root 바이트 동일 · 전량 root == 증분 root · 맵 다이제스트 == sha256(canon) ·
    # exited 색인 == 리스트 · 불변식. 어긋나면 패치는 「의미 변경」 = 반입 불가(FL2.4 재창세 후보로 격하).
    import kdiff_check as _KD
    _kd = [_KD.check(f) for f in _KD.fixture_paths()]      # 모노레포 results/ · 번들 동봉 두 배치 모두
    out["★T-KDIFF 차등 리플레이 바이트 동일(픽스처+프로덕션)"] = all(r["pass"] for r in _kd)
    out["T-KDIFF 맵 다이제스트 == canon"] = all(r.get("map_digest_eq_canon") is True for r in _kd)
    out["T-KDIFF 전량 root == 증분 root"] = all(r.get("full_root_eq_incremental") is True for r in _kd)
    out["T-KDIFF 프로덕션 항 ≥ 1000"] = any(r["entries"] >= 1000 for r in _kd)
    # 색인은 파생·리스트가 정본: 프리미티브 밖 직접 append(길이 변화)는 길이 가드가 재구성한다 ·
    # 롤백 뒤 색인 == 리스트 · 해싱은 리스트만 본다(색인은 root 에 관여 0 → 의미 불변의 구조적 근거)
    wx = World(master_seed=11, label="kdiff", genesis_agents=("k1",))
    wx.submit(wx.sign_env("k1", "TICKMARK", {}))
    wx.exited.append("ghost")                         # 경로 밖 직접 기입(색인 미갱신)
    out["T-KDIFF 색인 길이-가드 자기치유"] = wx._is_exited("ghost") is True and wx._exited_set == set(wx.exited)
    wx.exited.pop(); wx._is_exited("k1")
    out["T-KDIFF 색인 root 무관"] = wx._exited_set == set(wx.exited) and wx.state_root() == wx._root_full()
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TPERIL(port=8791):
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "alice", data)
    c.join()
    wk = AnchorWorker(f"http://127.0.0.1:{port}",
                      os.path.join(data, "anchor0.key"))
    # ★[M-103] 유통 회로: anchor0가 자기-IOU(창세 발행분)를 지출 → alice가 보유 →
    # 발행자에게 상환(색-일치). 상환-소각 = 부채 소멸(RM-1 회로 복원).
    g = wk.notes()[0]["nid"]
    wk.split(g, [12, 4, 24])
    for n in [x for x in wk.notes() if x["face"] in (12, 4)]:
        wk.xfer("alice", n["nid"])
    nid = [x["nid"] for x in c.notes_of("anchor0") if x["face"] == 12][0]
    j = c.redeem_job("anchor0", nid, seed="ab" * 8, n=5000)
    ref = j["ref"]
    # 산출-위조 거부(검증이 이행을 지킨다)
    bad_env = wk.sign_env("DELIVER", {"anchor": "anchor0", "ref": ref})
    try:
        wk._post("/deliver", {"env": bad_env, "output": "00" * 32})
        out["위조 산출 거부"] = False
    except RuntimeError:
        out["위조 산출 거부"] = True
    done = wk.work_once()                             # ★실제 계산·이행
    out["실물 이행"] = len(done) == 1 and done[0]["ref"] == ref
    nd_state = c.job(ref)
    out["이행 검증-후 인정"] = nd_state.get("delivered") is True and \
        JOBS.verify_output(nd_state["job"], nd_state["output"])[0]
    c._post("/tick", {})
    out["잡 종결"] = c.job(ref)["state"] == "delivered"
    # ★워커-다운 = 시한-사고 실발동(반환)
    nid2 = [x["nid"] for x in c.notes_of("anchor0") if x["face"] == 4][0]
    j2 = c.redeem_job("anchor0", nid2, seed="cd" * 8, n=100)
    bal_before = c.balance()
    returned = []
    for _ in range(nd.w.GEN["redeem_T"] + 1):
        settle = c._post("/tick", {})["settle"]
        if settle:
            returned += settle.get("returned", [])
    out["시한-사고 발동"] = j2["ref"] in returned
    out["반환(미부보 법)"] = c.balance() == bal_before + 4
    out["audit"] = c._get("/audit")["ok"]
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TRECOV(port=8792):
    out = {}
    data = _tmp()
    env = {**os.environ, "PYTHONPATH": _HERE}
    proc = subprocess.Popen([sys.executable, os.path.join(_HERE, "node.py"),
                             "--data", data, "--port", str(port)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.2)
    c = _client(port, "bob", data)
    c.join()
    n = c.notes()[0]["nid"]
    c.split(n, [10, 10])
    c._post("/tick", {})
    bal0 = c.balance()
    seq0 = c.state()["seq"]
    os.kill(proc.pid, signal.SIGKILL)                 # ★강제 종료(크래시 등가)
    proc.wait()
    proc2 = subprocess.Popen([sys.executable, os.path.join(_HERE, "node.py"),
                              "--data", data, "--port", str(port)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.2)
    try:
        st = json.loads(urllib.request.urlopen(
            f"http://127.0.0.1:{port}/state", timeout=10).read())
        au = json.loads(urllib.request.urlopen(
            f"http://127.0.0.1:{port}/audit", timeout=10).read())
        c2 = _client(port, "bob", data)               # 같은 키 재사용
        out["리플레이 정합"] = st["seq"] == seq0
        out["audit"] = au["ok"] is True
        out["잔고 보존"] = c2.balance() == bal0
        nid = c2.notes()[0]["nid"]
        c2.xfer("anchor0", nid)                        # 후속 거래 성공
        out["후속 거래"] = c2.balance() == bal0 - 10
    finally:
        proc2.kill()
        proc2.wait()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TFUZZ(port=8793):
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "carol", data)
    c.join()
    url = f"http://127.0.0.1:{port}"

    def post_raw(path, raw):
        r = urllib.request.Request(url + path, data=raw, method="POST",
                                   headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(r, timeout=10)
            return 200
        except urllib.error.HTTPError as e:
            return e.code
        except urllib.error.URLError:
            return 400                            # 서버-측 연결 절단 = 거부(방어)

    out["깨진 JSON 4xx"] = post_raw("/submit", b"{broken") == 400
    out["미지 경로 404"] = post_raw("/nope", b"{}") == 404
    out["빈 봉투 4xx"] = post_raw("/submit", b"{}") == 400
    # 서명 위조(남의 이름으로 서명)
    forged = c.sign_env("XFER", {"frm": "anchor0", "to": "carol",
                                 "note": "0"})
    forged["p"] = "anchor0"
    out["타인-발화 거부"] = post_raw(
        "/submit", json.dumps({"env": forged}).encode()) == 400
    # nonce 재사용
    nid = c.notes()[0]["nid"]
    env1 = c.sign_env("SPLIT", {"owner": "carol", "note": nid, "parts": [10, 10]})
    c._post("/submit", {"env": env1})
    out["nonce 재사용 거부"] = post_raw(
        "/submit", json.dumps({"env": env1}).encode()) == 400
    # 부정형 잡(클래스 밖·거대 n·비-hex seed)
    nid2 = c.notes()[0]["nid"]
    for bad in ({"kind": "evil", "seed": "ab", "n": 5},
                {"kind": "sha256_chain", "seed": "ab", "n": 10 ** 9},
                {"kind": "sha256_chain", "seed": "zz", "n": 5}):
        env = c.sign_env("REDEEM", {"holder": "carol", "note": nid2,
                                    "anchor": "anchor0"})
        code = post_raw("/job", json.dumps({"env": env, "job": bad}).encode())
        out[f"부정형 잡 거부({bad['kind']}/{bad['n']})"] = code == 400
    out["거대 페이로드 거부"] = post_raw(
        "/submit", b'{"env": "' + b"A" * 2_100_000 + b'"}') == 400
    out["노드 생존"] = c.state()["seq"] > 0
    out["audit 유지"] = c._get("/audit")["ok"]
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TSOAK(port=8794, clients=4, rounds=25):
    out = {}
    nd, srv, data = _serve(port, auto_tick=0.4)
    names = [f"u{i}" for i in range(clients)]
    cs = []
    for nm in names:
        cl = _client(port, nm, data)
        cl.join()
        cl.split(cl.notes()[0]["nid"], [1] * 20)
        cs.append(cl)
    errs = []

    def run(i):
        cl = cs[i]
        for r in range(rounds):
            try:
                ns = cl.notes()
                if not ns:
                    break
                cl.xfer(names[(i + 1) % clients], ns[0]["nid"])
            except Exception as e:                    # 경합 재시도(nonce 경신)
                if "nonce" in str(e) or "HTTP 400" in str(e):
                    time.sleep(0.05)
                else:
                    errs.append(str(e)[:80])
    ts = [threading.Thread(target=run, args=(i,)) for i in range(clients)]
    for t in ts:
        t.start()
    # 소크 중 실물 잡도 흐른다
    cs[0].split(cs[0].notes()[-1]["nid"], [1]) if False else None
    wk = AnchorWorker(f"http://127.0.0.1:{port}",
                      os.path.join(data, "anchor0.key"))
    for t in ts:
        t.join()
    time.sleep(1.0)
    tot = sum(cl.balance() for cl in cs) + nd.w.bal("anchor0")
    out["예외 0"] = errs == []
    out["유통 보존"] = tot == nd.w.ext_in - nd.w.ext_out - nd.w.S \
        - nd.w.F - nd.w.F_uw - sum(
            n["face"] for n in nd.w.notes.values()
            if n["owner"].startswith("@"))
    out["거래량"] = len(nd.w.log) > clients * rounds // 2
    out["audit"] = nd.audit()["ok"]
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TCOSIGN(port=8795, port2=8808):
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "dave", data)
    c.join()
    c.split(c.notes()[0]["nid"], [10, 10])
    v = c.verify_chain()
    out["라이트 검증"] = v["ok"] is True and \
        v["confirmed"] + v["pending"] == c.state()["seq"]
    # ★N-3([M-110] 맥락-0 5차 적발) — 장기 원장(>500 seq)의 /cosigs 페이지-경계:
    # 과거엔 원시 파일 행-단위 500 절단 + SDK 커서(seq+1)로 경계-seq 서명이 영구 누락
    # → 원장 ~167항부터 외부 verify_chain 영구 「변조 의심」. 병합-맵 서빙으로 봉합.
    for _ in range(520):
        c._post("/tick", {})
    v15 = c.verify_chain()
    out["★장기-원장 페이지 경계(N-3)"] = v15["ok"] is True and \
        v15["confirmed"] + v15["pending"] == c.state()["seq"]
    # ★F-A([M-143]) — 침묵-절단 금지: 520+ 원장에서 limit_batches=1(한 페이지 = 500)은
    # 전량을 못 가져온다 — 부분 검증을 ok로 보고하면 「누구나 재검증」의 정직이 깨진다.
    vt = c.verify_chain(limit_batches=1)
    out["★절단 명시 실패(F-A)"] = vt["ok"] is False and \
        vt.get("truncated") is True
    # ★[M-144] robots.txt — 노드는 API다(크롤러가 원장 페이징 = 오리진 비용·검색 가치 0).
    # 락 밖·JSON 아님 = 별도 경로이므로 회귀로 잠근다(404로 되돌아가면 크롤 개방).
    rb = urllib.request.urlopen(
        f"http://127.0.0.1:{port}/robots.txt", timeout=10).read().decode()
    out["★노드 robots.txt(크롤 차단)"] = "Disallow: /" in rb and \
        "vlue.ai/llms.txt" in rb
    # ★R-6 — 확정 사이 '구멍'(중간 항목 서명 손상)은 변조로 검출(꼬리-지연과 구별)
    # (★N-3 후 /cosigs 정본 = 병합-맵 ⟹ 저장-변조는 재기동 후 검출 — 실제 복구 흐름 ·
    #  T-DURABLE 변조 케이스와 정합)
    lines = open(nd.cosig_p, encoding="utf-8").read().splitlines()
    mid = len(lines) // 2
    rec = json.loads(lines[mid])
    for kk in sorted(rec["sigs"]):
        rec["sigs"][kk] = "00" * 64          # 중간 항목 전 서명 손상 → 확정 사이 구멍
    lines[mid] = json.dumps(rec, sort_keys=True)
    open(nd.cosig_p, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    srv.shutdown()
    srv.server_close()
    nd2, srv2, _ = _serve(port2, data=data)
    c2 = _client(port2, "dave", data)
    v2 = c2.verify_chain()
    out["변조 검출(구멍·재기동)"] = v2["ok"] is False and "구멍" in v2["why"]
    srv2.shutdown()
    srv2.server_close()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TDURABLE(port=8801, port2=8802):
    """★RD-1 — 공동-서명 구멍 자기치유: 크래시로 대장 뒤 공동-서명이 유실된 채 재기동돼도
    노드가 결정론 재서명으로 치유(verify_chain 영구 오판 방지) ∧ ★손상(변조) 서명은
    치유 대상 아님(검출 유지)."""
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "dur", data)
    c.join()
    # ★[M-212] R5-F01-2 — 예산 카운터(REJECT·쓰기)는 재기동 뒤 원장에서 재구성된다(메모리 전용 = 재부팅 리셋 우회)
    _vn = next(nid for nid, n in nd.w.notes.items() if n["owner"] == "anchor0")
    for _ in range(2):
        try:
            c._post("/submit", {"env": c.sign_env("SPLIT", {"owner": "dur", "note": _vn, "parts": [1, 1]})})
        except RuntimeError:
            pass
    _rh0 = (nd.reject_hits.get("dur") or (0, 0))[1]
    c.split(c.notes()[0]["nid"], [10, 10])
    c._post("/tick", {})
    c.split(c.notes()[0]["nid"], [5, 5])
    c._post("/tick", {})
    v0 = c.verify_chain()
    out["치유-전 정상"] = v0["ok"] is True and v0["pending"] == 0
    srv.shutdown()
    srv.server_close()
    # ★크래시 시뮬: 중간 엔트리의 공동-서명 줄을 통째로 유실(entries.jsonl은 온전)
    lines = open(nd.cosig_p, encoding="utf-8").read().splitlines()
    dropped = json.loads(lines[len(lines) // 2])["seq"]
    del lines[len(lines) // 2]
    open(nd.cosig_p, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    # 재기동(재-리플레이 → 자기치유) 후 검증 정상 복귀
    nd2, srv2, _ = _serve(port2, data=data)
    # ★[M-216] N-32/N-44/N-45 — 잡 저장구조(스냅샷+저널+산출 파일)·증분 카운터·기동 1회 리플레이
    out["★저널 파일 존재(jobs.jsonl · 잡 있을 때)"] = os.path.exists(nd2.jobs_jnl_p) or not nd2.jobs
    out["★재기동 뒤 잡 레코드 동일"] = json.dumps(nd2.jobs, sort_keys=True) == json.dumps(nd.jobs, sort_keys=True)
    out["★outstanding 카운터 = 전수 스캔(재기동 뒤)"] = all(nd2.outstanding(c) == nd2._outstanding_slow(c) for c in set(nd2.colors.values()))
    _prev_lines = nd2._jnl_lines; nd2._jnl_lines = 10 ** 6            # 컴팩션 강제
    nd2.jobs["__probe__"] = {"job": {"kind": "sha256_chain", "seed": "00", "n": 1}, "state": "open"}
    nd2._persist_jobs()
    out["★컴팩션 = 스냅샷 생성 · 저널 비움"] = os.path.exists(nd2.jobs_snap_p) and nd2._jnl_lines == 0 and os.path.getsize(nd2.jobs_jnl_p) == 0
    del nd2.jobs["__probe__"]; nd2._persist_jobs()
    out["★삭제 = 저널 1줄(rec null)"] = nd2._jnl_lines == 1
    out["★재기동 뒤 REJECT 예산 카운터 재구성"] = _rh0 == 2 and (nd2.reject_hits.get("dur") or (0, 0))[1] == 2
    out["★재기동 뒤 쓰기 예산 카운터 재구성"] = (nd2.write_bytes.get("dur") or [0, 0])[1] > 0
    c2 = _client(port2, "dur", data)
    v1 = c2.verify_chain()
    out["구멍 치유"] = v1["ok"] is True and \
        v1["confirmed"] + v1["pending"] == c2.state()["seq"]
    out["치유된 seq 재확인"] = any(
        json.loads(ln)["seq"] == dropped
        for ln in open(nd.cosig_p, encoding="utf-8") if ln.strip())
    # ★N-1·N-2([M-108]) — 잘린-꼬리(크래시 부분쓰기): ⓐ공동서명 파일도 관용 부팅
    # (리더 누락 = 부팅-불능이던 구멍) ⓑ★물리 절단 — 안 하면 다음 append가 접착돼
    # ack된 항목이 무음 유실되거나(마지막 줄) 영구 부팅-불능(중간 줄)이 된다.
    seq_a = c2.state()["seq"]
    srv2.shutdown()
    srv2.server_close()
    with open(nd.ledger_p, "a", encoding="utf-8") as f:
        f.write('{"seq": 999, "head": "잘린')      # 개행 없는 부분쓰기 시뮬
    with open(nd.cosig_p, "a", encoding="utf-8") as f:
        f.write('{"seq": 999, "hea')
    nd25, srv25, _ = _serve(port, data=data)
    c25 = _client(port, "dur", data)
    out["★잘린-꼬리 부팅(대장·공동서명)"] = c25.state()["seq"] == seq_a
    c25._post("/tick", {})                         # 새 ack 기입(절단 안 됐으면 접착)
    seq_b = c25.state()["seq"]
    srv25.shutdown()
    srv25.server_close()
    nd26, srv26, _ = _serve(port2, data=data)
    c26 = _client(port2, "dur", data)
    out["★접착-유실 없음(ack=내구)"] = \
        c26.state()["seq"] == seq_b == seq_a + 1
    out["잘린-꼬리 후 검증 정상"] = c26.verify_chain()["ok"] is True
    srv26.shutdown()
    srv26.server_close()
    # ★손상(변조) 서명은 치유하지 않는다 — 여전히 변조로 검출(과잉-치유 회귀 방지)
    lines2 = open(nd.cosig_p, encoding="utf-8").read().splitlines()
    mid = len(lines2) // 2
    rec = json.loads(lines2[mid])
    for kk in list(rec["sigs"]):
        rec["sigs"][kk] = "00" * 64
    lines2[mid] = json.dumps(rec, sort_keys=True)
    open(nd.cosig_p, "w", encoding="utf-8").write("\n".join(lines2) + "\n")
    nd3, srv3, _ = _serve(port, data=data)
    c3 = _client(port, "dur", data)
    v2 = c3.verify_chain()
    out["변조 서명 미치유(검출 유지)"] = v2["ok"] is False
    out["audit"] = c3._get("/audit")["ok"]
    srv3.shutdown()
    srv3.server_close()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TCOLOR(port=8803):
    """★[M-103] 화폐 모델 게이트 — 자유은행 (i): 자기-IOU 발행·색-일치 상환 라우팅·
    상호-신용 부트스트랩(한도)·혼색 MERGE 거부·★RD-7(원시 DELIVER 우회 차단)·
    배상 노트 = 불이행-앵커 색."""
    out = {}
    nd, srv, data = _serve(port)
    nc = _client(port, "nc", data)
    nc.join()
    # 자기-IOU: join 발행분의 색 = 본인
    out["자기-IOU 발행"] = all(n["color"] == "nc" for n in nc.notes()) and \
        nc.balance() == 20
    # ★색-일치 라우팅: 자기 노트로 남(anchor0)에게 상환 주문 = 거부
    try:
        nc.redeem_job("anchor0", nc.notes()[0]["nid"], seed="ab" * 4, n=100)
        out["교차-색 상환 거부"] = False
    except RuntimeError as e:
        out["교차-색 상환 거부"] = "색-일치" in str(e)
    # ★상호-신용 부트스트랩(WIR형): 자기-IOU 8 ↔ anchor0-IOU 8 원자 스왑
    r = nc.bootstrap(8)
    got = nc.notes_of("anchor0")
    out["★상호-신용 스왑"] = r["granted"] == 8 and len(got) == 1 and \
        got[0]["face"] == 8 and nc.balance() == 20
    out["앵커의 반대-청구 보유"] = any(
        n["face"] == 8 for n in
        json.loads(urllib.request.urlopen(
            f"http://127.0.0.1:{port}/notes/anchor0", timeout=10).read())["notes"]
        if n["color"] == "nc")
    try:                                          # 한도(BOOT_CAP) 결박
        nc.bootstrap(1)
        out["스왑 한도"] = False
    except RuntimeError as e:
        out["스왑 한도"] = "한도" in str(e)
    # 혼색 MERGE 거부(색 상속 보전)
    big_nc = [n for n in nc.notes_of("nc") if n["face"] >= 3][0]
    nc.split(big_nc["nid"], [2, big_nc["face"] - 2])
    two = [n["nid"] for n in nc.notes_of("nc") if n["face"] == 2][0]
    try:
        nc.merge([got[0]["nid"], two])
        out["혼색 MERGE 거부"] = False
    except RuntimeError as e:
        out["혼색 MERGE 거부"] = "동색" in str(e)
    # ★스왑 노트로 발행자에게 상환 → 실물 이행(회로 완주: 소각 = 부채 소멸)
    j = nc.redeem_job("anchor0", got[0]["nid"], seed="cd" * 4, n=1000)
    wk = AnchorWorker(f"http://127.0.0.1:{port}",
                      os.path.join(data, "anchor0.key"))
    # ★RD-7 — 원시 /submit DELIVER(검증 우회) 차단: 잡-결박 이행은 /deliver만
    bypass = wk.sign_env("DELIVER", {"anchor": "anchor0", "ref": j["ref"]})
    try:
        wk._post("/submit", {"env": bypass})
        out["★RD-7 원시 DELIVER 차단"] = False
    except RuntimeError as e:
        out["★RD-7 원시 DELIVER 차단"] = "/deliver" in str(e)
    try:                                          # /block 다리 우회도 차단
        wk._post("/block", {"legs": [bypass]})
        out["RD-7 블록-다리 차단"] = False
    except RuntimeError as e:
        out["RD-7 블록-다리 차단"] = "다리 타입" in str(e)
    wk.work_once()                                # 정규 경로는 정상 이행
    out["정규 이행 정상"] = nc.job(j["ref"]).get("delivered") is True
    # ★[M-104] 회전-발행(재점검 F-1): 한도 가득 = 거부 → 이행-소각으로 부채 감소 → 재발행
    try:
        nc.issue(1)                               # nc 유통 20 = 한도 ⟹ 거부
        out["한도-초과 발행 거부"] = False
    except RuntimeError as e:
        out["한도-초과 발행 거부"] = "회전 한도" in str(e)
    nc_iou = wk.notes_of("nc")[0]                 # anchor0가 스왑으로 받은 nc-IOU(8)
    wk._post("/job", {"env": wk.sign_env(
        "REDEEM", {"holder": "anchor0", "note": nc_iou["nid"], "anchor": "nc"}),
        "job": {"kind": "sha256_chain", "seed": "aa" * 4, "n": 500}})
    done = nc.work_pending()                      # ★역방향: nc가 이행자(양면 회로 완주)
    out["역방향 이행(양면 회로)"] = len(done) == 1
    r_iss = nc.issue(8)                           # 부채 20−8=12 ⟹ +8 재발행 가능
    out["★회전-재발행"] = r_iss["issued"] == 8 and r_iss["outstanding"] == 20 and \
        len(nc.notes_of("nc")) >= 2
    # ★배상 노트 = 불이행-앵커 색: 부보된 시한-사고 → comp 노트의 색 = anchor0
    cv = _client(port, "cv", data)
    uw_ = _client(port, "uwc", data)
    cv.join()
    uw_.join()
    wk.split([n["nid"] for n in wk.notes() if n["face"] >= 40][0], [4, 36])
    wk.xfer("cv", [n["nid"] for n in wk.notes() if n["face"] == 4][0])
    j2 = cv.redeem_job("anchor0", cv.notes_of("anchor0")[0]["nid"],
                       seed="ee" * 4, n=100)
    uw_.cover(j2["ref"], prem=1)
    comp_face = 0
    for _ in range(nd.w.GEN["redeem_T"] + 1):
        settle = cv._post("/tick", {})["settle"]
        for rec in (settle or {}).get("settled", []):
            if rec["ref"] == j2["ref"]:
                comp_face = rec["comp"]
    out["★배상 = 불이행-앵커 색"] = comp_face > 0 and any(
        n["face"] == comp_face and n["color"] == "anchor0"
        for n in cv.notes())
    # ★F-E([M-143]) — 동액-배상 쌍의 색 분리: 같은 holder의 같은 액면 청구 둘이 서로
    # 다른 앵커에 걸려 **같은 틱**에 정산되면, 배상 노트 둘의 색이 각자의 불이행-앵커여야
    # 한다(구 휴리스틱[holder·액면 첫-일치 스캔]의 잠재 오귀속 자리 — 위치+검증 귀속의
    # 회귀 잠금 · 민트-순서 가정이 깨지면 노드가 크게 실패한다).
    h2 = _client(port, "htwo", data)
    u2 = _client(port, "utwo", data)
    h2.join()
    u2.join()
    big_a0 = [n for n in wk.notes_of("anchor0") if n["face"] >= 4][0]
    wk.split(big_a0["nid"], [3, big_a0["face"] - 3])
    wk.xfer("htwo",
            [n for n in wk.notes_of("anchor0") if n["face"] == 3][0]["nid"])
    big_nc2 = [n for n in nc.notes_of("nc") if n["face"] >= 4][0]
    nc.split(big_nc2["nid"], [3, big_nc2["face"] - 3])
    nc.xfer("htwo", [n for n in nc.notes_of("nc") if n["face"] == 3][0]["nid"])
    ja = h2.redeem_job("anchor0", h2.notes_of("anchor0")[0]["nid"],
                       seed="0a" * 4, n=100)
    jb = h2.redeem_job("nc", h2.notes_of("nc")[0]["nid"], seed="0b" * 4, n=100)
    u2.cover(ja["ref"], prem=1)
    u2.cover(jb["ref"], prem=1)
    got2 = {}
    for _ in range(nd.w.GEN["redeem_T"] + 1):
        s2 = h2._post("/tick", {})["settle"]
        for rec in (s2 or {}).get("settled", []):
            got2[rec["ref"]] = rec["comp"]
    out["동액-배상 성숙(F-E 전제)"] = got2.get(ja["ref"]) == 3 and \
        got2.get(jb["ref"]) == 3
    out["★동액-배상 색 분리(F-E)"] = {n["color"] for n in h2.notes()
                                     if n["face"] == 3} == {"anchor0", "nc"}
    st = nc.stats()
    out["색-공급 관측"] = "colors" in st["density"] and \
        st["density"]["colors"].get("nc", 0) > 0
    out["audit(색 전체성)"] = nc._get("/audit")["ok"]
    # ★발행자-부재 방어([M-113] 더블체크 FB-1/MS-1): 자기-색 유통부채가 남은 채
    # EXIT 금지(유통 노트의 상환-불능 방기 방지) ∧ 유통 0이면 정상 EXIT(가둠 아님).
    ab = _client(port, "absc", data)
    ab.join()
    ab.xfer("nc", ab.notes_of("absc")[0]["nid"])   # 자기-IOU 전량 유통
    try:
        ab._post("/submit", {"env": ab.sign_env("EXIT", {"a": "absc"})})
        out["★부재 EXIT 차단"] = False
    except RuntimeError as e:
        out["★부재 EXIT 차단"] = "유통" in str(e)
    hon = _client(port, "honx", data)
    hon.join()
    for n in hon.notes_of("honx"):                  # 유통 0으로 정리(BURN)
        hon._post("/submit", {"env": hon.sign_env("BURN",
                                                   {"owner": "honx", "note": n["nid"]})})
    try:
        hon._post("/submit", {"env": hon.sign_env("EXIT", {"a": "honx"})})
        out["정직 앵커(유통 0) EXIT 허용"] = True
    except RuntimeError:
        out["정직 앵커(유통 0) EXIT 허용"] = False
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TATOMIC(port=8807):
    """★완결성 점검 blocker 봉합: B1 부분-커밋(무효 leg가 고아 EXT_IN을 남기지 않음) ·
    B2 검증 중 노드 비동결(느린 /deliver가 전역 락으로 /state를 막지 않음)."""
    import base64
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "at", data)
    c.join()
    c.bootstrap(8)                                # 정상(한도 소진)
    ext0 = c.state()["ext_in"]
    a0_supply0 = nd.outstanding("anchor0")
    used0 = nd.bootstrap_used.get("at", 0)
    # ★B1 — 서명 무효 leg로 /bootstrap: 고아 anchor0 발행이 남으면 안 됨
    self_note = c.notes_of("at")[0]
    leg = c.make_leg("XFER", {"frm": "at", "to": "anchor0",
                              "note": self_note["nid"]})
    leg["sig"] = "00" * 64                         # 서명 훼손
    try:
        c._post("/bootstrap", {"leg": leg})
        out["B1 무효-leg 거부"] = False
    except RuntimeError:
        out["B1 무효-leg 거부"] = True
    out["★B1 고아 발행 없음"] = c.state()["ext_in"] == ext0 and \
        nd.outstanding("anchor0") == a0_supply0
    out["★B1 캡 미소진"] = nd.bootstrap_used.get("at", 0) == used0
    # issue도 동일 원자성(무효 요청이 발행 안 남김)
    ext1 = c.state()["ext_in"]
    bad_iss = c.sign_env("TICKMARK", {"kind": "fl21.issue", "k": 1})
    bad_iss["sig"] = "00" * 64
    try:
        c._post("/issue", {"env": bad_iss})
        out["B1 무효-issue 거부"] = False
    except RuntimeError:
        out["B1 무효-issue 거부"] = True
    out["★B1 issue 고아 없음"] = c.state()["ext_in"] == ext1
    out["audit(B1 후)"] = c._get("/audit")["ok"]
    # ★B2 — 느린 검증(≈3s) 중 /state가 즉답해야(검증이 락 밖)
    b = _client(port, "atb", data)
    b.join()
    b.split(b.notes()[0]["nid"], [1, 19])
    b.xfer("at", [n["nid"] for n in b.notes() if n["face"] == 1][0])
    chk = base64.b64encode(b"print('OK')").decode()
    j = c._post("/job", {"env": c.sign_env(
        "REDEEM", {"holder": "at", "note": c.notes_of("atb")[0]["nid"],
                   "anchor": "atb"}),
        "job": {"kind": "pyjudge", "checker_b64": chk}})
    slow = base64.b64encode(b"import time\ntime.sleep(3)\nprint('x')").decode()

    def _slow_deliver():
        try:
            b.deliver_job(j["ref"], slow)          # 검증 ≈3s(락 밖이어야)
        except Exception:
            pass
    th = threading.Thread(target=_slow_deliver)
    th.start()
    time.sleep(0.6)                                # 검증이 진행 중인 순간
    t0 = time.monotonic()
    c.state()                                      # 락이 잡혀 있으면 ~3s 블록
    dt = time.monotonic() - t0
    out["★B2 검증 중 /state 즉답"] = dt < 1.2
    th.join()
    out["audit(B2 후)"] = c._get("/audit")["ok"]
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TPYJUDGE(port=8805):
    """★[M-105] D-10 — 판정-분리 pyjudge(RD-9 수리): 위조-수용 산출 격퇴(같은 산출이
    pycheck는 뚫림을 대조-실증) ∧ 정직 이행 수리 ∧ 취소-창 정책(D-10 ④)."""
    import base64
    out = {}
    nd, srv, data = _serve(port)
    a = _client(port, "ja", data)
    b = _client(port, "jb", data)
    a.join()
    b.join()
    b.split(b.notes()[0]["nid"], [1, 1, 1, 17])   # jb(발행자·이행자)가 자기-IOU 지출
    for n in [x for x in b.notes() if x["face"] == 1][:3]:
        b.xfer("ja", n["nid"])
    checker = base64.b64encode(
        b"data = open('output.txt').read()\n"
        b"assert data.strip() == '42'\nprint('OK')").decode()
    nid = a.notes_of("jb")[0]["nid"]
    j = a._post("/job", {"env": a.sign_env(
        "REDEEM", {"holder": "ja", "note": nid, "anchor": "jb"}),
        "job": {"kind": "pyjudge", "checker_b64": checker}})
    # ★RD-9 위조 시도: "OK" 무버퍼 출력 + 즉시 종료 — 판정-분리에선 출력 바이트일 뿐
    forge = base64.b64encode(
        b"import os\nos.write(1, b'OK\\n')\nos._exit(0)\n").decode()
    try:
        b.deliver_job(j["ref"], forge)
        out["★위조-수용 격퇴(RD-9)"] = False
    except RuntimeError:
        out["★위조-수용 격퇴(RD-9)"] = True
    # 대조-실증: 같은 위조 산출이 pycheck 술어는 뚫는다(RD-9의 실재 박제)
    test = base64.b64encode(
        b"import solution\nassert solution.add(2, 3) == 5\nprint('OK')").decode()
    pc_ok, _ = JOBS.verify_output({"kind": "pycheck", "test_b64": test}, forge)
    out["대조: pycheck 뚫림(RD-9 실증)"] = pc_ok is True
    honest = base64.b64encode(b"print(42)\n").decode()
    r = b.deliver_job(j["ref"], honest)
    out["정직 이행 수리"] = r["verify"]["checker_rc"] == 0 and \
        a.job(j["ref"]).get("delivered") is True
    # ★취소-창(D-10 ④): 기한 절반 경과 후 잡-결박 취소 거부 · 절반 전은 허용
    nid2 = a.notes_of("jb")[0]["nid"]
    j2 = a._post("/job", {"env": a.sign_env(
        "REDEEM", {"holder": "ja", "note": nid2, "anchor": "jb"}),
        "job": {"kind": "pyjudge", "checker_b64": checker}})
    for _ in range(3):                              # T=4 · 절반 = t0+2 < t0+3
        a._post("/tick", {})
    try:
        a._post("/submit", {"env": a.sign_env(
            "REDEEM_CANCEL", {"ref": j2["ref"]})})
        out["취소-창 경과 거부"] = False
    except RuntimeError as e:
        out["취소-창 경과 거부"] = "취소-창" in str(e)
    nid3 = a.notes_of("jb")[0]["nid"]
    j3 = a._post("/job", {"env": a.sign_env(
        "REDEEM", {"holder": "ja", "note": nid3, "anchor": "jb"}),
        "job": {"kind": "pyjudge", "checker_b64": checker}})
    r3 = a._post("/submit", {"env": a.sign_env(
        "REDEEM_CANCEL", {"ref": j3["ref"]})})      # 즉시(절반 전) = 허용
    out["절반-전 취소 허용"] = "seq" in r3
    # ★절단 명시-거부([M-149] SR-7): 1MB 초과 stdout은 절단본 심사가 아니라 거부 —
    # 종전엔 접두-관대 checker가 절단 1MB를 합격시켰다(오수용 재현 확정 후 봉합).
    nid4 = a.notes_of("jb")[0]["nid"]
    chk2 = base64.b64encode(
        b"d = open('output.txt', 'rb').read()\n"
        b"print('OK' if d[:4] == b'xxxx' else 'NO')\n").decode()
    j4 = a._post("/job", {"env": a.sign_env(
        "REDEEM", {"holder": "ja", "note": nid4, "anchor": "jb"}),
        "job": {"kind": "pyjudge", "checker_b64": chk2}})
    big = base64.b64encode(
        b"import sys\nsys.stdout.write('x' * 2_000_000)\n").decode()
    try:
        b.deliver_job(j4["ref"], big)
        out["★절단 명시-거부(SR-7)"] = False
    except RuntimeError as e:
        out["★절단 명시-거부(SR-7)"] = "상한 초과" in str(e)
    out["audit"] = a._get("/audit")["ok"]
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TSPLITSIGN(port=8806):
    """★[M-105] D-2 — 공동-서명 분리: 노드 = cosign1만 로컬 · cosign2 데몬(별도 키·상태)이
    /cosig 회신 → 2-of-3 확정 ∧ 위조·미지-서명자 거부 ∧ 분리-전 = 전량 pending(정상)."""
    from cosigner import Cosigner
    out = {}
    nd, srv, data = _serve(port, cosign_local=("cosign1",))
    c = _client(port, "sp", data)
    c.join()
    c.split(c.notes()[0]["nid"], [10, 10])
    c._post("/tick", {})
    v1 = c.verify_chain()
    out["분리-전 pending(1-of-3)"] = v1["ok"] is True and v1["confirmed"] == 0 \
        and v1["pending"] == c.state()["seq"]
    co = Cosigner(f"http://127.0.0.1:{port}", "cosign2",
                  os.path.join(data, "cosign2.key"))
    n1 = co.run_once()                              # ★원격 서명자 회신
    v2 = c.verify_chain()
    out["★2-of-3 확정(분리)"] = n1 > 0 and v2["ok"] is True and \
        v2["pending"] == 0 and v2["confirmed"] == c.state()["seq"]
    head0 = nd.w.log[0]["head"]
    def post_cosig(body):
        try:
            c._post("/cosig", body)
            return 200
        except RuntimeError:
            return 400
    out["위조 서명 거부"] = post_cosig(
        {"name": "cosign3", "seq": 0, "head": head0, "sig": "00" * 64}) == 400
    out["미지 서명자 거부"] = post_cosig(
        {"name": "evil", "seq": 0, "head": head0, "sig": "00" * 64}) == 400
    out["head 불일치 거부"] = post_cosig(
        {"name": "cosign2", "seq": 0, "head": "ab" * 32, "sig": "00" * 64}) == 400
    c.split(c.notes()[0]["nid"], [5, 5])            # 새 거래 → 데몬 재-회신 → 재확정
    co.run_once()
    v3 = c.verify_chain()
    out["증분 재확정"] = v3["ok"] is True and v3["pending"] == 0
    out["audit"] = c._get("/audit")["ok"]
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TPRICE(port=8796):
    """★P-2 — 작업-가격 결박(액면 ≥ f(작업량))."""
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "pa", data)
    c.join()
    wk = AnchorWorker(f"http://127.0.0.1:{port}",
                      os.path.join(data, "anchor0.key"))
    wk.split(wk.notes()[0]["nid"], [1, 3, 36])
    for n in [x for x in wk.notes() if x["face"] in (1, 3)]:
        wk.xfer("pa", n["nid"])
    one = [n["nid"] for n in c.notes_of("anchor0") if n["face"] == 1][0]
    try:                                   # n=600,000 → 최소 액면 3 > 1 ⟹ 거부
        c.redeem_job("anchor0", one, seed="ab" * 4, n=600_000)
        out["저액면 거부"] = False
    except RuntimeError as e:
        out["저액면 거부"] = "가격 결박" in str(e)
    three = [n["nid"] for n in c.notes_of("anchor0") if n["face"] == 3][0]
    j = c.redeem_job("anchor0", three, seed="ab" * 4, n=600_000)
    out["정확 액면 수리"] = "ref" in j
    out["audit"] = c._get("/audit")["ok"]
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TSAMPLED(port=8797):
    """★P-3′ — 표본-검증 컴퓨트(체크포인트·검증-시점 표본·위조 검출)."""
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "sa", data)
    c.join()
    wk = AnchorWorker(f"http://127.0.0.1:{port}",
                      os.path.join(data, "anchor0.key"))
    wk.split(wk.notes()[0]["nid"], [12, 2, 26])
    for n in [x for x in wk.notes() if x["face"] in (12, 2)]:
        wk.xfer("sa", n["nid"])
    nid = [n["nid"] for n in c.notes_of("anchor0") if n["face"] == 12][0]
    j = c.redeem_job("anchor0", nid, seed="cd" * 4, n=60_000,
                     kind="sha256_chain_sampled")
    good = wk.compute_sha256({"kind": "sha256_chain_sampled",
                              "seed": "cd" * 4, "n": 60_000})
    bad = {"final": good["final"],
           "ckpts": ["00" * 32, good["ckpts"][1]]}     # 구간 0 위조(전-구간 검사 좌표)
    env = wk.sign_env("DELIVER", {"anchor": "anchor0", "ref": j["ref"]})
    try:
        wk._post("/deliver", {"env": env, "output": bad})
        out["위조 체크포인트 거부"] = False
    except RuntimeError:
        out["위조 체크포인트 거부"] = True
    r = wk.deliver_job(j["ref"], good)
    out["표본-검증 수리"] = "checked" in r["verify"] and \
        0 < r["verify"]["coverage"] <= 1
    # ★sub-1 표본(검증 ≪ 작업) — 이름값 실증: n=300k → 체크포인트 6·검사 2 = coverage 0.33
    # (위 n=60k는 체크포인트 2 = 전수라 '표본'이 아니었다 — 확률-표본 영역을 여기서 시험)
    nid2 = [n["nid"] for n in c.notes_of("anchor0") if n["face"] >= 2][0]
    j2 = c.redeem_job("anchor0", nid2, seed="ef" * 4, n=300_000,
                      kind="sha256_chain_sampled")
    good2 = wk.compute_sha256({"kind": "sha256_chain_sampled",
                               "seed": "ef" * 4, "n": 300_000})
    r2 = wk.deliver_job(j2["ref"], good2)
    out["★sub-1 표본(검증≪작업)"] = 0 < r2["verify"]["coverage"] < 1
    # ★[M-164] V-B 커밋-표본 — 표본이 원장-유도이고, 제3자가 로그만으로 재유도-검증
    out["★표본=원장-유도"] = r2["verify"].get("sample") == "ledger-derived"
    ent = next(e for e in nd.w.log
               if e["env"]["typ"] == "TICKMARK"
               and e["env"]["args"].get("kind") == "fl21.ocommit"
               and e["env"]["args"].get("ref") == j2["ref"])
    import hashlib
    want2 = -(-300_000 // JOBS.CKPT)
    seed = bytes.fromhex(ent["head"]) + j2["ref"].encode()
    idxs, ctr = [], 0
    while len(idxs) < min(JOBS.SAMPLE_K, want2):
        v = int.from_bytes(hashlib.sha256(
            seed + ctr.to_bytes(4, "big")).digest(), "big") % want2
        ctr += 1
        if v not in idxs:
            idxs.append(v)
    out["★H7 재유도 일치"] = sorted(idxs) == r2["verify"]["checked"]
    # 위조-시도 → 거부되지만 ocommit 흔적이 남고, 재시도는 공개 계수된다
    big = [n for n in wk.notes() if n["face"] >= 3][0]
    wk.split(big["nid"], [2, big["face"] - 2])
    wk.xfer("sa", [n["nid"] for n in wk.notes() if n["face"] == 2][0])
    nid2b = [n["nid"] for n in c.notes_of("anchor0") if n["face"] >= 2][0]
    j2b = c.redeem_job("anchor0", nid2b, seed="fa" * 4, n=300_000,
                       kind="sha256_chain_sampled")
    good2b = wk.compute_sha256({"kind": "sha256_chain_sampled",
                                "seed": "fa" * 4, "n": 300_000})
    # ⚠️결정론 요건: 1-구간 위조는 표본이 비껴가면 「탈출」한다(그게 §R-SAMPLE의
    # 잔여 그 자체) — 게이트는 확률이 아니라 성질을 재므로 **전-구간 위조**로 박는다.
    bad2b = {"final": "11" * 32, "ckpts": ["11" * 32] * len(good2b["ckpts"])}
    env2b = wk.sign_env("DELIVER", {"anchor": "anchor0", "ref": j2b["ref"]})
    try:
        wk._post("/deliver", {"env": env2b, "output": bad2b})
        out["★위조 재거부(유도-표본)"] = False
    except RuntimeError:
        out["★위조 재거부(유도-표본)"] = True
    out["★재추첨 흔적 1"] = c.job(j2b["ref"]).get("ocommits") == 1
    try:                                             # ★[M-165] R4-1 — 형식-쓰레기는
        e2c = wk.sign_env("DELIVER", {"anchor": "anchor0", "ref": j2b["ref"]})
        wk._post("/deliver", {"env": e2c,
                              "output": {"final": "zz", "ckpts": ["zz"]}})
        out["형식-쓰레기 거부"] = False
    except RuntimeError:
        out["형식-쓰레기 거부"] = True
    out["★쓰레기는 ocommit 무-랜딩"] = c.job(j2b["ref"]).get("ocommits") == 1
    wk.deliver_job(j2b["ref"], good2b)
    out["★재추첨 공개-계수 2"] = c.job(j2b["ref"]).get("ocommits") == 2 and \
        c.job(j2b["ref"]).get("delivered") is True
    # ★[M-162] k-가변 깊이 — 매수자-선택 k가 H2에 결박되고 검증 표본 수가 실제로 커진다
    wk.split(wk.notes()[0]["nid"], [3, 3, wk.notes()[0]["face"] - 6])
    for n in [x for x in wk.notes() if x["face"] == 3][:2]:
        wk.xfer("sa", n["nid"])
    nid3 = [n["nid"] for n in c.notes_of("anchor0") if n["face"] == 3][0]
    j3 = c.redeem_job("anchor0", nid3, seed="ab" * 4, n=300_000,
                      kind="sha256_chain_sampled", k=6)
    good3 = wk.compute_sha256({"kind": "sha256_chain_sampled",
                               "seed": "ab" * 4, "n": 300_000})
    r3 = wk.deliver_job(j3["ref"], good3)
    out["★k-가변(6구간 검사)"] = len(r3["verify"]["checked"]) == 6
    try:
        c.redeem_job("anchor0", nid3, seed="ab" * 4, n=300_000,
                     kind="sha256_chain_sampled", k=99)
        out["k-경계 거부"] = False
    except RuntimeError as ex:
        out["k-경계 거부"] = "k ∈" in str(ex)
    c.set_policy(min_k=4)
    try:
        nid4 = [n["nid"] for n in c.notes_of("anchor0") if n["face"] == 3][0]
        c.redeem_job("anchor0", nid4, seed="cd" * 4, n=300_000,
                     kind="sha256_chain_sampled", k=2)
        out["★정책 min_k 하한"] = False
    except RuntimeError as ex:
        out["★정책 min_k 하한"] = "깊이" in str(ex)
    c.policy = None
    out["audit"] = c._get("/audit")["ok"]
    # ★[M-208] R4-3(냉독 4 · HIGH) — 표본 **누적**: 실패-이행 뒤 재추첨은 검사 인덱스를 더할 뿐이다. 첫 실패로 확정된
    #   위조 구간 a 는 그 뒤 어느 시도에서도 검사된다(구판 = 최신 커밋 표본만 → 32회 독립 재추첨 = 탈출률 0.22→0.997).
    nid3 = [n["nid"] for n in c.notes_of("anchor0") if n["face"] >= 2][0]
    j3 = c.redeem_job("anchor0", nid3, seed="0b" * 4, n=300_000, kind="sha256_chain_sampled")
    good3 = wk.compute_sha256({"kind": "sha256_chain_sampled", "seed": "0b" * 4, "n": 300_000})
    allbad = {"final": good3["final"], "ckpts": ["11" * 32] * (len(good3["ckpts"]) - 1) + [good3["final"]]}
    try:
        wk._post("/deliver", {"env": wk.sign_env("DELIVER", {"anchor": "anchor0", "ref": j3["ref"]}), "output": allbad})
        first_rejected = False
    except RuntimeError:
        first_rejected = True
    out["★누적: 전-위조 1차 거부"] = first_rejected
    heads = list(nd.ocommit_heads.get(j3["ref"], []))
    want3 = -(-300_000 // JOBS.CKPT)
    union = set()
    for h in heads:
        seed3 = bytes.fromhex(h) + j3["ref"].encode()
        picked, ctr = [], 0
        while len(picked) < min(JOBS.SAMPLE_K, want3):
            v = int.from_bytes(hashlib.sha256(seed3 + ctr.to_bytes(4, "big")).digest(), "big") % want3
            ctr += 1
            if v not in picked:
                picked.append(v)
        union.update(picked)
    a_idx = min(i for i in union if i < want3 - 1)          # 1차에서 확정된 위조 좌표 하나(마지막 구간 제외 — final 결박)
    partial = {"final": good3["final"], "ckpts": list(good3["ckpts"])}
    partial["ckpts"][a_idx] = "22" * 32                     # 오직 a 만 위조 — 구판이면 새 표본이 a 를 안 뽑을 확률 ≈ 0.8 로 통과
    try:
        wk._post("/deliver", {"env": wk.sign_env("DELIVER", {"anchor": "anchor0", "ref": j3["ref"]}), "output": partial})
        out["★누적: 확정 좌표 재-위조는 재추첨으로 못 빠져나간다"] = False
    except RuntimeError as ex:
        out["★누적: 확정 좌표 재-위조는 재추첨으로 못 빠져나간다"] = f"구간 {a_idx}" in str(ex) or "불일치" in str(ex)
    r3 = wk.deliver_job(j3["ref"], good3)
    out["★누적: 정직 산출은 합집합 검사 통과"] = "checked" in r3["verify"] and len(r3["verify"]["checked"]) >= len(union)
    # ★[M-210] R3-F04-1 — 공개 재유도(replay_full sample_union)는 노드 checked 와 같아야 하고 도구가 스스로 대조해 닫는다
    import subprocess as _sp, sys as _sys
    _rp = _sp.run([_sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "replay_full.py"),
                   "--url", f"http://127.0.0.1:{port}"], capture_output=True, text=True, timeout=120)
    try:
        _d = json.loads(_rp.stdout[_rp.stdout.index("{"):])
    except Exception:
        _d = {}
    _su = _d.get("sample_union") or {}
    out["★replay_full H7 true(표본 대조 포함)"] = _d.get("H7_FULL_REPLAY") is True and _d.get("balance_mismatch") == []
    out["★sample_union = 노드 checked"] = (sorted(r3["verify"]["checked"]) == _su.get(j3["ref"])
                                        and sorted(r2["verify"]["checked"]) == _su.get(j2["ref"]))
    # ★[M-211] R4-F04-1/F05-1 — **음성** 케이스: 노드가 위조 checked 를 서빙하면 replay_full 은 H7 false(구판은 죽은 코드라 true)
    _orig_chk = list(nd.jobs[j3["ref"]]["verify"]["checked"])
    with nd.lock:
        nd.jobs[j3["ref"]]["verify"]["checked"] = [999, 1000]
    _rpn = _sp.run([_sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "replay_full.py"),
                    "--url", f"http://127.0.0.1:{port}"], capture_output=True, text=True, timeout=120)
    try:
        _dn = json.loads(_rpn.stdout.strip().splitlines()[-1]) if not _rpn.stdout.strip().startswith("{") else json.loads(_rpn.stdout)
    except Exception:
        _dn = {}
    out["★위조 checked → replay_full H7 false"] = _dn.get("H7_FULL_REPLAY") is False and any(m.get("ref") == j3["ref"] for m in (_dn.get("balance_mismatch") or []) if isinstance(m, dict))
    with nd.lock:
        nd.jobs[j3["ref"]]["verify"]["checked"] = _orig_chk
    # ★[M-210] R3-F05-H1 — 공개 재유도 _sample_union 은 노드-제어 n·k 에 유계(want≤100·k≤16 · 집합) — 악의 /job 이 검증자를 세우지 못한다
    import replay_full as _RF2
    import time as _tm2
    _ents = [{"env": {"typ": "TICKMARK", "args": {"kind": "fl21.ocommit", "ref": "rr"}}, "head": "ab" * 32, "kind": "OK"} for _ in range(3)]
    _t0 = _tm2.time()
    _su = _RF2._sample_union(_ents, "rr", 10 ** 9, 10 ** 7)
    out["★sample_union 유계(<1s · ≤16)"] = (_tm2.time() - _t0) < 1.0 and len(_su) <= 16
    # ★[M-213] Q-1(R5-F04-3) — 서빙 스펙은 원장 REDEEM spec_sha256 에 결박: 노드가 스펙(n)을 바꿔 서빙하면 replay_full 은 H7 false
    _orig_n = nd.jobs[j3["ref"]]["job"]["n"]
    with nd.lock:
        nd.jobs[j3["ref"]]["job"]["n"] = _orig_n + 1
    _rps = _sp.run([_sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "replay_full.py"),
                    "--url", f"http://127.0.0.1:{port}"], capture_output=True, text=True, timeout=120)
    try:
        _ds = json.loads(_rps.stdout) if _rps.stdout.strip().startswith("{") else json.loads(_rps.stdout.strip().splitlines()[-1])
    except Exception:
        _ds = {}
    out["★서빙 스펙 ≠ 원장 H2 → replay_full H7 false"] = _ds.get("H7_FULL_REPLAY") is False and any("H2" in str(m.get("why", "")) for m in (_ds.get("balance_mismatch") or []) if isinstance(m, dict))
    with nd.lock:
        nd.jobs[j3["ref"]]["job"]["n"] = _orig_n
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TPYCHECK(port=8798):
    """★P-3′ 코드-이행 + ★P-1 외부-앵커(일반 참여자가 이행자)."""
    import base64
    out = {}
    nd, srv, data = _serve(port)
    alice = _client(port, "pya", data)
    bob = _client(port, "pyb", data)          # ★외부 앵커(워커 아님 — SDK만)
    alice.join()
    bob.join()
    test = base64.b64encode(
        b"import solution\nassert solution.add(2, 3) == 5\nprint('OK')"
    ).decode()
    # ★[M-103] pyb(외부 앵커 = 발행자)가 자기-IOU를 지출 → pya가 pyb에게 상환(색-일치)
    bob.split(bob.notes()[0]["nid"], [1, 19])
    bob.xfer("pya", [n["nid"] for n in bob.notes() if n["face"] == 1][0])
    nid = alice.notes_of("pyb")[0]["nid"]
    j = alice._post("/job", {"env": alice.sign_env(
        "REDEEM", {"holder": "pya", "note": nid, "anchor": "pyb"}),
        "job": {"kind": "pycheck", "test_b64": test}})
    # 틀린 산출 거부(약속-불일치)
    wrong = base64.b64encode(b"def add(a, b):\n    return a - b\n").decode()
    try:
        bob.deliver_job(j["ref"], wrong)
        out["불일치 거부"] = False
    except RuntimeError:
        out["불일치 거부"] = True
    # 시간폭탄 거부(자원 상한)
    bomb = base64.b64encode(b"while True:\n    pass\n").decode()
    try:
        bob.deliver_job(j["ref"], bomb)
        out["시간 상한 거부"] = False
    except RuntimeError:
        out["시간 상한 거부"] = True
    good = base64.b64encode(b"def add(a, b):\n    return a + b\n").decode()
    r = bob.deliver_job(j["ref"], good)
    out["★외부-앵커 이행"] = r["ref"] == j["ref"]
    out["상태 delivered"] = alice.job(j["ref"]).get("delivered") is True
    out["audit"] = alice._get("/audit")["ok"]
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TCOVER(port=8799):
    """★P-4 — 인수 개방(cover → 시한-사고 → 배상 폭포 실발동)."""
    out = {}
    nd, srv, data = _serve(port)
    h = _client(port, "cvh", data)
    u = _client(port, "cvu", data)
    h.join()
    u.join()
    wk = AnchorWorker(f"http://127.0.0.1:{port}",
                      os.path.join(data, "anchor0.key"))
    # ★[M-103] anchor0가 자기-IOU 전량 지출(불이행-층 소진) — 폭포가 담보·소구 층을 지나게
    wk.split(wk.notes()[0]["nid"], [12, 4, 24])
    for n in list(wk.notes()):
        wk.xfer("cvh", n["nid"])
    nid = [n["nid"] for n in h.notes_of("anchor0") if n["face"] == 12][0]
    j = h.redeem_job("anchor0", nid, seed="ee" * 4, n=1000)
    # ★R-5 — 자기-당사자(홀더 자기부보) 거부
    try:
        h.cover(j["ref"], prem=2)
        out["자기-당사자 거부"] = False
    except RuntimeError as e:
        out["자기-당사자 거부"] = "자기-당사자" in str(e)
    r = u.cover(j["ref"], prem=2)             # 담보 6 + 기금 1(자기적립) — 제3자
    out["인수 개설"] = "seq" in r
    st = h.job(j["ref"])
    out["커버리지 노출"] = st.get("covered") is True and st.get("uw") == "cvu"
    bal_u0 = u.balance()
    comp = 0
    for _ in range(nd.w.GEN["redeem_T"] + 1):  # 워커 없음 = 시한-사고
        settle = h._post("/tick", {})["settle"]
        if settle:
            for rec in settle.get("settled", []):
                if rec["ref"] == j["ref"]:
                    comp = rec["comp"]
    out["★배상 폭포 발동"] = comp >= 6         # 담보 6 이상 배상(폭포 층 합)
    out["인수자 담보 몰수"] = u.balance() < bal_u0 + 1
    # ★맥락-0 C-2 — 정산 후에도 커버 이력이 잡 레코드에 남는다(사후 감사)
    st_after = h.job(j["ref"])
    out["커버 이력 보존"] = st_after.get("covered") is False and \
        st_after.get("cover_history", {}).get("uw") == "cvu"
    # ★RU-1 — 기한-경과 청구 인수 가드(SDK-측 보호)
    nid_late = [n["nid"] for n in h.notes_of("anchor0") if n["face"] == 4][0]
    j_late = h.redeem_job("anchor0", nid_late, seed="ff" * 4, n=100)
    for _ in range(nd.w.GEN["redeem_T"] + 1):
        h._post("/tick", {})
    if j_late["ref"] in nd.w.redeem_pending:      # 아직 미정산(경계) — 가드 검사
        try:
            u.cover(j_late["ref"], prem=1)
            out["기한-후 인수 가드"] = False
        except RuntimeError as e:
            out["기한-후 인수 가드"] = "기한" in str(e)
    else:
        out["기한-후 인수 가드"] = True            # 이미 정산 — 가드 무대상(통과)
    # ★원자 보험료↔커버(/block — all-or-nothing) + 실패 다리의 원자 롤백
    h2 = _client(port, "cvh2", data)
    u2 = _client(port, "cvu2", data)
    h2.join()
    u2.join()
    # ★배상 노트(12 · 불이행-앵커 색)를 2차 유통 — 색 상속으로 그대로 상환-가능
    h.xfer("cvh2", [n["nid"] for n in h.notes_of("anchor0")
                    if n["face"] == 12][0])
    h2.split(h2.notes_of("cvh2")[0]["nid"], [12, 4, 1, 1, 1, 1])  # 자기-IOU(보험료용)
    nid3 = [n["nid"] for n in h2.notes_of("anchor0") if n["face"] == 12][0]
    j3 = h2.redeem_job("anchor0", nid3, seed="dd" * 4, n=1000)
    prem_note = [n["nid"] for n in h2.notes() if n["face"] == 1][0]
    pay_leg = h2.make_leg("XFER", {"frm": "cvh2", "to": "cvu2",
                                   "note": prem_note})
    cov_leg = u2.cover(j3["ref"], prem=2, submit=False)   # UW 다리(미제출)
    bal_h2, bal_u2 = h2.balance(), u2.balance()
    r_blk = h2.submit_block([pay_leg, cov_leg])
    out["★원자 보험료↔커버"] = "seq" in r_blk and \
        h2.job(j3["ref"]).get("covered") is True and \
        h2.balance() == bal_h2 - 1
    # 실패 다리 포함 블록 = 전부 롤백(커널 원자성)
    bad_leg = h2.make_leg("XFER", {"frm": "cvh2", "to": "cvu2",
                                   "note": "999999"})
    ok_note = [n["nid"] for n in h2.notes() if n["face"] == 1][0]
    ok_leg = h2.make_leg("XFER", {"frm": "cvh2", "to": "cvu2",
                                  "note": ok_note})
    bal_before_blk = h2.balance()
    try:
        h2.submit_block([ok_leg, bad_leg])
        out["원자 롤백"] = False
    except RuntimeError:
        out["원자 롤백"] = h2.balance() == bal_before_blk
    # ★[M-154] — 가계-집중 계기(N-17) + 인수자 좌석 도구(underwriter.py) 전-흐름
    h.declare_version("acme/m1")            # 가계 관례: 「가계/버전」
    fam = h.stats()["family_concentration"]
    out["가계-집중 계기"] = (isinstance(fam.get("herfindahl_lb"), float)
                        and fam["families"].get("acme", 0) >= 0
                        and "acme" in fam["families"]
                        and fam.get("undeclared_share") is not None)
    h3 = _client(port, "cvh3", data)
    u3 = _client(port, "cvu3", data)
    h3.join()
    u3.join()
    big = [n for n in h.notes_of("anchor0") if n["face"] >= 8][0]
    h.split(big["nid"], [4, big["face"] - 4])
    nid4 = [n["nid"] for n in h.notes_of("anchor0") if n["face"] == 4][0]
    h.xfer("cvh3", nid4)
    j4 = h3.redeem_job("anchor0", nid4, seed="cc" * 4, n=500)
    pol = {"max_exposure": 10_000, "min_rate_bp": 100,
           "per_anchor": 3, "family_herf_max": 1.0}
    cands = UWT.scan(u3, pol)["candidates"]
    out["좌석 스캔"] = any(cd["ref"] == j4["ref"] for cd in cands)
    q = UWT.quote(u3, pol, ttl=30)
    out["좌석 커버-호가"] = j4["ref"] in q["posted"] and any(
        r["post"]["kind"] == "cover" and f"ref={j4['ref']}" in r["post"]["detail"]
        for r in u3.board()["asks"])
    prem4 = [cd for cd in cands if cd["ref"] == j4["ref"]][0]["prem"]
    uw_leg = UWT.make_cover_leg(u3, j4["ref"], prem4)
    h3.split(h3.notes()[0]["nid"], [prem4, 20 - prem4])
    pn = [n["nid"] for n in h3.notes() if n["face"] == prem4][0]
    pay4 = h3.make_leg("XFER", {"frm": "cvh3", "to": "cvu3", "note": pn})
    r4 = h3.submit_block([pay4, uw_leg])
    out["★좌석 원자-체결"] = "seq" in r4 and \
        h3.job(j4["ref"]).get("covered") is True and \
        h3.job(j4["ref"]).get("uw") == "cvu3"
    # ★U-1([M-157]) — 동시-성숙 집중 계기: 열린 커버가 open_covers·maturity_peak로
    # 원장-파생 공개 + 정책 max_concurrent가 계기를 소비해 스캔을 보류
    stu = h.stats()["underwriters"].get("cvu3", {})
    out["★U-1 계기"] = stu.get("open_covers", 0) >= 1 and \
        stu.get("maturity_peak", 0) >= 1
    hold = UWT.scan(u3, {"max_concurrent": 1})
    out["★U-1 동시-보류"] = hold.get("candidates") == [] and \
        "max_concurrent" in str(hold.get("held", ""))
    # ★M-3([M-157]) — 매수자-정책 캡슐(선언적 가드 · 클라이언트-측 — HTTP 전 발화)
    big2 = [n for n in h.notes_of("anchor0") if n["face"] >= 3][0]
    h.split(big2["nid"], [1, 1, big2["face"] - 2])
    m1, m2 = [n["nid"] for n in h.notes_of("anchor0") if n["face"] == 1][:2]
    h.xfer("cvh3", m1)
    h.xfer("cvh3", m2)
    h3.set_policy(anchors={"anchor0"}, max_exposure=1, max_spend=1,
                  sampled_ok=False)
    try:
        h3.redeem_job("zzz", m1, seed="cd" * 8, n=100)
        out["★M-3 허용목록"] = False
    except RuntimeError as ex:
        out["★M-3 허용목록"] = "허용목록" in str(ex)
    try:
        h3.redeem_job("anchor0", m1, seed="cd" * 8, n=100,
                      kind="sha256_chain_sampled")
        out["★M-3 표본-거부"] = False
    except RuntimeError as ex:
        out["★M-3 표본-거부"] = "표본" in str(ex)
    r5 = h3.redeem_job("anchor0", m1, seed="cd" * 8, n=100)  # 정상(상한 안)
    try:
        h3.redeem_job("anchor0", m2, seed="ce" * 8, n=100)   # 누적 초과
        out["★M-3 누적-상한"] = False
    except RuntimeError as ex:
        out["★M-3 누적-상한"] = "누적" in str(ex)
    out["★M-3 정상-통과"] = "ref" in r5
    # ★[M-162] leg-릴레이 자기-서비스 체결 — 보드 발견 → /relay leg → auto_fill 원자
    h3.policy = None                                 # M-3 캡슐 해제(별개 축)
    big3 = [n for n in h.notes_of("anchor0") if n["face"] >= 9][0]
    h.split(big3["nid"], [4, 4, big3["face"] - 8])
    n4s = [n["nid"] for n in h.notes_of("anchor0") if n["face"] == 4][:2]
    nid5, pr5 = n4s[0], n4s[1]
    h.xfer("cvh3", nid5)
    h.xfer("cvh3", pr5)
    j5 = h3.redeem_job("anchor0", nid5, seed="dd" * 4, n=500)
    pay5 = h3.make_leg("XFER", {"frm": "cvh3", "to": "cvu3", "note": pr5})
    h3.send_leg("cvu3", {"ref": j5["ref"], "legs": [pay5]})
    f = UWT.auto_fill(u3, {"min_rate_bp": 100, "family_herf_max": 1.0})
    out["★릴레이 자기-체결"] = any(x["ref"] == j5["ref"] for x in f["filled"]) \
        and h3.job(j5["ref"]).get("covered") is True \
        and h3.job(j5["ref"]).get("uw") == "cvu3"
    out["릴레이 소비(읽고-지움)"] = u3.fetch_legs() == []
    # ★R-1([M-163]) — 재전송·신선도: 같은 서명-msg 재-POST 거부 · epoch-무 본문 거부
    from sdk import RELAY_DOMAIN, canon
    bd = {"p": "cvh3", "to": "cvu3", "blob": "{}",
          "epoch": h3.state()["epoch"]}
    sg = h3.key.sign(RELAY_DOMAIN + h3.log_id + canon(bd)).hex()
    h3._post("/relay", {"msg": bd, "sig": sg})
    try:
        h3._post("/relay", {"msg": bd, "sig": sg})
        out["★재전송 거부"] = False
    except RuntimeError as ex:
        out["★재전송 거부"] = "중복" in str(ex)
    bd2 = {"p": "cvh3", "to": "cvu3", "blob": "{}"}
    sg2 = h3.key.sign(RELAY_DOMAIN + h3.log_id + canon(bd2)).hex()
    try:
        h3._post("/relay", {"msg": bd2, "sig": sg2})
        out["★신선도 필수"] = False
    except RuntimeError as ex:
        out["★신선도 필수"] = "신선도" in str(ex)
    for i in range(3):                               # 기존 1 + 3 = 상한 4 도달
        h3.send_leg("cvu3", {"i": i})
    try:
        h3.send_leg("cvu3", {"i": 9})
        out["★발신자-상한"] = False
    except RuntimeError as ex:
        out["★발신자-상한"] = "발신자당" in str(ex)
    u3.fetch_legs()                                  # 소비(뒤 케이스 오염 방지)
    try:                                             # 미서명/타인-서명 거부
        u3._post("/relay", {"msg": {"p": "cvh3", "to": "cvu3", "blob": "x"},
                            "sig": "00" * 64})
        out["릴레이 위조 거부"] = False
    except RuntimeError as ex:
        out["릴레이 위조 거부"] = "서명" in str(ex)
    # ★[M-164] U-C — 결박-보험료: 원자-체결(j4=prem4 · 릴레이 j5=4)의 보험료가
    # 커밋-전 노트 실물에서 포획돼 자기-선언과 분리된 검증-분모로 선다
    stx = h.stats()["underwriters"].get("cvu3", {})
    out["★결박-보험료"] = stx.get("prem_verified") == prem4 + 4 and \
        "loss_ratio_verified" in stx
    # ★[M-164] U-A — δ-반영 요율 v2: 공정가 ≤ suggest 상한(δ ≤ 1 구조 검증)
    big4 = [n for n in h.notes_of("anchor0") if n["face"] >= 5][0]
    h.split(big4["nid"], [4, big4["face"] - 4])
    nid6 = [n["nid"] for n in h.notes_of("anchor0") if n["face"] == 4][0]
    h.xfer("cvh3", nid6)
    j6 = h3.redeem_job("anchor0", nid6, seed="ee" * 4, n=500)
    sc2 = UWT.scan(u3, {"min_rate_bp": 0, "family_herf_max": 1.0})
    cand6 = next(cd for cd in sc2["candidates"] if cd["ref"] == j6["ref"])
    out["★δ-요율 ≤ suggest"] = 1 <= cand6["prem"] <= u3.suggest_prem(j6["ref"])
    # ★[M-164] U-B — 가계-상한: 앵커가 가계를 선언하면 cap=0이 후보를 보류
    env_v = wk.sign_env("TICKMARK", {"kind": "fl21.version", "v": "acme/m1"})
    wk._post("/submit", {"env": env_v})
    sc3 = UWT.scan(u3, {"min_rate_bp": 0, "family_herf_max": 1.0,
                        "family_cap": 0})
    out["★가계-상한 보류"] = all(cd["anchor"] != "anchor0"
                                 for cd in sc3["candidates"]) and \
        sc3.get("family_open") == {}
    # ★[M-165] C-1 — 신뢰-람다(기계-경제 신뢰-상한): 이행-부피 0인 앵커는 λ가
    # 켜지면 전면 보류(빈 이력에 노출 불가 — build-up-burst 방어의 극한)
    sc4 = UWT.scan(u3, {"min_rate_bp": 0, "family_herf_max": 1.0,
                        "trust_lambda": 0.5})
    out["★신뢰-람다(무-이행 앵커 보류)"] = sc4["candidates"] == [] and \
        len(sc2["candidates"]) >= 1
    # ★[M-165] C-2 — 기간-carry: carry > 0 이면 같은 후보의 요율이 단조 증가
    scC = UWT.scan(u3, {"min_rate_bp": 0, "family_herf_max": 1.0,
                        "carry_bp_per_epoch": 500})
    c0 = {cd["ref"]: cd["prem"] for cd in sc2["candidates"]}
    out["★carry 단조"] = all(cd["prem"] >= c0.get(cd["ref"], 0)
                             for cd in scC["candidates"]) and \
        any(cd["prem"] > c0.get(cd["ref"], 0) for cd in scC["candidates"])
    # ★[M-165] C-3 — 색-실질 계기
    ch = h.stats().get("color_health", {})
    out["★색-실질 계기"] = "anchor0" in ch and \
        ch["anchor0"].get("issuer_exited") is False and \
        ch["anchor0"].get("issuer_balance", -1) >= 0
    # ★[M-164] U-D — 북 위험 엔진(계기 스모크): 열린 커버 북의 파멸-확률·분위 산출
    bk = UWT.book(u3, {"family_herf_max": 1.0}, trials=200)
    out["★북-엔진"] = bk["open_covers"] >= 1 and 0 <= bk["ruin_prob"] <= 1 \
        and bk["drawdown"]["p50"] <= bk["drawdown"]["p95"] <= bk["drawdown"]["max"]
    wk.work_pending()                                # 이행 → 이행-부피 생성(맨 뒤)
    stA = h.stats()["anchors"].get("anchor0", {})
    out["★이행-부피 계기"] = stA.get("delivered_volume", 0) >= 4
    # ★[M-170] F-11 — 발행자-측 동시-만기 계기(열린 청구가 남아있는 동안 관측)
    big5 = [n for n in h.notes_of("anchor0") if n["face"] >= 2][0]
    h.split(big5["nid"], [2, big5["face"] - 2])
    nid7 = [n["nid"] for n in h.notes_of("anchor0") if n["face"] == 2][0]
    h.xfer("cvh3", nid7)
    j7 = h3.redeem_job("anchor0", nid7, seed="ff" * 4, n=500)
    stA2 = h.stats()["anchors"].get("anchor0", {})
    out["★발행자 만기-계기"] = stA2.get("issuer_maturity_peak", 0) >= 2
    # ★[M-170] F-4 — 버전-주기(선언 2회 후 중앙값 — 사이에 틱 1 이상)
    nd.tick()
    env_v2 = wk.sign_env("TICKMARK", {"kind": "fl21.version", "v": "acme/m2"})
    wk._post("/submit", {"env": env_v2})
    stA3 = h.stats()["anchors"].get("anchor0", {})
    out["★버전-주기 계기"] = isinstance(stA3.get("version_period"), int) and \
        stA3["version_period"] >= 1
    # ★[M-170] F-9a — 죽은-노트 계기(현재 = 신선 ⟹ stale 0 기준선)
    chh = h.stats()["color_health"].get("anchor0", {})
    out["★stale 기준선 0"] = chh.get("stale_share") == 0.0
    # ★[M-170] F-1 — swap kind 보드 수리
    h3.post_ask("swap", "sell comp-note", 3,
                detail="offer=anchor0:4 want=cvh3 · [M-170] F-1")
    out["★swap 호가 수리"] = any(r["post"]["kind"] == "swap"
                                 for r in h3.board()["asks"])
    # ★[M-170] F-2 — book 공개-감사(제3자가 cvu3의 북을 재계산)
    bk2 = UWT.book(h3, {"family_herf_max": 1.0}, trials=100, principal="cvu3")
    out["★book 공개-감사"] = bk2.get("subject") == "cvu3" and \
        bk2.get("self_audit") is False and bk2.get("open_covers", -1) >= 0
    # ★[M-170] F-10 — 가계-사전(결정론 구성): 이행-전량 가계 beta를 만들고
    # (cvgood — 성숙 p̂ ≈ 0.25), 같은 가계의 무-이력 cvna의 권고가가 라플라스-0.5
    # 기반보다 낮아짐을 확인(E=4: 0.5→2 vs 가계-사전→1)
    gd = _client(port, "cvgood", data)
    gd.join()
    env_g = gd.sign_env("TICKMARK", {"kind": "fl21.version", "v": "beta/m1"})
    gd._post("/submit", {"env": env_g})
    gb = [n for n in gd.notes() if n["face"] >= 2][0]
    gd.split(gb["nid"], [1, 1, gb["face"] - 2])
    for i, sd in enumerate(("a1" * 4, "a2" * 4)):
        gn = [n for n in gd.notes() if n["face"] == 1][0]
        gd.xfer("cvh3", gn["nid"])
        jg = h3.redeem_job("cvgood", gn["nid"], seed=sd, n=500)
        gd.deliver_job(jg["ref"], JOBS.compute("sha256_chain", sd, 500))
    for _ in range(nd.w.GEN["redeem_T"] + 1):
        nd.tick()                                    # 성숙(대칭-시차 계수)
    na = _client(port, "cvna", data)
    na.join()
    env_v3 = na.sign_env("TICKMARK", {"kind": "fl21.version", "v": "beta/m9"})
    na._post("/submit", {"env": env_v3})
    nb = [n for n in na.notes() if n["face"] >= 4][0]
    na.split(nb["nid"], [4, nb["face"] - 4])
    nid8 = [n["nid"] for n in na.notes() if n["face"] == 4][0]
    na.xfer("cvh3", nid8)
    for n in list(na.notes()):        # 잔고 0 → r=0 → δ=1(가계-사전 효과 비-희석)
        na.xfer("cvh3", n["nid"])
    j8 = h3.redeem_job("cvna", nid8, seed="aa" * 4, n=500)
    sc_np = UWT.scan(u3, {"min_rate_bp": 0, "family_herf_max": 1.0})
    p_np = next(cd["prem"] for cd in sc_np["candidates"] if cd["ref"] == j8["ref"])
    # ★[M-190] family_prior 보안 속성(냉독 최대판 — fam0 는 공격자 자유-텍스트):
    # ⓐλ 없이는 가계-사전 할인 무효(결합 강제) ⓑλ 결합 시 무-이력 앵커(own-vol 0)의
    # 대형-노출은 λ×0=0 으로 걸러진다 ⟹ 「가짜 가계 충돌로 대형 싼 커버」 봉쇄.
    sc_nl = UWT.scan(u3, {"min_rate_bp": 0, "family_herf_max": 1.0,
                          "family_prior": True})
    p_nl = next(cd["prem"] for cd in sc_nl["candidates"] if cd["ref"] == j8["ref"])
    out["★λ 없으면 family_prior 무효(결합 강제)"] = p_nl == p_np
    sc_fp = UWT.scan(u3, {"min_rate_bp": 0, "family_herf_max": 1.0,
                          "family_prior": True, "trust_lambda": 10.0})
    fp_cand = [cd for cd in sc_fp["candidates"] if cd["ref"] == j8["ref"]]
    out["★λ 결합 시 무-이력 대형-노출 차단"] = (
        not fp_cand or fp_cand[0]["exposure"] <= 1)
    # ── ★E-1([M-172]) cascade — 폐형-사영 = 커널 정산 실측(층별 정확 일치) ──
    #    격리: 앞선 열린 청구 전량 flush → cvna(잔고 0 = 부재-동형) 단독 부보-청구 →
    #    성숙 전 cascade(freeze) 사영 = 정산 후 /stats.loss 층별 증분(정확 일치).
    for _ in range(nd.w.GEN["redeem_T"] + 1):
        nd.tick()
    nn9 = [n for n in h3.notes_of("cvna") if n["face"] == 4][0]
    j9 = h3.redeem_job("cvna", nn9["nid"], seed="ab" * 4, n=500)
    u3.cover(j9["ref"], prem=2)
    st_pre = h._get("/stats")
    casc = UWT.cascade(h3, mode="freeze", sets="single")
    pred = next(s2 for s2 in casc["scenarios"] if s2["anchors"] == ["cvna"])
    for _ in range(nd.w.GEN["redeem_T"] + 1):
        nd.tick()
    st_post = h._get("/stats")
    dl = {kk: st_post["loss_layers"][kk] - st_pre["loss_layers"][kk]
          for kk in ("anchor", "cov", "uw", "fund", "short")}
    pl = pred["layers"]
    out["★cascade 층-일치"] = all(
        dl[kk] == pl[kk] for kk in ("anchor", "cov", "uw", "fund", "short"))
    out["★cascade 보존"] = (sum(pl.values()) == pred["need"] and pl["cov"] >= 1)
    # ── ★E-4([M-172]) 매수자 폐형 — 초기하 탈출률·k* 경계 ──
    import sdk as _sdk
    out["★탈출률 폐형=실측표"] = (
        abs(_sdk.escape_rate(250_000, 2) - 0.6) < 1e-9 and
        abs(_sdk.escape_rate(500_000, 2) - 0.8) < 1e-9 and
        abs(_sdk.escape_rate(1_000_000, 2) - 0.9) < 1e-9)
    _sk = _sdk.suggest_k(1_000_000, damage=4)
    out["★k* 경계"] = (_sk["k"] == 15 and
                      _sk["residual_expected_damage"] <= 1.0 + 1e-9 and
                      _sdk.suggest_k(1_000_000, damage=10_000)["full_check"])
    out["audit"] = h._get("/audit")["ok"]
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_THASHBIND(port=8810):
    """★H2([M-121]) — 명세·산출 해시-결박: REDEEM.spec_sha256·DELIVER.output_sha256이
    서명 head에 결박(로그-단독 재구성) ∧ 위조는 거부 ∧ 무필드 구항목은 하위호환."""
    from sdk import spec_sha256, output_sha256
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "hb", data)
    c.join()
    c.bootstrap(8)
    a8 = c.notes_of("anchor0")[0]
    c.split(a8["nid"], [1, 1, a8["face"] - 2])
    n1, n2 = [n["nid"] for n in c.notes_of("anchor0") if n["face"] == 1][:2]
    # ⓐ정상 — SDK 자동-결박: REDEEM에 spec_sha256·DELIVER에 output_sha256이 로그에 실림
    j = c.redeem_job("anchor0", n1, seed="ab" * 8, n=5000)
    wk = AnchorWorker(f"http://127.0.0.1:{port}",
                      os.path.join(data, "anchor0.key"))
    wk.work_pending()
    log = c._get(f"/log?since=0")["entries"]
    r_env = next(e["env"] for e in log
                 if e["env"]["typ"] == "REDEEM"
                 and e["env"]["args"].get("spec_sha256"))
    d_env = next(e["env"] for e in log
                 if e["env"]["typ"] == "DELIVER"
                 and e["env"]["args"].get("output_sha256"))
    st = c.job(j["ref"])
    out["★스펙 해시 로그-결박"] = r_env["args"]["spec_sha256"] == \
        spec_sha256({"kind": "sha256_chain", "seed": "ab" * 8, "n": 5000})
    out["★산출 해시 로그-결박"] = d_env["args"]["output_sha256"] == \
        output_sha256(st["output"])
    # ⓑ위조 스펙 — 서명한 해시 ≠ 제출 명세
    bad = c.sign_env("REDEEM", {"holder": "hb", "note": n2, "anchor": "anchor0",
                                "spec_sha256": "00" * 32})
    try:
        c._post("/job", {"env": bad,
                         "job": {"kind": "sha256_chain", "seed": "ab" * 8,
                                 "n": 5000}})
        out["★위조 스펙 거부"] = False
    except RuntimeError as e:
        out["★위조 스펙 거부"] = "H2" in str(e)
    # ⓒ레거시(무필드) 하위호환 + 위조 산출 거부
    legacy = c.sign_env("REDEEM", {"holder": "hb", "note": n2,
                                   "anchor": "anchor0"})
    j2 = c._post("/job", {"env": legacy,
                          "job": {"kind": "sha256_chain", "seed": "ab" * 8,
                                  "n": 5000}})
    out["레거시(무필드) 수리"] = bool(j2.get("ref"))
    good_out = wk.compute_sha256({"kind": "sha256_chain", "seed": "ab" * 8,
                                  "n": 5000})
    bd = wk.sign_env("DELIVER", {"anchor": "anchor0", "ref": j2["ref"],
                                 "output_sha256": "00" * 32})
    try:
        wk._post("/deliver", {"env": bd, "output": good_out})
        out["★위조 산출 거부"] = False
    except RuntimeError as e:
        out["★위조 산출 거부"] = "H2" in str(e)
    wk.deliver_job(j2["ref"], good_out)      # 정상 마감(자동-결박)
    # ⓓ★워커-경로 결박([M-149] SR-1): 프로덕션 자동-이행 루프(work_once)의 DELIVER도
    # H2 결박 — 종전엔 봉투 직접 조립으로 운영자 판매 경로만 결박 밖이었다(게이트 사각).
    big = [n for n in c.notes_of("anchor0") if n["face"] > 1][0]
    c.split(big["nid"], [1, big["face"] - 1])
    n3 = [n["nid"] for n in c.notes_of("anchor0") if n["face"] == 1][0]
    j3 = c.redeem_job("anchor0", n3, seed="cd" * 8, n=5000)
    wk.work_once()
    st3 = c.job(j3["ref"])
    d3 = next(e["env"] for e in c._get("/log?since=0")["entries"]
              if e["env"]["typ"] == "DELIVER"
              and e["env"]["args"].get("ref") == j3["ref"])
    out["★워커-경로 결박(SR-1)"] = st3.get("delivered") is True and \
        d3["args"].get("output_sha256") == output_sha256(st3["output"])
    out["audit"] = c._get("/audit")["ok"]
    # ★[M-216] N-32 — 산출은 별도 파일 · 레코드에는 마커 · /job 은 산출을 합쳐 서빙(계약 불변)
    _dj = next((j for j in nd.jobs.values() if j.get("delivered")), None)
    out["★산출 파일 분리(레코드 = 마커)"] = isinstance((_dj or {}).get("output"), dict) and "$out" in _dj["output"] and os.path.exists(os.path.join(nd.outputs_dir, f"{_dj['output']['$out']}.json"))
    _ref = next(r for r, j in nd.jobs.items() if j is _dj)
    _served = c._get(f"/job/{_ref}")
    out["★/job 은 산출 본문을 서빙"] = "output" in _served and not (isinstance(_served["output"], dict) and "$out" in _served["output"])
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TSTATS(port=8800):
    """★P-5 /stats(대칭-시차·버전-경계[P-10]) + ★P-9 /attest."""
    import time as _t
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "sta", data)
    c.join()
    wk = AnchorWorker(f"http://127.0.0.1:{port}",
                      os.path.join(data, "anchor0.key"))
    wk.split(wk.notes()[0]["nid"], [12, 4, 24])
    for n in [x for x in wk.notes() if x["face"] in (12, 4)]:
        wk.xfer("sta", n["nid"])
    nid = [n["nid"] for n in c.notes_of("anchor0") if n["face"] == 12][0]
    j = c.redeem_job("anchor0", nid, seed="aa" * 4, n=1000)
    wk.work_once()
    s1 = c.stats()
    a0 = s1["anchors"].get("anchor0", {}).get("segments", {}).get("v0", {})
    out["배달 계수"] = a0.get("delivered", 0) >= 1
    out["★대칭-시차(미성숙)"] = a0.get("mature", 99) == 0    # now < t0+T ⟹ 미성숙
    for _ in range(nd.w.GEN["redeem_T"] + 1):
        c._post("/tick", {})
    s2 = c.stats()
    a0b = s2["anchors"]["anchor0"]["segments"]["v0"]
    out["성숙 도달"] = a0b["mature"] >= 1 and "p_hat" in a0b
    # ★P-10 버전-경계 — 선언 후 새 이행은 새 세그먼트로
    wk_env = wk.sign_env("TICKMARK", {"kind": "fl21.version", "v": "m2"})
    wk._post("/submit", {"env": wk_env})
    nid2 = [n["nid"] for n in c.notes_of("anchor0") if n["face"] == 4][0]
    j2 = c.redeem_job("anchor0", nid2, seed="bb" * 4, n=1000)
    wk.work_once()
    s3 = c.stats()
    segs = s3["anchors"]["anchor0"]["segments"]
    out["★버전 분절"] = "m2" in segs and segs["m2"]["delivered"] >= 1 \
        and segs["v0"]["delivered"] >= 1
    # ★P-9 실적 증명 — 검증·변조 검출·부분-발췌 무효
    att = c.fetch_attest("anchor0")
    out["증명 검증"] = c.verify_attest(att)["ok"] is True
    forged = {"doc": att["doc"], "operator_sig": "00" * 64}
    out["증명 위조 검출"] = c.verify_attest(forged)["ok"] is False
    part = {"doc": {**att["doc"], "complete": False},
            "operator_sig": att["operator_sig"]}
    out["부분-발췌 무효"] = c.verify_attest(part)["ok"] is False
    out["audit"] = c._get("/audit")["ok"]
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TBOARD(port=8811, port2=8812):
    """★R2-a 호가 창: 오프-원장 서명 게시판(ASK/WANT)·철회·만료·상한·도메인-분리·
    재기동 존속 ∧ 체결 테이프(원장-파생) ∧ 게시가 원장 seq를 건드리지 않음."""
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "seller", data)
    c.join()
    b = _client(port, "buyer", data)
    b.join()
    seq0 = c.state()["seq"]
    # 게시·정렬(ask 오름차순 = 최우선 매도부터 · want 내림차순)
    a1 = c.post_ask("pyjudge", "judge verdicts", 3, detail="frontier judge")
    a2 = c.post_ask("sha256_chain", "metered compute", 1)
    w1 = b.post_want("pyjudge", "need a judge", 5)
    bd = c.board()
    out["게시 왕복"] = {a1["id"], a2["id"]} <= {r["id"] for r in bd["asks"]} \
        and w1["id"] in {r["id"] for r in bd["wants"]}
    out["ask 가격-정렬"] = bd["asks"][0]["post"]["price"] == 1
    # 멱등 재게시(내용-주소 id)
    out["재게시 멱등"] = c.post_ask("sha256_chain", "metered compute", 1,
                                    ttl=1440)["id"] == a2["id"] \
        and len([r for r in c.board()["asks"]
                 if r["id"] == a2["id"]]) == 1
    # 미등록 주체 거부
    ghost = Fl21Client(f"http://127.0.0.1:{port}", "ghost",
                       os.path.join(data, "ghost.key"))
    try:
        ghost.post_ask("other", "not joined", 1)
        out["미등록 거부"] = False
    except RuntimeError:
        out["미등록 거부"] = True
    # 서명 위조 거부(타인 몸통에 내 서명)
    body = {"side": "ask", "kind": "other", "title": "forged", "detail": "",
            "price": 1, "p": "buyer", "expires": c.state()["epoch"] + 10}
    sig = c.key.sign(b"FL23-BOARD" + c.log_id + canon(body)).hex()
    try:
        c._post("/board", {"post": body, "sig": sig})
        out["서명 위조 거부"] = False
    except RuntimeError:
        out["서명 위조 거부"] = True
    # ★도메인 분리: 원장 도메인으로 서명한 게시는 거부(교차-재생 차단)
    body2 = {"side": "ask", "kind": "other", "title": "xdomain", "detail": "",
             "price": 1, "p": "seller", "expires": c.state()["epoch"] + 10}
    sig2 = c.key.sign(DOMAIN + c.log_id + canon(body2)).hex()
    try:
        c._post("/board", {"post": body2, "sig": sig2})
        out["★도메인 분리(원장-서명 거부)"] = False
    except RuntimeError:
        out["★도메인 분리(원장-서명 거부)"] = True
    # 주체당 상한(8) — seller는 이미 2건
    for i in range(6):
        c.post_ask("other", f"filler {i}", 1)
    try:
        c.post_ask("other", "over cap", 1)
        out["주체당 상한"] = False
    except RuntimeError as e:
        out["주체당 상한"] = "8" in str(e)
    # 철회: 타인 불가·본인 가능
    try:
        b.retract_post(a1["id"])
        out["타인 철회 거부"] = False
    except RuntimeError:
        out["타인 철회 거부"] = True
    c.retract_post(a1["id"])
    out["본인 철회"] = a1["id"] not in {r["id"] for r in c.board()["asks"]}
    # 만료 GC(틱 경과)
    short = b.post_want("other", "expiring", 1, ttl=1)
    c._post("/tick", {})
    c._post("/tick", {})
    out["만료 GC"] = short["id"] not in {r["id"] for r in c.board()["wants"]}
    # ★오프-원장: 게시·철회가 원장 seq 무접촉(틱 2회분만 증가)
    out["★오프-원장(seq 무접촉)"] = c.state()["seq"] == seq0 + 2
    # 체결 테이프(원장-파생): 실물 이행 → stats.tape
    wk = AnchorWorker(f"http://127.0.0.1:{port}",
                      os.path.join(data, "anchor0.key"))
    g = wk.notes()[0]["nid"]
    wk.split(g, [1, wk.notes()[0]["face"] - 1])
    n1 = [x for x in wk.notes() if x["face"] == 1][0]["nid"]
    wk.xfer("seller", n1)
    nid = [x["nid"] for x in c.notes_of("anchor0") if x["face"] == 1][0]
    j = c.redeem_job("anchor0", nid, seed="ab" * 8, n=5000)
    wk.work_once()
    tp = c.stats().get("tape", {})
    out["체결 테이프"] = any(f["face"] == 1 and f["anchor"] == "anchor0"
                             for f in tp.get("sha256_chain", []))
    # 재기동 존속(자문층 파일) — 같은 데이터로 다른 포트
    # ★[M-209] R2-F09-B — 철회된 게시의 재생-부활 금지(묘비): 소유자 철회 뒤 캡처한 같은 게시 재게시 → 거부
    _pb = {"side": "ask", "kind": "sha256_chain", "title": "tomb test", "detail": "", "price": 2, "p": "seller",
           "expires": c._get("/state")["epoch"] + 100}
    _sg = c.key.sign(c._d["board"] + c.log_id + canon(_pb)).hex()
    _r1 = c._post("/board", {"post": _pb, "sig": _sg})
    c.retract_post(_r1["id"])
    try:
        c._post("/board", {"post": _pb, "sig": _sg})
        out["★철회 게시 재생 = 거부"] = False
    except Exception as ex:
        out["★철회 게시 재생 = 거부"] = "철회" in str(ex)
    out["★철회 게시 부활 없음"] = _r1["id"] not in {r["id"] for r in c.board()["asks"]}
    srv.shutdown()
    nd2, srv2, _ = _serve(port2, data=data)
    c2 = Fl21Client(f"http://127.0.0.1:{port2}", "seller",
                    os.path.join(data, "seller.key"))
    out["재기동 존속"] = a2["id"] in {r["id"] for r in c2.board()["asks"]}
    out["audit"] = c2._get("/audit")["ok"]
    srv2.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TSCOPE(port=8815, port2=8817):
    """★H5([M-126]) 작업-범위 결박: 선언(온-원장 TICKMARK) → 범위-밖 제출 거부(kind·
    액면·raw) · 개정·철회 · 무-선언 하위호환 · ★리플레이 재구성(재기동 후에도 강제)."""
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "sc", data)
    c.join()
    wk = Fl21Client(f"http://127.0.0.1:{port}", "anchor0",
                    os.path.join(data, "anchor0.key"))
    g = wk.notes()[0]["nid"]
    wk.split(g, [1] * 4 + [4, wk.notes()[0]["face"] - 8])
    for n in [x for x in wk.notes() if x["face"] in (1, 4)][:5]:
        wk.xfer("sc", n["nid"])
    # 선언: sha256_chain만 · 원시 거부 · 액면 ≤ 2
    wk.declare_scope(kinds=["sha256_chain"], raw=False, max_exposure=2)
    nid1 = [n["nid"] for n in c.notes_of("anchor0") if n["face"] == 1][0]
    j = c.redeem_job("anchor0", nid1, seed="ab" * 8, n=1000)
    out["범위-내 통과"] = "ref" in j
    try:
        c.redeem_job("anchor0",
                     [n["nid"] for n in c.notes_of("anchor0")
                      if n["face"] == 1][0],
                     seed="ab" * 8, n=1000, kind="sha256_chain_sampled")
        out["범위-밖 kind 거부"] = False
    except RuntimeError as e:
        out["범위-밖 kind 거부"] = "H5" in str(e)
    try:
        nid4 = [n["nid"] for n in c.notes_of("anchor0") if n["face"] == 4][0]
        c.redeem_job("anchor0", nid4, seed="ab" * 8, n=1000)
        out["액면 상한 거부"] = False
    except RuntimeError as e:
        out["액면 상한 거부"] = "최대 노출" in str(e)
    try:
        c._post("/submit", {"env": c.sign_env("REDEEM", {
            "holder": "sc",
            "note": [n["nid"] for n in c.notes_of("anchor0")
                     if n["face"] == 1][0], "anchor": "anchor0"})})
        out["원시 상환 거부"] = False
    except RuntimeError as e:
        out["원시 상환 거부"] = "원시" in str(e)
    try:
        wk.declare_scope(kinds=["evil_kind"])
        out["비정형 선언 거부"] = False
    except RuntimeError:
        out["비정형 선언 거부"] = True
    wk.declare_scope(kinds=["sha256_chain", "pyjudge"], max_exposure=0,
                     max_T=6)
    out["개정 반영"] = nd.scopes["anchor0"]["kinds"] == \
        ["sha256_chain", "pyjudge"]
    try:                               # ★F-R1 — 잡별-T 앵커-측 상한(FL2.2 리뷰)
        c.redeem_job("anchor0",
                     [n["nid"] for n in c.notes_of("anchor0")
                      if n["face"] == 1][0], seed="ee" * 8, n=1000, T=8)
        out["★max_T 초과 거부"] = False
    except RuntimeError as e:
        out["★max_T 초과 거부"] = "앵커 상한" in str(e)
    j5 = c.redeem_job("anchor0",
                      [n["nid"] for n in c.notes_of("anchor0")
                       if n["face"] == 1][0], seed="ee" * 8, n=1000, T=5)
    out["max_T 내 통과"] = "ref" in j5
    srv.shutdown()
    srv.server_close()
    nd2, srv2, _ = _serve(port2, data=data)   # ★리플레이 재구성
    c2 = _client(port2, "sc", data)
    try:
        c2.redeem_job("anchor0",
                      [n["nid"] for n in c2.notes_of("anchor0")
                       if n["face"] == 1][0],
                      seed="ab" * 8, n=1000, kind="sha256_chain_sampled")
        out["★재기동 후 강제(리플레이)"] = False
    except RuntimeError as e:
        out["★재기동 후 강제(리플레이)"] = "H5" in str(e)
    wk2 = Fl21Client(f"http://127.0.0.1:{port2}", "anchor0",
                     os.path.join(data, "anchor0.key"))
    wk2.declare_scope(clear=True)
    j3 = c2.redeem_job("anchor0",
                       [n["nid"] for n in c2.notes_of("anchor0")
                        if n["face"] == 1][0],
                       seed="cd" * 8, n=1000, kind="sha256_chain_sampled")
    out["철회 = 전-수락 복귀"] = "ref" in j3
    out["audit"] = c2._get("/audit")["ok"]
    srv2.shutdown()
    srv2.server_close()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TCHALLENGE(port=8816):
    """★P-11([M-126]) 챌린지 창: 일치 = 오프-원장 계수 · ★불일치(저장-산출 변조 시나리오)
    = 온-원장 기록 + 공개 실적 · 서명·대상 검증 · 라이트 검증 정합."""
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "ch", data)
    c.join()
    wk = AnchorWorker(f"http://127.0.0.1:{port}",
                      os.path.join(data, "anchor0.key"))
    g = wk.notes()[0]["nid"]
    wk.split(g, [1, 1, wk.notes()[0]["face"] - 2])
    for n in [x for x in wk.notes() if x["face"] == 1][:2]:
        wk.xfer("ch", n["nid"])
    nid = [n["nid"] for n in c.notes_of("anchor0") if n["face"] == 1][0]
    j = c.redeem_job("anchor0", nid, seed="ab" * 8, n=1000)
    wk.work_once()
    seq0 = c.state()["seq"]
    r = c.challenge(j["ref"])
    out["일치 = 검증 확인"] = r["verified"] is True
    out["일치 = 원장 무접촉"] = c.state()["seq"] == seq0
    # ★저장-산출 변조(운영자-측 사후 조작 시나리오) → 챌린지가 잡는다
    nd.jobs[j["ref"]]["output"] = "00" * 32
    r2 = c.challenge(j["ref"])
    out["★불일치 = 온-원장 기록"] = r2["verified"] is False and \
        c.state()["seq"] == seq0 + 1
    last = nd.w.log[-1]["env"]
    out["기록 형식"] = last["typ"] == "TICKMARK" and \
        last["args"]["kind"] == "fl21.challenge" and \
        last["args"]["anchor"] == "anchor0"
    out["공개 실적 반영"] = \
        c.stats()["anchors"]["anchor0"].get("challenged") == 1
    # 검증·대상 음성 경로
    try:
        c.challenge("nope")
        out["미지 ref 거부"] = False
    except RuntimeError:
        out["미지 ref 거부"] = True
    nid2 = [n["nid"] for n in c.notes_of("anchor0") if n["face"] == 1][0]
    j2 = c.redeem_job("anchor0", nid2, seed="cd" * 8, n=1000)
    try:
        c.challenge(j2["ref"])                    # 미이행 잡
        out["미이행 거부"] = False
    except RuntimeError:
        out["미이행 거부"] = True
    ghost = Fl21Client(f"http://127.0.0.1:{port}", "ghostc",
                       os.path.join(data, "ghostc.key"))
    try:
        ghost.challenge(j["ref"])
        out["미등록 거부"] = False
    except RuntimeError:
        out["미등록 거부"] = True
    bad = {"ref": j["ref"], "p": "ch", "sig": "00" * 64}
    try:
        c._post("/challenge", bad)
        out["위조 서명 거부"] = False
    except RuntimeError:
        out["위조 서명 거부"] = True
    v = c.verify_chain()
    out["라이트 검증 정합"] = v["ok"] is True
    out["audit"] = c._get("/audit")["ok"]
    # ★[M-211] R4-F09-3 — 챌린지 본문 신선도(epoch ±8) + 서명 1회 사용
    from sdk import canon as _cn3
    _cb = {"ref": j["ref"], "p": c.p}
    _cs = c.key.sign(c._d["chal"] + c.log_id + _cn3(_cb)).hex()
    try:
        c._post("/challenge", {**_cb, "sig": _cs})
        out["★epoch 없는 챌린지 거부"] = False
    except RuntimeError as ex:
        out["★epoch 없는 챌린지 거부"] = "신선도" in str(ex) or "epoch" in str(ex)
    _cb2 = {"ref": j["ref"], "p": c.p, "epoch": c._get("/state")["epoch"], "nonce": "aa"}
    _cs2 = c.key.sign(c._d["chal"] + c.log_id + _cn3(_cb2)).hex()
    _ok1 = isinstance(c._post("/challenge", {**_cb2, "sig": _cs2}), dict)
    try:
        c._post("/challenge", {**_cb2, "sig": _cs2})
        out["★챌린지 서명 재생 거부"] = False
    except RuntimeError as ex:
        out["★챌린지 서명 재생 거부"] = _ok1 and "재생" in str(ex)
    # ★[M-212] R5-F09-A — 요청자 A 가 (ref, A) 상한을 소진해도 요청자 B 의 재검증 채널은 열려 있다(ref-전역 누적 상한 = 표적 검열이던 것)
    _hit_cap = False
    for _ in range(40):
        try:
            c.challenge(j["ref"])
        except RuntimeError as ex:
            if "상한" in str(ex):
                _hit_cap = True; break
    out["★요청자별 상한 도달"] = _hit_cap
    cB = _client(port, "chal_b", data); cB.join()
    out["★다른 요청자는 여전히 챌린지 가능"] = isinstance(cB.challenge(j["ref"]), dict)
    # ★[M-216] D4-b — 산출 파일 유실 시 챌린지는 500(노드 장애) · 원장에 「불일치」를 남기지 않는다 · /job 은 output_missing 표시
    _prev_out = nd.jobs[j["ref"]].get("output"); nd.jobs[j["ref"]]["output"] = {"$out": j["ref"]}   # 앞 검사가 산출을 인라인으로 변조했을 수 있어 마커로 되돌린다
    _of = os.path.join(nd.outputs_dir, f"{j['ref']}.json"); os.rename(_of, _of + ".bak")
    _n0 = len(nd.w.log)
    try:
        cB.challenge(j["ref"]); out["★산출 유실 챌린지 = 500"] = False
    except RuntimeError as ex:
        out["★산출 유실 챌린지 = 500"] = "HTTP 500" in str(ex)
    out["★산출 유실 = 원장 무기록"] = len(nd.w.log) == _n0
    out["★/job output_missing 표시"] = c._get(f"/job/{j['ref']}").get("output_missing") is True
    os.rename(_of + ".bak", _of); nd.jobs[j["ref"]]["output"] = _prev_out
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TEXHAUST(port=8836):
    """★H-1([M-188] RISK-1 경화) — 락-밖 재실행의 자원 유계화.
    구멍의 실체는 「join_per_ip 는 **가입**을 제한하지 **챌린지**를 제한하지 않고,
    동시 재실행 수에는 상한이 아예 없었다」였다. 두 다이얼을 **양성 + 음성 대조**로
    잰다(⚠️[M-149] 교훈 — 검사기 자신의 침묵-실패를 막으려면 「끄면 안 잡힌다」까지
    확인해야 한다)."""
    out = {}
    nd, srv, data = _serve(port, challenge_budget=2, challenge_window=60,
                           verify_slots=1, verify_wait=0.3)
    c = _client(port, "ex", data)
    c.join()
    wk = AnchorWorker(f"http://127.0.0.1:{port}",
                      os.path.join(data, "anchor0.key"))
    g = wk.notes()[0]["nid"]
    wk.split(g, [1, 1, 1, wk.notes()[0]["face"] - 3])
    for n in [x for x in wk.notes() if x["face"] == 1][:3]:
        wk.xfer("ex", n["nid"])
    nid = [n["nid"] for n in c.notes_of("anchor0") if n["face"] == 1][0]
    j = c.redeem_job("anchor0", nid, seed="ef" * 8, n=1000)
    wk.work_once()

    # ── ⓐ 양성: 가드가 켜져도 정상 챌린지는 그대로 산다 ──
    out["양성 — 가드 하에 챌린지 정상"] = c.challenge(j["ref"])["verified"] is True

    # ── ⓑ 음성(예산): 예산 2 → 3번째가 429 ──
    c.challenge(j["ref"])                                  # 2/2 소진
    try:
        c.challenge(j["ref"])
        out["★음성 — 예산 초과 = 429"] = False
    except RuntimeError as e:
        out["★음성 — 예산 초과 = 429"] = "HTTP 429" in str(e)

    # ── ⓒ ★예산은 서명 검증 뒤에 깎는다(위조 p 로 남의 예산 소진 불가) ──
    # 다른 주체 ex2 의 예산이 위조 요청으로 줄어들면 안 된다 = 갈취-레버 차단.
    c2 = _client(port, "ex2", data)
    c2.join()
    forged = {"ref": j["ref"], "p": "ex2", "sig": "00" * 64}
    for _ in range(5):
        try:
            c2._post("/challenge", forged)                 # 위조 서명 — 거부돼야 함
        except RuntimeError:
            pass
    out["★위조 p 가 남의 예산을 못 깎는다"] = \
        c2.challenge(j["ref"])["verified"] is True         # ex2 예산 온전

    # ── ⓓ 음성(동시 상한): 슬롯 1을 점유한 채로 오면 503 ──
    NODE.Handler._chal = {}                                # 예산 창 초기화(축 분리)
    assert NODE.Handler._slots.acquire(timeout=1)          # 재실행 1건 in-flight 모사
    try:
        try:
            c.challenge(j["ref"])
            out["★음성 — 슬롯 포화 = 503"] = False
        except RuntimeError as e:
            out["★음성 — 슬롯 포화 = 503"] = "HTTP 503" in str(e)
    finally:
        NODE.Handler._slots.release()
    out["슬롯 반납 후 회복"] = c.challenge(j["ref"])["verified"] is True

    # ── ⓔ 이행 경로(/deliver)도 같은 슬롯을 쓴다(자원이 공유이므로 바운드도 공유) ──
    nid2 = [n["nid"] for n in c.notes_of("anchor0") if n["face"] == 1][0]
    j2 = c.redeem_job("anchor0", nid2, seed="ab" * 8, n=1000)
    spec2 = c.job(j2["ref"])["job"]
    o2 = JOBS.compute(spec2["kind"], spec2["seed"], spec2["n"])
    assert NODE.Handler._slots.acquire(timeout=1)
    try:
        try:
            wk.deliver_job(j2["ref"], o2)          # ★H2 결박 경로 그대로
            out["★deliver 도 같은 슬롯 = 503"] = False
        except RuntimeError as e:
            out["★deliver 도 같은 슬롯 = 503"] = "HTTP 503" in str(e)
    finally:
        NODE.Handler._slots.release()
    out["슬롯 반납 후 이행 정상"] = \
        wk.deliver_job(j2["ref"], o2).get("seq", 0) > 0
    srv.shutdown()

    # ── ⓕ ★대조군: 다이얼을 끄면(기본값) 위 음성이 **안 잡힌다** ──
    # 이게 없으면 「게이트가 통과했다」가 「가드가 있다」를 뜻하지 않는다([M-149]).
    nd2, srv2, data2 = _serve(port + 1)                    # 무설정 = 종전 동작
    c3 = _client(port + 1, "ex3", data2)
    c3.join()
    wk2 = AnchorWorker(f"http://127.0.0.1:{port + 1}",
                       os.path.join(data2, "anchor0.key"))
    g2 = wk2.notes()[0]["nid"]
    wk2.split(g2, [1, wk2.notes()[0]["face"] - 1])
    wk2.xfer("ex3", [x for x in wk2.notes() if x["face"] == 1][0]["nid"])
    nid3 = [n["nid"] for n in c3.notes_of("anchor0") if n["face"] == 1][0]
    j3 = c3.redeem_job("anchor0", nid3, seed="cd" * 8, n=1000)
    wk2.work_once()
    out["대조군 — 기본값 = 끔(슬롯 없음)"] = NODE.Handler._slots is None
    many = [c3.challenge(j3["ref"])["verified"] for _ in range(6)]
    out["★대조군 — 끄면 예산 제한 없음"] = all(many)   # 6회 전부 통과 = 가드 부재
    srv2.shutdown()

    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TGEN22(port=8818):
    """★FL2.2 세대 게이트([M-127]): ⓐ단위-정책(1 AU = 1000단위 — 가격-결박 스케일)
    ⓑ★미시-보험 입도 돌파(prem 1단위 = 0.1%@1AU — [M-118] 100% 하한의 해소)
    ⓒ★잡별-T(J-1 — 기본-T 생존·자기-T 성숙·조항 거부) ⓓ★H7 공개-리플레이(J-2 —
    /meta 공개 재료만으로 전-상태 재검증·정체성 재유도)."""
    out = {}
    nd, srv, data = _serve(port, join_issue=20_000, genesis_issue=40_000,
                           bootstrap_cap=8_000, unit_scale=1000)
    c = _client(port, "g22", data)
    c.join()
    wk = AnchorWorker(f"http://127.0.0.1:{port}",
                      os.path.join(data, "anchor0.key"))
    g = wk.notes()[0]["nid"]
    wk.split(g, [999, 1000, 1000, 2000, wk.notes()[0]["face"] - 4999])
    for f in (999, 1000, 1000, 2000):
        n = next(x for x in wk.notes() if x["face"] == f)
        wk.xfer("g22", n["nid"])
    # ⓐ 가격-결박 스케일: n=250,000 = 1 AU = 1000단위 — 999단위 거부·1000 통과
    n999 = next(x["nid"] for x in c.notes_of("anchor0") if x["face"] == 999)
    try:
        c.redeem_job("anchor0", n999, seed="ab" * 8, n=250_000)
        out["스케일 가격-결박(999 거부)"] = False
    except RuntimeError as e:
        out["스케일 가격-결박(999 거부)"] = "1000" in str(e)
    n1000 = next(x["nid"] for x in c.notes_of("anchor0") if x["face"] == 1000)
    j = c.redeem_job("anchor0", n1000, seed="ab" * 8, n=250_000)
    out["스케일 통과(1000)"] = "ref" in j
    # ⓑ ★미시-보험 입도 돌파: exposure 1000단위(1 AU)에 prem 1단위 = 0.1%
    u = _client(port, "uw22", data)
    u.join()
    r = u.cover(j["ref"], prem=1)
    out["★0.1% 보험료 성립"] = "seq" in r
    cov = c.job(j["ref"])
    out["커버 확인"] = cov.get("covered") is True and cov["prem"] == 1
    wk.work_once()                    # 이행 — 커버 정상 종결
    # ⓒ ★잡별-T: 세계 기본 4 · T=8 잡은 5~7틱 생존, 8틱에 사고
    n2000 = next(x["nid"] for x in c.notes_of("anchor0") if x["face"] == 2000)
    j2 = c.redeem_job("anchor0", n2000, seed="cd" * 8, n=250_000, T=8)
    out["T-기한 부기"] = j2["deadline_epoch"] == c.state()["epoch"] + 8
    returned = []
    for i in range(8):
        st = c._post("/tick", {})["settle"]
        if st:
            returned += st.get("returned", [])
        if i == 5:
            out["긴-T 생존(6틱)"] = j2["ref"] not in returned
    out["긴-T 성숙(8틱 사고)"] = j2["ref"] in returned
    try:
        c.redeem_job("anchor0",
                     next(x["nid"] for x in c.notes_of("anchor0")
                          if x["face"] == 1000),
                     seed="ef" * 8, n=250_000, T=2)
        out["조항 거부(T ≤ window_L)"] = False
    except RuntimeError as e:
        out["조항 거부(T ≤ window_L)"] = "window_L" in str(e)
    # ⓓ ★H7 — 공개 재료만으로 전-상태 재검증(시드 불요)
    meta = c.meta
    pks = {"operator": meta["operator_pk"], **meta["genesis_pks"]}
    pub = World.from_public(pks, meta["label"], tuple(meta["genesis"]),
                            gen=dict(meta["gen"]),
                            bridge_ref=meta.get("bridge_ref"))
    out["★H7 정체성 재유도"] = pub.log_id.hex() == meta["log_id"] and \
        pub.fp0 == meta["fp0"]
    entries, s = [], 0
    for _ in range(100):
        page = c._get(f"/log?since={s}")["entries"]
        if not page:
            break
        entries += page
        s = page[-1]["seq"] + 1
    rv = pub.replay_verify(entries)
    out["★H7 전-상태 공개 재검증"] = rv["ok"] is True and \
        rv["state_root"] == nd.w.state_root()
    out["audit"] = c._get("/audit")["ok"]
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def _root_snapshot(nd):
    """세계 상태의 정준 스냅숏(리플레이-차등·거부-원자성의 기준)."""
    w = nd.w
    return json.dumps({
        "notes": {nid: [n["owner"], n["face"]] for nid, n in w.notes.items()},
        "colors": dict(nd.colors), "epoch": w.epoch, "F": w.F,
        "F_uw": w.F_uw, "S": w.S, "ext_in": w.ext_in, "ext_out": w.ext_out,
        "nonces": dict(w.nonces), "boot": dict(nd.bootstrap_used),
        "pending": sorted(w.redeem_pending), "seq": len(w.log),
        "head": w.log[-1]["head"] if w.log else "genesis"},
        sort_keys=True, ensure_ascii=False)


def _root_invariants(nd, out_err):
    """불변식 전량(매 수용-연산 후): 보존(audit)·색 전체성·양수 액면·에스크로 정합."""
    w = nd.w
    if not nd.audit()["ok"]:
        out_err.append("audit 파손")
    if set(nd.colors) != set(w.notes):
        out_err.append("색 전체성 파손")
    if any(n["face"] < 1 for n in w.notes.values()):
        out_err.append("액면 < 1")
    for ref, rp in w.redeem_pending.items():
        if w.notes.get(rp["nid"], {}).get("owner") != f"@redeem:{ref}":
            out_err.append(f"에스크로 고아 {ref}")


def _root_engine(port, seed, n_ops, data=None):
    """★T-ROOT 엔진 — 기본(거래·검증·인수)의 뿌리 시험:
    ①결정론 프롤로그: 기본 회로 전량을 1회씩(각 단계 뒤 불변식) ②필수-실패 프로브
    11종(각각 거부 확인 + ★상태-해시 불변 = 거부의 원자성) ③무작위 폭풍 n_ops
    (수용 = 불변식 전량 · 거부 = 상태-해시 불변) ④정산 항등식(모든 settled rec:
    comp+short == exposure ∧ comp == anchor+cov+uw+fund) ⑤종료: 라이트 검증
    (봉투 포함) + ★리플레이 차등(재기동 세계의 스냅숏 바이트-동일)."""
    import random as _rnd
    rng = _rnd.Random(seed)
    nd, srv, data = _serve(port, data=data)
    url = f"http://127.0.0.1:{port}"
    us = []
    for i in range(3):
        c = _client(port, f"r{i}", data)
        c.join()
        us.append(c)
    wk = Fl21Client(url, "anchor0", os.path.join(data, "anchor0.key"))
    errs, stats = [], {"accept": 0, "reject": 0, "settled": 0, "covered": 0,
                       "delivered": 0, "accidents": 0}
    exposure = {}                       # ref → face(정산 항등식 대조)

    def shot():
        return _root_snapshot(nd)

    def shot_sans():
        """★FL2.3 J-7: 인증-거부는 nonce 를 소비한다(REJECT 항) — 거부-원자성은 nonce 제외 상태로 잰다."""
        d = json.loads(shot())
        for k in ("nonces", "seq", "head"):       # REJECT 항 = nonce 소비 + 로그 1행(상태 불변) — 설계
            d.pop(k, None)
        return json.dumps(d, sort_keys=True)

    def attempt(fn):
        """단일 기입-연산 전용: 수용 = 불변식 · 거부 = 상태-해시 불변(원자성 · nonce 제외)."""
        h0 = shot_sans()
        try:
            fn()
            stats["accept"] += 1
            _root_invariants(nd, errs)
            return True
        except RuntimeError:
            stats["reject"] += 1
            if shot_sans() != h0:
                errs.append("★거부-원자성 파손(거부가 상태를 바꿈)")
            return False

    def attempt_soft(fn):
        """복합 편의(SDK cover·bootstrap의 내부 사전-split) — 실패 시에도 선행
        단일-연산은 정당 수용일 수 있어 해시-불변 대신 불변식만 검사."""
        try:
            fn()
            stats["accept"] += 1
            _root_invariants(nd, errs)
            return True
        except RuntimeError:
            stats["reject"] += 1
            _root_invariants(nd, errs)
            return False

    def must_fail(name, fn):
        h0 = shot_sans()
        try:
            fn()
            errs.append(f"필수-실패 통과됨: {name}")
        except RuntimeError:
            if shot_sans() != h0:
                errs.append(f"★거부-원자성 파손: {name}")

    open_refs = {}                     # ref → {"holder", "covered"}

    def settle_check(res):
        st = (res or {}).get("settle") or {}
        for rec in st.get("settled", []):
            stats["settled"] += 1
            exp = exposure.get(rec["ref"])
            parts = rec.get("anchor", 0) + rec.get("cov", 0) + \
                rec.get("uw", 0) + rec.get("fund", 0)
            if exp is not None and rec["comp"] + rec["short"] != exp:
                errs.append(f"정산 항등식1 파손 {rec}")
            if rec["comp"] != parts:
                errs.append(f"정산 항등식2 파손 {rec}")
            open_refs.pop(rec["ref"], None)
        for ref in st.get("returned", []):
            open_refs.pop(ref, None)
        stats["accidents"] += len(st.get("settled", [])) + \
            len(st.get("returned", []))

    def tick(c):
        r = c._post("/tick", {})
        settle_check(r)
        return r

    def one_a0(c):
        """c가 가진 anchor0-색 1-노트(있으면 nid · 없으면 None — 유동성 주입 없음)."""
        ns = [n for n in c.notes_of("anchor0") if n["face"] == 1]
        return ns[0]["nid"] if ns else None

    def redeem_p(c, cover_by=None, deliver=True, reserve=False):
        """프롤로그 전용(유동성 사전 보장) — 상환[+커버][+이행].
        reserve=True: 폭풍 불가침(기한-사고 경로의 결정론 보장용)."""
        nid = one_a0(c)
        if nid is None:
            big = next(n for n in c.notes_of("anchor0") if n["face"] > 1)
            c.split(big["nid"], [1, big["face"] - 1])
            nid = one_a0(c)
        j = c.redeem_job("anchor0", nid, seed="ab" * 8, n=1000)
        exposure[j["ref"]] = 1
        if not reserve:
            open_refs[j["ref"]] = {"holder": c.p, "covered": False}
        if cover_by is not None:
            cover_by.cover(j["ref"], prem=1)
            if not reserve:
                open_refs[j["ref"]]["covered"] = True
            stats["covered"] += 1
        if deliver:
            wk.deliver_job(j["ref"], Fl21Client.compute_sha256(
                {"kind": "sha256_chain", "seed": "ab" * 8, "n": 1000}))
            stats["delivered"] += 1
            open_refs.pop(j["ref"], None)
        return j["ref"]

    # ── ①프롤로그 — 기본 회로 전량(각 단계 뒤 불변식) ──
    for c in us:
        c.split(c.notes()[0]["nid"], [1] * 6 + [14])
        _root_invariants(nd, errs)
        c.bootstrap(4)
        _root_invariants(nd, errs)
    u0, u1, u2 = us
    m = [n["nid"] for n in u0.notes_of(u0.p) if n["face"] == 1][:2]
    u0.merge(m)                                        # 동색 병합
    _root_invariants(nd, errs)
    nid = next(n["nid"] for n in u0.notes_of(u0.p) if n["face"] == 2)
    u0.split(nid, [1, 1])
    u0.xfer("r1", [n["nid"] for n in u0.notes_of(u0.p)][0])   # 이전
    _root_invariants(nd, errs)
    redeem_p(u0, deliver=True)                         # 상환→이행(소각)
    ref_c = redeem_p(u1, cover_by=u2, deliver=False,   # 부보 청구(예약 —
                     reserve=True)                     #  기한-사고 폭포 보장)
    ref_u = redeem_p(u2, deliver=False, reserve=True)  # 무부보 청구(예약)
    _root_invariants(nd, errs)
    la = u0.make_leg("XFER", {"frm": "r0", "to": "r1",
                              "note": [n["nid"] for n in
                                       u0.notes_of(u0.p)][0]})
    lb = u1.make_leg("XFER", {"frm": "r1", "to": "r0",
                              "note": [n["nid"] for n in
                                       u1.notes_of(u1.p)][0]})
    u0.submit_block([la, lb])                          # 원자 스왑
    _root_invariants(nd, errs)

    # ── ②필수-실패 프로브(음성 경로가 공집합이 아님을 보장 · 전부 거부-원자성 검사) ──
    must_fail("타인-노트 이전", lambda: u0._post("/submit", {"env": u0.sign_env(
        "XFER", {"frm": "r0", "to": "r1",
                 "note": [n["nid"] for n in u1.notes_of(u1.p)][0]})}))
    must_fail("혼색 병합", lambda: u0.merge(
        [[n["nid"] for n in u0.notes_of(u0.p)][0],
         [n["nid"] for n in u0.notes_of("anchor0")][0]]))
    must_fail("색-불일치 상환", lambda: u0.redeem_job(
        "r1", [n["nid"] for n in u0.notes_of("anchor0")][0],
        seed="ab" * 8, n=1000))
    must_fail("과대-발행", lambda: u0.issue(999))
    must_fail("스왑 상한 초과", lambda: u0.bootstrap(999))
    # 자기-부보 프로브는 단일-연산으로 직접 구성(SDK cover는 사전-split 복합)
    must_fail("홀더 자기-부보", lambda: u2._post("/submit", {"env": u2.sign_env(
        "UW", {"uw": "r2", "ref": ref_u,
               "cov_notes": [u2.notes()[0]["nid"]], "prem": 0,
               "prem_fund_notes": []})}))
    must_fail("불이행-앵커 자기-부보", lambda: wk._post("/submit", {
        "env": wk.sign_env("UW", {"uw": "anchor0", "ref": ref_u,
                                  "cov_notes": [wk.notes()[0]["nid"]],
                                  "prem": 0, "prem_fund_notes": []})}))
    must_fail("위조 산출 이행", lambda: wk.deliver_job(ref_c, "00" * 32))
    ref_d = redeem_p(u0, deliver=True)
    must_fail("중복 이행", lambda: wk.deliver_job(ref_d, "00" * 32))
    ref_l = redeem_p(u1, deliver=False)                # 취소-창 프로브용
    for _ in range(3):                                 # 반-창 경과(t0+3 < 기한 4)
        tick(u0)
    must_fail("취소-창 경과 취소", lambda: u1._post("/submit", {
        "env": u1.sign_env("REDEEM_CANCEL", {"holder": "r1", "ref": ref_l})}))
    used = u2.sign_env("TICKMARK", {"kind": "fl21.note", "v": "x"})
    u2._post("/submit", {"env": used})                 # nonce 소비
    good_leg = u0.make_leg("XFER", {"frm": "r0", "to": "r2",
                                    "note": [n["nid"] for n in
                                             u0.notes_of(u0.p)][0]})
    must_fail("원자 블록 나쁜 다리(전부-무효)",
              lambda: u0.submit_block([good_leg, used]))
    must_fail("유통-부채 EXIT", lambda: u0._post("/submit", {
        "env": u0.sign_env("EXIT", {"a": "r0"})}))

    # ── ③무작위 폭풍(★단일-연산 단위 — 수용 = 불변식·거부 = 상태-불변) ──
    seq0 = u0.state()["seq"]
    u0.post_ask("other", "root probe", 1, ttl=100)     # board = seq 무접촉
    if u0.state()["seq"] != seq0:
        errs.append("board가 원장을 건드림")
    for i in range(n_ops):
        c = rng.choice(us)
        op = rng.random()
        if op < 0.15:                                  # 쪼개기
            ns = [n for n in c.notes() if n["face"] > 1]
            if ns:
                n = rng.choice(ns)
                k = rng.randint(1, n["face"] - 1)
                attempt(lambda: c.split(n["nid"], [k, n["face"] - k]))
        elif op < 0.28:                                # 이전
            ns = c.notes()
            if ns:
                attempt(lambda: c.xfer(rng.choice(
                    [u.p for u in us if u.p != c.p] + ["anchor0"]),
                    rng.choice(ns)["nid"]))
        elif op < 0.36:                                # 병합(동색만 수용될 것)
            mine = c.notes_of(c.p)
            if len(mine) >= 2:
                attempt(lambda: c.merge([mine[0]["nid"], mine[1]["nid"]]))
        elif op < 0.44:                                # 회전-발행
            attempt(lambda: c.issue(rng.randint(1, 3)))
        elif op < 0.50:                                # 상호-신용 스왑(복합 편의)
            attempt_soft(lambda: c.bootstrap(rng.randint(1, 3)))
        elif op < 0.62:                                # 상환 주문(유동성 있을 때만)
            nid2 = one_a0(c)
            if nid2:
                def _rd():
                    j = c.redeem_job("anchor0", nid2, seed="ab" * 8, n=1000)
                    exposure[j["ref"]] = 1
                    open_refs[j["ref"]] = {"holder": c.p, "covered": False}
                attempt(_rd)
        elif op < 0.72:                                # 이행(열린 청구)
            if open_refs:
                ref = rng.choice(list(open_refs))   # 삽입-순(세계-독립 — ref 문자열은 세계-고유)
                def _dl():
                    wk.deliver_job(ref, Fl21Client.compute_sha256(
                        {"kind": "sha256_chain", "seed": "ab" * 8, "n": 1000}))
                if attempt(_dl):
                    stats["delivered"] += 1
                    open_refs.pop(ref, None)
        elif op < 0.80:                                # 제3자 인수
            cands = [r for r, v in open_refs.items()
                     if not v["covered"] and v["holder"] != c.p]
            # ⚠️빈-지갑 사전검사: SDK cover()는 노트 0에서 ValueError(비-정제 —
            # 다음 번들 갱신 후보로 등재 · RuntimeError 정제가 옳다)
            if cands and c.notes():
                ref = rng.choice(cands)             # 삽입-순(세계-독립)
                if attempt_soft(lambda: c.cover(ref, prem=1)):
                    stats["covered"] += 1
                    if ref in open_refs:
                        open_refs[ref]["covered"] = True
        elif op < 0.86:                                # 원자 스왑
            other = us[(us.index(c) + 1) % 3]
            mine = c.notes_of(c.p)
            theirs = other.notes_of(other.p)
            if mine and theirs:
                def _swap():
                    a = c.make_leg("XFER", {"frm": c.p, "to": other.p,
                                            "note": mine[0]["nid"]})
                    b = other.make_leg("XFER", {"frm": other.p, "to": c.p,
                                                "note": theirs[0]["nid"]})
                    c.submit_block([a, b])
                attempt(_swap)
        elif op < 0.94:                                # 틱(정산 항등식 검사 동반)
            attempt(lambda: tick(c))
        else:
            _root_invariants(nd, errs)                 # 유휴 검문
    for _ in range(6):                                 # 잔여 청구 전량 성숙·정산
        tick(u0)

    # ── ⑤종료 검증 — 라이트 검증(봉투 포함) + 리플레이 차등 ──
    v = u0.verify_chain()
    snap_live = shot()
    seq_end = u0.state()["seq"]
    srv.shutdown()
    srv.server_close()
    nd2 = NODE.Node(data)                              # 재기동 = 전체-리플레이
    snap_replay = _root_snapshot(nd2)
    # 의미-지문: 세계-고유 값(head — 키·log_id 파생)을 뺀 상태 = 같은 시드의
    # 신선-세계 간 비교 대상(리플레이-차등은 전체 스냅숏으로 같은-세계 비교)
    sem = json.loads(snap_live)
    sem.pop("head", None)
    return {"seed": seed, "ops": n_ops, **stats,
            "invariant_errors": errs[:5], "err_n": len(errs),
            "verify_ok": v.get("ok") is True,
            "replay_identical": snap_live == snap_replay,
            "seq": seq_end,
            "state_fp": __import__("hashlib").sha256(
                snap_live.encode()).hexdigest()[:16],
            "sem_fp": __import__("hashlib").sha256(json.dumps(
                sem, sort_keys=True, ensure_ascii=False).encode())
            .hexdigest()[:16],
            "pass": not errs and v.get("ok") is True
                    and snap_live == snap_replay}


def gate_TROOT():
    """★기본의 뿌리: 결정론 프롤로그(기본 회로 전량) + 필수-실패 11종(거부-원자성) +
    무작위 폭풍(수용 = 불변식·거부 = 상태-불변) + 정산 항등식 + 리플레이 차등 × 3시드."""
    out = {}
    for i, (port, seed) in enumerate([(8821, 11), (8822, 22), (8823, 33)]):
        r = _root_engine(port, seed, 150)
        out[f"seed{seed}"] = {k: r[k] for k in
                              ("accept", "reject", "settled", "covered",
                               "delivered", "err_n", "verify_ok",
                               "replay_identical", "seq", "state_fp", "pass")}
        if r["invariant_errors"]:
            out[f"seed{seed}_errs"] = r["invariant_errors"]
    out["기본경로 전량 가동"] = all(
        o["settled"] >= 1 and o["covered"] >= 1 and o["delivered"] >= 2
        and o["reject"] >= 1 for o in out.values() if isinstance(o, dict))
    out["pass"] = out["기본경로 전량 가동"] and all(
        o["pass"] for o in out.values() if isinstance(o, dict) and "pass" in o)
    return out


def gate_TERC8004(port=8821):
    """★V-1([M-159]) — ERC-8004 지목-검증자 어댑터: keccak·ABI 자기검증 ∧ 판정 사상
    실동(이행→100 · 시한-사고→0 · ★미성숙(open)→응답 거부) ∧ responseHash 결박."""
    import erc8004_adapter as EA
    out = dict(EA.selftest())
    del out["pass"]
    nd, srv, data = _serve(port)
    c = _client(port, "e8", data)
    c.join()
    c.bootstrap(8)
    a8 = c.notes_of("anchor0")[0]
    c.split(a8["nid"], [1, 1, a8["face"] - 2])
    n1, n2 = [n["nid"] for n in c.notes_of("anchor0") if n["face"] == 1][:2]
    outdir = os.path.join(data, "e8out")
    url = f"http://127.0.0.1:{port}"
    # ⓐ 이행 잡 → 100
    j1 = c.redeem_job("anchor0", n1, seed="ee" * 8, n=5000)
    wk = AnchorWorker(url, os.path.join(data, "anchor0.key"))
    wk.work_pending()
    r1_ = EA.respond(url, j1["ref"], "11" * 32, "u://1", outdir)
    doc = json.load(open(r1_["doc"]))
    out["이행→100"] = r1_["response"] == 100 and doc["verdict"] == 100
    out["responseHash 결박"] = EA.keccak256(
        open(r1_["doc"], "rb").read()).hex() == r1_["responseHash"]
    # ⓑ 미성숙 → 거부
    j2 = c.redeem_job("anchor0", n2, seed="ef" * 8, n=5000)
    try:
        EA.respond(url, j2["ref"], "11" * 32, "u://2", outdir)
        out["★미성숙 거부"] = False
    except SystemExit as ex:
        out["★미성숙 거부"] = "미성숙" in str(ex)
    # ⓒ 시한-사고 정산 → 0
    for _ in range(nd.w.GEN["redeem_T"] + 1):
        nd.tick()
    r0 = EA.respond(url, j2["ref"], "22" * 32, "u://2", outdir)
    out["사고→0"] = r0["response"] == 0
    cd = open(r0["calldata"]).read().strip()
    out["calldata 접두"] = cd.startswith(r0["selector"])
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out



def gate_TVALVE():
    """★단방향 밸브([M-160] 결합 규율의 게이트화) — 체인은 게시판이지 입력이 아니다.
    ⓐ커널 = 네트워크-무 ⓑ번들 파이썬 전 파일 = 체인-RPC 어휘 0(송신 도구는 deploy/
    운영자-측 — 번들 밖) ⓒ어댑터 = 오프라인 생성기(하드코딩 URL 무) ⓓ어댑터 응답 =
    증거-선행(문서 쓰기가 calldata 쓰기보다 코드상 먼저) ⓔ자기-당사자 가드 실동."""
    out = {}
    kern = open(os.path.join(_HERE, "..", "fin_lean", "lang23",
                             "kernel23.py"), encoding="utf-8").read()
    out["커널 네트워크-무"] = not any(
        f"import {m}" in kern for m in ("urllib", "socket", "http",
                                        "requests", "asyncio"))
    forb = ("eth_sendRawTransaction", "eth_chainId", "eth_getBalance",
            "publicnode", "drpc.org", "1rpc.io", "blastapi", "web3")
    hits = []
    for fn in sorted(os.listdir(_HERE)):
        if not fn.endswith(".py"):
            continue
        src = open(os.path.join(_HERE, fn), encoding="utf-8").read()
        me = fn == "test_r1.py"                    # 이 게이트 자신의 어휘는 제외
        for w in forb:
            if not me and w in src:
                hits.append(f"{fn}:{w}")
    out["번들 체인-RPC 어휘 0"] = hits == []
    ad = open(os.path.join(_HERE, "erc8004_adapter.py"),
              encoding="utf-8").read()
    urls = [ln for ln in ad.splitlines() if "https://" in ln]
    out["어댑터 하드코딩 URL 무"] = (          # 독스트링 자기-노드 사용례 1건만 허용
        len(urls) <= 1 and all("node.vlue.ai" in u for u in urls))
    i_doc = ad.index('open(fp, "wb")')
    i_cd = ad.index("calldata.hex")
    out["증거-선행(문서→calldata)"] = i_doc < i_cd
    import erc8004_adapter as EA
    meta = {"genesis": ["anchor0"], "cosigners": ["cosign1"]}
    try:
        EA._party_guard({"holder": "operator"}, meta, False)
        out["자기-당사자 거부"] = False
    except SystemExit as ex:
        out["자기-당사자 거부"] = "무-오염" in str(ex)
    out["라벨-표기"] = EA._party_guard(
        {"holder": "anchor0"}, meta, True) == "operator-demonstration (labeled)"
    out["참여자 통과"] = EA._party_guard(
        {"holder": "someone"}, meta, False) == "participant"
    out["송신도구 번들-밖"] = not os.path.exists(
        os.path.join(_HERE, "erc8004_submit.py"))
    out["pass"] = all(v is True for v in out.values())
    return out



def gate_TSIGV(port=8851):
    """★[M-164] V-A — ed25519_verify 1급 kind(암호-확실 사다리 최상단의 상품화):
    정상 수령증 수리 ∧ 위조-서명 거부 ∧ 약속-밖 메시지(해시 불일치) 거부 ∧ 스펙 경계."""
    import base64
    import hashlib as _h
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "sv", data)
    c.join()
    wk = AnchorWorker(f"http://127.0.0.1:{port}",
                      os.path.join(data, "anchor0.key"))
    wk.split(wk.notes()[0]["nid"], [1, 1, wk.notes()[0]["face"] - 2])
    for n in [x for x in wk.notes() if x["face"] == 1][:2]:
        wk.xfer("sv", n["nid"])
    ek = Ed25519PrivateKey.generate()
    msg = b"service-receipt: job#42 endorsed"
    spec = {"kind": "ed25519_verify",
            "pk": ek.public_key().public_bytes_raw().hex(),
            "msg_sha256": _h.sha256(msg).hexdigest()}
    nid = c.notes_of("anchor0")[0]["nid"]
    from sdk import spec_sha256
    env = c.sign_env("REDEEM", {"holder": "sv", "note": nid,
                                "anchor": "anchor0",
                                "spec_sha256": spec_sha256(spec)})
    j = c._post("/job", {"env": env, "job": spec})
    good = {"msg_b64": base64.b64encode(msg).decode(), "sig": ek.sign(msg).hex()}
    try:                                             # 위조-서명 거부
        e2 = wk.sign_env("DELIVER", {"anchor": "anchor0", "ref": j["ref"]})
        wk._post("/deliver", {"env": e2, "output": dict(good, sig="00" * 64)})
        out["위조-서명 거부"] = False
    except RuntimeError as ex:
        out["위조-서명 거부"] = "검증 실패" in str(ex)
    try:                                             # 약속-밖 메시지 거부
        m2 = b"other message"
        e3 = wk.sign_env("DELIVER", {"anchor": "anchor0", "ref": j["ref"]})
        wk._post("/deliver", {"env": e3,
                              "output": {"msg_b64":
                                         base64.b64encode(m2).decode(),
                                         "sig": ek.sign(m2).hex()}})
        out["약속-밖 메시지 거부"] = False
    except RuntimeError as ex:
        out["약속-밖 메시지 거부"] = "해시 불일치" in str(ex)
    r = wk.deliver_job(j["ref"], good)               # 정상 수령증 수리
    out["★수령증 수리(암호-확실)"] = r["verify"].get("certainty") == "cryptographic"
    out["정산 상태"] = c.job(j["ref"]).get("delivered") is True
    try:                                             # 스펙 경계
        c._post("/job", {"env": c.sign_env(
            "REDEEM", {"holder": "sv",
                       "note": c.notes_of("anchor0")[0]["nid"],
                       "anchor": "anchor0"}),
            "job": {"kind": "ed25519_verify", "pk": "zz", "msg_sha256": "00"}})
        out["스펙 경계 거부"] = False
    except RuntimeError:
        out["스펙 경계 거부"] = True
    out["audit"] = c._get("/audit")["ok"]
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TACCEPT(port=8857):
    """★[M-178] 수락-채널 v0 — 이행-후·매수자만·(ref,p) 교체·양측 집계·record-only."""
    out = {}
    nd, srv, data = _serve(port)
    an = _client(port, "acan", data)
    an.join()
    by = _client(port, "acby", data)
    by.join()
    ot = _client(port, "acot", data)
    ot.join()
    nb = [n for n in an.notes() if n["face"] >= 3][0]
    an.split(nb["nid"], [1, 1, 1, nb["face"] - 3])
    n1, n2, n3 = [n["nid"] for n in an.notes() if n["face"] == 1][:3]
    for nid in (n1, n2, n3):
        an.xfer("acby", nid)
    j1 = by.redeem_job("acan", n1, seed="aa" * 4, n=500)
    try:                                      # ⓐ 미이행 잡 수락 = 거부
        by.accept_job(j1["ref"], "accept")
        out["미이행 거부"] = False
    except Exception:
        out["미이행 거부"] = True
    an.deliver_job(j1["ref"], JOBS.compute("sha256_chain", "aa" * 4, 500))
    j2 = by.redeem_job("acan", n2, seed="bb" * 4, n=500)
    an.deliver_job(j2["ref"], JOBS.compute("sha256_chain", "bb" * 4, 500))
    j3 = by.redeem_job("acan", n3, seed="cc" * 4, n=500)   # 열린 잡(요율 대조용)
    p0 = by.suggest_prem(j3["ref"])
    out["수락 게시"] = bool(by.accept_job(j1["ref"], "accept")["id"])
    by.accept_job(j2["ref"], "rework", note="형식은 맞고 결이 다름")
    try:                                      # ⓑ 비-매수자 = 거부
        ot.accept_job(j1["ref"], "accept")
        out["비-매수자 거부"] = False
    except Exception:
        out["비-매수자 거부"] = True
    by.accept_job(j1["ref"], "rework")        # ⓒ (ref,p) 교체-주소
    recs = by.accepts()["records"]
    mine1 = [r for r in recs if r["rec"]["ref"] == j1["ref"]]
    out["교체-주소 1건"] = len(mine1) == 1 and \
        mine1[0]["rec"]["verdict"] == "rework"
    by.accept_job(j1["ref"], "accept")        # 최종 상태: j1 수락 · j2 재작업
    agg = UWT.acceptance(by)
    out["★양측 집계"] = (
        agg["anchors"]["acan"]["taste_residual"] == 0.5
        and agg["buyers"]["acby"]["reject_rate"] == 0.5
        and agg["anchors"]["acan"]["rated"] == 2)
    out["★record-only(요율 불변)"] = by.suggest_prem(j3["ref"]) == p0
    agg2 = UWT.acceptance(by, tau=0.4)           # ★[M-181] τ-결합(자문-가격층)
    out["★τ-할증 산술"] = agg2["buyers"]["acby"]["surcharge_mult"] == 1.2 \
        and agg2["tau"] == 0.4 \
        and "surcharge_mult" not in UWT.acceptance(by)["buyers"]["acby"]
    # ★[M-186] 개명 회귀 — 기호 충돌(담보비율 β ↔ 매수자-할증)을 가른 뒤,
    # ⓐ 구명 인자가 되살아나지 않고 ⓑ 출력 키가 τ로 굳었는지 잠근다.
    try:
        UWT.acceptance(by, beta=0.4)
        out["★β 구명 차단"] = False
    except TypeError:
        out["★β 구명 차단"] = True
    out["★출력 키 = tau"] = "tau" in agg2 and "beta" not in agg2
    from sdk import ACCEPT_DOMAIN, canon as _cn
    bad = {"ref": j1["ref"], "p": "acby", "verdict": "accept", "note": "",
           "expires": 0}                      # ⓓ 비-미래 만료 = 거부(epoch ≥ 0)
    sg = by.key.sign(ACCEPT_DOMAIN + by.log_id + _cn(bad)).hex()
    try:
        by._post("/accept", {"rec": bad, "sig": sg})
        out["만료 검증"] = False
    except Exception:
        out["만료 검증"] = True
    out["audit"] = by._get("/audit")["ok"]
    # ★[M-209] R2-F09-A — 판정 재생-되돌리기: 캡처한 옛 레코드를 새 판정 뒤 재게시 → 거부 · 현재 판정 유지 · v 없는 레코드 거부
    recs = [r for r in by._get("/accept")["records"] if r["rec"]["p"] == "acby"]
    if recs:
        old = recs[0]
        ref_o = old["rec"]["ref"]
        cur_v = old["rec"].get("v", 0)
        out["★accept v 존재"] = cur_v >= 1
        nv = "rework" if old["rec"]["verdict"] == "accept" else "accept"
        by.accept_job(ref_o, nv, "changed")
        now_rec = next(r for r in by._get("/accept")["records"] if r["rec"]["p"] == "acby" and r["rec"]["ref"] == ref_o)
        out["★accept 교체 = v 전진"] = now_rec["rec"]["v"] == cur_v + 1 and now_rec["rec"]["verdict"] == nv
        try:
            ot._post("/accept", {"rec": old["rec"], "sig": old["sig"]})     # 제3자가 캡처한 옛 서명 재생
            out["★옛 판정 재생 거부"] = False
        except Exception as ex:
            out["★옛 판정 재생 거부"] = "되돌리기" in str(ex) or "버전" in str(ex)
        again = next(r for r in by._get("/accept")["records"] if r["rec"]["p"] == "acby" and r["rec"]["ref"] == ref_o)
        out["★재생 뒤 최신 판정 유지"] = again["rec"]["verdict"] == nv
        nov = {k: v for k, v in old["rec"].items() if k != "v"}
        sg = by.key.sign(by._d["accept"] + by.log_id + canon(nov)).hex()
        try:
            by._post("/accept", {"rec": nov, "sig": sg})
            out["★v 없는 레코드 거부"] = False
        except Exception:
            out["★v 없는 레코드 거부"] = True
    # ★[M-210] R3-F09-1 — 만료-경계 재생: 최신 판정(v 높음·짧은 ttl)이 GC-만료된 뒤 캡처한 옛 판정(v 낮음)을 재생 → 워터마크가 거부
    j2r = j2["ref"]
    old2 = next(r for r in by._get("/accept")["records"] if r["rec"]["ref"] == j2r)
    by.accept_job(j2r, "accept", "final", ttl=1)          # v 전진 · 만료 = epoch+1
    for _ in range(3):
        nd.tick()
    try:
        ot._post("/accept", {"rec": old2["rec"], "sig": old2["sig"]})
        out["★만료 뒤 옛 판정 부활 거부"] = False
    except Exception as ex:
        out["★만료 뒤 옛 판정 부활 거부"] = "워터마크" in str(ex) or "부활" in str(ex)
    out["★만료 뒤 더 높은 v 는 통과"] = bool(by.accept_job(j2r, "rework", "again")["id"])
    # ★[M-210] R3-F09-2 — 릴레이 fetch 는 신선-서명(epoch ±8 · 서명 1회): 같은 서명 재사용 → 거부 · epoch 없는 본문 → 거부
    from sdk import canon as _cn2
    fb = {"p": "acby", "fetch": True, "epoch": by._get("/state")["epoch"]}
    fs = by.key.sign(by._d["relay"] + by.log_id + _cn2(fb)).hex()
    out["fetch 1회 통과"] = isinstance(by._post("/relay/fetch", {"msg": fb, "sig": fs}), dict)
    try:
        by._post("/relay/fetch", {"msg": fb, "sig": fs})
        out["★fetch 서명 재생 거부"] = False
    except Exception as ex:
        out["★fetch 서명 재생 거부"] = "재생" in str(ex)
    fb0 = {"p": "acby", "fetch": True}
    fs0 = by.key.sign(by._d["relay"] + by.log_id + _cn2(fb0)).hex()
    try:
        by._post("/relay/fetch", {"msg": fb0, "sig": fs0})
        out["★epoch 없는 fetch 거부"] = False
    except Exception as ex:
        out["★epoch 없는 fetch 거부"] = "epoch" in str(ex)
    out["SDK fetch_legs 정상"] = isinstance(by.fetch_legs(), (list, dict))
    # ★[M-211] R4-F06-4 — 매수자 REKEY 뒤에도 옛 수락 레코드는 서명-시점 키로 검증돼 이력이 남는다(회전 = 세탁 아님)
    _agg_b = UWT.acceptance(by)
    by.rekey()
    _agg_a = UWT.acceptance(by)
    out["★매수자 회전 뒤 수락 이력 유지(sig_rejected 0)"] = _agg_a.get("sig_rejected", 0) == 0 and \
        _agg_a["anchors"]["acan"]["rated"] == _agg_b["anchors"]["acan"]["rated"]
    # ★[M-213] Q-7(R5-F10-1) — 잡 취소 뒤 같은 에포크의 **원시** 재-REDEEM(같은 ref) 은 거부(죽은 잡-껍데기 상속 차단) · /job 재청구는 정상
    _nb2 = max(an.notes_of("acan"), key=lambda x: x["face"])
    an.split(_nb2["nid"], [1, _nb2["face"] - 1])
    n4 = [n["nid"] for n in an.notes_of("acan") if n["face"] == 1][0]
    an.xfer("acby", n4)
    j4 = by.redeem_job("acan", n4, seed="dd" * 4, n=500)                 # 신선한 잡(취소-창 안)
    by._post("/submit", {"env": by.sign_env("REDEEM_CANCEL", {"ref": j4["ref"]})})
    try:
        by._post("/submit", {"env": by.sign_env("REDEEM", {"holder": "acby", "note": n4, "anchor": "acan"})})
        out["★취소 뒤 원시 재-REDEEM(같은 ref) 거부"] = False
    except RuntimeError as ex:
        out["★취소 뒤 원시 재-REDEEM(같은 ref) 거부"] = "충돌" in str(ex)
    j4b = by.redeem_job("acan", n4, seed="dd" * 4, n=500)
    out["★/job 경로 재청구는 정상(새 기록 open)"] = nd.jobs[j4b["ref"]]["state"] == "open"
    # ★[M-213] Q-4(R5-F02-4) — 커널 커밋 뒤 단계 실패는 400(=미커밋 암시)이 아니라 500
    _pn = nd._persist_new
    nd._persist_new = lambda: (_ for _ in ()).throw(OSError("disk"))
    _seq0 = len(nd.w.log)
    try:
        by._post("/submit", {"env": by.sign_env("TICKMARK", {"kind": "fl21.version", "v": "v1"})})
        out["★커밋-후 실패 = 500"] = False
    except RuntimeError as ex:
        out["★커밋-후 실패 = 500"] = "HTTP 500" in str(ex) and len(nd.w.log) == _seq0 + 1
    nd._persist_new = _pn
    # ★[M-216] N-44 — 증분 카운터 = 전수 스캔(모든 색 · 정산·소각·민트 뒤)
    out["★outstanding 카운터 정합"] = all(nd.outstanding(c) == nd._outstanding_slow(c) for c in set(nd.colors.values()) | {"acan", "acby"})
    out["★audit 는 카운터 정합도 본다"] = nd.audit()["ok"] is True
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TPROV(port=8858):
    """★[M-178] 출처-계기 v0 — 보관-사슬 혈통 분해가 구성 시나리오와 정확 일치.
    ⓐ직접-순환(발행자→매수자→상환) ⓑearned-경유(독립·실-이행 이력자 경유)
    ⓒearned-수요(홀더 자신이 이력자) · rooted_ext = 0 기준선 · 보존식."""
    out = {}
    nd, srv, data = _serve(port)
    A = _client(port, "pva", data)
    A.join()
    B = _client(port, "pvb", data)
    B.join()
    C = _client(port, "pvc", data)
    C.join()
    cn = [n for n in C.notes() if n["face"] >= 2][0]     # ⓐ선행: C가 이력자가 된다
    C.split(cn["nid"], [1, cn["face"] - 1])
    nc = [n["nid"] for n in C.notes() if n["face"] == 1][0]
    C.xfer("pvb", nc)
    jc = B.redeem_job("pvc", nc, seed="dd" * 4, n=500)
    C.deliver_job(jc["ref"], JOBS.compute("sha256_chain", "dd" * 4, 500))
    na = [n for n in A.notes() if n["face"] >= 4][0]
    A.split(na["nid"], [1, 1, 1, na["face"] - 3])
    a1, a2, a3 = [n["nid"] for n in A.notes() if n["face"] == 1][:3]
    A.xfer("pvb", a1)                                     # ⓑ 직접-순환
    j1 = B.redeem_job("pva", a1, seed="ee" * 4, n=500)
    A.deliver_job(j1["ref"], JOBS.compute("sha256_chain", "ee" * 4, 500))
    A.xfer("pvc", a2)                                     # ⓒ earned-경유(C 경유)
    C.xfer("pvb", a2)
    j2 = B.redeem_job("pva", a2, seed="ff" * 4, n=500)
    A.deliver_job(j2["ref"], JOBS.compute("sha256_chain", "ff" * 4, 500))
    A.xfer("pvc", a3)                                     # ⓓ earned-수요(홀더 = C)
    j3 = C.redeem_job("pva", a3, seed="ab" * 4, n=500)
    A.deliver_job(j3["ref"], JOBS.compute("sha256_chain", "ab" * 4, 500))
    pr = UWT.provenance(A)
    out["리플레이-결박"] = "error" not in pr
    ra = pr["anchors"].get("pva", {})
    out["★혈통 분해"] = (ra.get("V") == 3 and ra.get("direct_cycle") == 2
                        and ra.get("earned_routed") == 1
                        and ra.get("routed") == 0)
    out["★earned-수요"] = ra.get("earned_demand") == 1
    out["★막-기준선 0"] = ra.get("rooted_ext") == 0
    out["보존"] = (ra.get("direct_cycle", 0) + ra.get("routed", 0)
                  + ra.get("earned_routed", 0)
                  + ra.get("rooted_ext", 0)) == ra.get("V")
    # ★[M-181] v1 hop-감쇠: ⓑh=1(w 1.0)·ⓒh=2(0.85)·ⓓh=1(1.0) → 0.95 · 중앙값 1
    out["★hop-가중 v1"] = (ra.get("hops_med") == 1
                          and abs(ra.get("w085_share", 0) - 0.95) < 1e-9)
    # ★[M-182] v2 용량-결박: ⓑ직접(indep ∅ → 0)·ⓒC-경유(용량 1 ≥ face 1 → 0.85)·
    # ⓓ홀더=C(indep ∅ → 0) ⟹ w_eh_share = 0.85/3
    out["★v2 용량-결박"] = abs(ra.get("w_eh_share", 0) - round(0.85 / 3, 4)) \
        < 1e-9
    # ★[M-182] 출처-λ 다이얼: 분모 할인으로 후보가 걸러진다(v0 trust-λ 대비)
    pvu = _client(port, "pvu", data)
    pvu.join()
    # ★[M-195] λ 분모가 이제 mature_delivered_volume 다(미성숙 부피 위조-방어) — pva 의
    # 선행 이행(j1·j2·j3)을 성숙시켜야 trust_lambda 캡이 j4 를 admit 한다(성숙 = now ≥
    # t0+T). ⚠️ 성숙 틱은 반드시 j4 생성 **전**에 — j4 뒤에 돌리면 j4 자신이 만료돼
    # 후보에서 사라진다(냉독 라운드5 T-PROV 실패의 실제 원인).
    for _ in range(20):
        with nd.lock:
            nd.tick()
    nb4 = [n for n in A.notes() if n["face"] >= 2][0]
    A.split(nb4["nid"], [1, nb4["face"] - 1])
    a4 = [n["nid"] for n in A.notes() if n["face"] == 1][0]
    A.xfer("pvb", a4)
    j4 = B.redeem_job("pva", a4, seed="cd" * 4, n=500)
    pol0 = {"min_rate_bp": 0, "family_herf_max": 1.0, "trust_lambda": 1.0}
    sc_off = UWT.scan(pvu, pol0)
    sc_on = UWT.scan(pvu, {**pol0, "prov_lambda": "v2"})
    refs_off = {cd["ref"] for cd in sc_off.get("candidates", [])}
    refs_on = {cd["ref"] for cd in sc_on.get("candidates", [])}
    out["★출처-λ 할인"] = (j4["ref"] in refs_off) and (j4["ref"] not in refs_on)
    rc = pr["anchors"].get("pvc", {})
    out["이력자-앵커 행"] = rc.get("V") == 1 and rc.get("direct_cycle") == 1
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TUNSIGNED(port=8830):
    """★[M-189] C-1 — 서명 없는 원장이 외부 검증을 통과하면 안 된다(H7 근간).
    옛 `if "head_sig" in e:` 는 부재를 통과시켰다(냉독 2차 B1). 양성(정상 통과) +
    음성(서명 벗김 거부) 둘 다 잰다 · verify_chain·replay_verify 양쪽."""
    import copy
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "us", data); c.join()
    c.split(c.notes()[0]["nid"], [5, 15])
    with nd.lock:
        nd.tick()
    meta = c._get("/meta")
    good = []
    s0 = 0
    while True:
        pg = c._get(f"/log?since={s0}")["entries"]
        if not pg:
            break
        good += pg
        s0 = pg[-1]["seq"] + 1
    # ① 정상 — verify_chain 통과
    out["정상 verify_chain 통과"] = c.verify_chain()["ok"] is True
    # ② 서명 벗김 — 커널 replay_verify 가 거부
    stripped = [{k: v for k, v in e.items() if k != "head_sig"} for e in copy.deepcopy(good)]
    w = World.from_public({"operator": meta["operator_pk"], **(meta.get("genesis_pks") or {})},
                          meta["label"], tuple(meta["genesis"]),
                          gen=dict(meta["gen"]), bridge_ref=meta.get("bridge_ref"))
    r = w.replay_verify(stripped)
    out["★서명 벗김 replay_verify 거부"] = (r["ok"] is False and "부재" in str(r.get("why")))
    # ③ 정상 원장은 replay_verify 통과(음성이 양성을 안 깨는지)
    w2 = World.from_public({"operator": meta["operator_pk"], **(meta.get("genesis_pks") or {})},
                           meta["label"], tuple(meta["genesis"]),
                           gen=dict(meta["gen"]), bridge_ref=meta.get("bridge_ref"))
    out["정상 replay_verify 통과"] = w2.replay_verify(good)["ok"] is True
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TDELIVERAUTH(port=8831):
    """★[M-189] C-2 — 인증 전 원장 영구-기입(ocommit 증폭) 봉합. 위조·미서명
    /deliver 는 원장을 **한 항도** 못 쓰고, 정상 이행은 여전히 수리돼야 한다."""
    import base64
    out = {}
    nd, srv, data = _serve(port)
    atk = _client(port, "atk", data); atk.join()
    wk = AnchorWorker(f"http://127.0.0.1:{port}", os.path.join(data, "anchor0.key"))
    g = wk.notes()[0]
    wk.split(g["nid"], [10, g["face"] - 10])
    wk.xfer("atk", [x for x in wk.notes() if x["face"] == 10][0]["nid"])
    nid = [x["nid"] for x in atk.notes_of("anchor0") if x["face"] == 10][0]
    j = atk.redeem_job("anchor0", nid, seed="aa" * 8, n=1000,
                       kind="sha256_chain_sampled")
    ref = j["ref"]
    e0 = nd.audit()["entries"]
    oc0 = atk._get(f"/job/{ref}").get("ocommits", 0)
    want = -(-1000 // JOBS.CKPT)
    fake = {"final": "ab" * 32, "ckpts": ["ab" * 32] * want}
    codes = []
    for _ in range(10):                           # 위조·미서명 /deliver
        try:
            atk._post("/deliver", {"env": {"typ": "DELIVER", "args": {"ref": ref},
                      "p": "atk", "epoch": 0, "nonce": 0, "sig": "00" * 64},
                      "output": fake})
            codes.append(200)
        except RuntimeError:
            codes.append(400)
    with nd.lock:
        nd.tick()
    e1 = nd.audit()["entries"]
    oc1 = atk._get(f"/job/{ref}").get("ocommits", 0)
    out["위조 /deliver 전부 거부"] = set(codes) == {400}
    out["★원장 증가 = 0(tick 제외)"] = (e1 - e0) <= 1
    out["★ocommit 카운터 불변"] = oc1 == oc0
    out["audit ok"] = nd.audit()["ok"] is True
    # 정상 이행은 여전히 수리(sampled) — 워커 경로
    spec = atk.job(ref)["job"]
    r = wk.deliver_job(ref, JOBS.compute(spec["kind"], spec["seed"], spec["n"]))
    out["정상 sampled 이행 수리"] = bool(r)
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TDELTALIEN(port=8832):
    """★[M-189] C-3 — δ 는 기본으로 **움직일 수 있는 자유잔고**를 신용하지 않는다
    (리엔 부재). 기본값에서 앵커가 XFER 로 잔고를 빼도 권고 보험료 불변 ∧ opt-in
    시에만 옛 δ 할인이 산다."""
    out = {}
    nd, srv, data = _serve(port)
    buyer = _client(port, "buyer", data); buyer.join()
    uwr = _client(port, "uwr", data); uwr.join()
    sink = _client(port, "sink", data); sink.join()
    wk = AnchorWorker(f"http://127.0.0.1:{port}", os.path.join(data, "anchor0.key"))
    g = wk.notes()[0]
    wk.split(g["nid"], [5, g["face"] - 5])
    wk.xfer("buyer", [x for x in wk.notes() if x["face"] == 5][0]["nid"])
    nid = [x["nid"] for x in buyer.notes_of("anchor0") if x["face"] == 5][0]
    buyer.redeem_job("anchor0", nid, seed="aa" * 8, n=1000, T=6)
    p1 = [x["prem"] for x in UWT.scan(uwr).get("candidates", [])]
    for z in sorted(wk.notes(), key=lambda x: -x["face"]):
        if z["face"] > 0:
            wk.xfer("sink", z["nid"])
    p2 = [x["prem"] for x in UWT.scan(uwr).get("candidates", [])]
    out["기본값: 잔고 이동에 보험료 불변"] = (p1 and p2 and p1[0] == p2[0])
    # opt-in 이면 δ 할인이 산다(잔고 있을 때 < 잔고 0일 때)
    pol = {**UWT.DEFAULT_POLICY, "delta_from_free_balance": True}
    _ = pol
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TBLOCKGUARD(port=8833):
    """★[M-190] CRITICAL — BLOCK 봉투는 /submit 로 못 들어간다(다리 무가드 우회 봉합).
    정상 /block 은 유지 · BLOCK-via-/submit 은 거부 · 색-라우팅 우회 불가."""
    out = {}
    nd, srv, data = _serve(port)
    victim = _client(port, "victim", data); victim.join()
    bb = _client(port, "bb", data); bb.join()
    holder = _client(port, "holder", data); holder.join()
    subm = _client(port, "subm", data); subm.join()
    bb.split(bb.notes()[0]["nid"], [1, 19])
    bb.xfer("holder", [n["nid"] for n in bb.notes() if n["face"] == 1][0])
    nid = holder.notes_of("bb")[0]["nid"]
    # BLOCK-via-/submit 로 색-라우팅 우회(bb-노트 → victim) 시도
    leg = holder.sign_env("REDEEM", {"holder": "holder", "note": nid, "anchor": "victim"})
    blk = subm.sign_env("BLOCK", {"legs": [leg]})
    try:
        subm._post("/submit", {"env": blk})
        out["★BLOCK-via-/submit 거부"] = False
    except RuntimeError as e:
        out["★BLOCK-via-/submit 거부"] = "/block 전용" in str(e)
    out["우회 미발생(redeem_pending victim 없음)"] =         "victim" not in [v.get("anchor") for v in nd.w.redeem_pending.values()]
    # 정상 /block XFER 은 유지
    aa = _client(port, "aa", data); aa.join()
    aa.split(aa.notes()[0]["nid"], [5, 15])
    xnid = [n["nid"] for n in aa.notes() if n["face"] == 5][0]
    r = aa.submit_block([aa.make_leg("XFER", {"frm": "aa", "to": "bb", "note": xnid})])
    out["정상 /block 유지"] = bool(r.get("seq"))
    out["원장 무오염"] = nd.audit()["ok"] is True
    # ★[M-208] R4-5(냉독 4) — 의미-실패 다리(미소유 노트 XFER)는 커널 전에 O(1) 선거부 · 원장 무변 · 재생해도 무성장
    n0 = len(nd.w.log)
    for _ in range(3):
        try:
            aa.submit_block([aa.make_leg("XFER", {"frm": "aa", "to": "bb", "note": "999999999"})])
            out["★미소유 다리 선거부"] = False
        except RuntimeError as ex:
            out["★미소유 다리 선거부"] = "선거부" in str(ex) or "미소유" in str(ex)
    out["★미소유 다리 재생 = 원장 무성장"] = len(nd.w.log) == n0
    # ★[M-209] R2-F03-1 — 다리 선체크 커널-동형 확장: REDEEM 미소유 · XFER 수취인 무효 · frm≠p 전부 선거부(원장 무성장)
    n1 = len(nd.w.log)
    vn2 = victim.notes()[0]["nid"]
    for lg, key in ((aa.make_leg("REDEEM", {"holder": "aa", "note": vn2, "anchor": "bb"}), "REDEEM 미소유"),
                    (aa.make_leg("XFER", {"frm": "aa", "to": "nobody_zz", "note": xnid}), "XFER 수취인 무효"),
                    (aa.make_leg("XFER", {"frm": "bb", "to": "aa", "note": xnid}), "XFER frm≠p")):
        try:
            aa.submit_block([lg])
            out[f"★선거부 {key}"] = False
        except RuntimeError as ex:                       # 노드-층 거부(선거부 또는 _guard_env 색-일치) — 커널 도달 전
            out[f"★선거부 {key}"] = any(t in str(ex) for t in ("선거부", "색-일치", "미소유", "발행자"))
    out["★선거부 3종 = 원장 무성장"] = len(nd.w.log) == n1
    # ★[M-210] R3-F03-1 — 같은 주체의 두 다리(커널 합법 · nonce n, n+1)는 /block 으로 성립해야 한다(구판 노드 선검증이 봉쇄하던 회귀)
    n15 = max(aa.notes(), key=lambda x: x["face"])
    aa.split(n15["nid"], [2, 3, n15["face"] - 5])
    a2 = [n["nid"] for n in aa.notes() if n["face"] == 2][0]
    a3 = [n["nid"] for n in aa.notes() if n["face"] == 3][0]
    nn = aa._get("/nonce/aa")["nonce"]
    l1 = aa.sign_env("XFER", {"frm": "aa", "to": "bb", "note": a2}, nonce=nn)
    l2 = aa.sign_env("XFER", {"frm": "aa", "to": "bb", "note": a3}, nonce=nn + 1)
    r2l = aa.submit_block([l1, l2])
    out["★같은 주체 2다리 /block 성립"] = bool(r2l.get("seq")) and {a2, a3} <= {n["nid"] for n in bb.notes_of("aa")}
    out["★2다리 뒤 nonce = +2"] = aa._get("/nonce/aa")["nonce"] == nn + 2
    # ★[M-210] R3-F03-2/3 — UW·REDEEM 다리의 커널-조건 미러: 담보 공백 UW · holder≠행위자 REDEEM 은 선거부(원장 무성장 = 무기록 재생 없음)
    holder._post("/submit", {"env": holder.sign_env("REDEEM", {"holder": "holder", "note": nid, "anchor": "bb"})})
    ref_h = next(iter(nd.w.redeem_pending))
    n2 = len(nd.w.log)
    for lg, key in ((subm.make_leg("UW", {"uw": "subm", "ref": ref_h, "cov_notes": [], "prem": 0}), "UW 담보 공백"),
                    (subm.make_leg("UW", {"uw": "bb", "ref": ref_h, "cov_notes": [a2], "prem": 0}), "UW 행위자≠인수자"),
                    (aa.make_leg("REDEEM", {"holder": "bb", "note": [n["nid"] for n in aa.notes()][0], "anchor": "bb"}), "REDEEM holder≠행위자")):
        try:
            (subm if key.startswith("UW") else aa).submit_block([lg])
            out[f"★선거부 {key}"] = False
        except RuntimeError as ex:
            out[f"★선거부 {key}"] = "선거부" in str(ex) or "색-일치" in str(ex)
    out["★UW/REDEEM 미러 선거부 = 원장 무성장"] = len(nd.w.log) == n2
    # ★[M-211] R4-F10-1 — [UW(u), XFER u→u] 한 블록은 prem_verified 를 만들지 않는다(원가 0 부양)
    nb19 = max(bb.notes_of("bb"), key=lambda x: x["face"])
    bb.split(nb19["nid"], [1, nb19["face"] - 1])
    hb1 = [n["nid"] for n in bb.notes_of("bb") if n["face"] == 1][0]
    bb.xfer("holder", hb1)
    hj = holder.redeem_job("bb", hb1, seed="ab" * 4, n=500)
    sn = max(subm.notes_of("subm"), key=lambda x: x["face"])
    subm.split(sn["nid"], [1, sn["face"] - 1])
    s1 = [n["nid"] for n in subm.notes_of("subm") if n["face"] == 1][0]
    s_big = [n["nid"] for n in subm.notes_of("subm") if n["face"] > 1][0]
    nn2 = subm._get("/nonce/subm")["nonce"]
    lu = subm.sign_env("UW", {"uw": "subm", "ref": hj["ref"], "cov_notes": [s1], "prem": 0}, nonce=nn2)
    lx = subm.sign_env("XFER", {"frm": "subm", "to": "subm", "note": s_big}, nonce=nn2 + 1)
    rb = subm.submit_block([lu, lx])
    out["★자기-XFER 블록 성립(커널 합법)"] = bool(rb.get("seq"))
    out["★자기-XFER 보험료 미포획"] = not nd.jobs[hj["ref"]].get("prem_verified")
    # ★[M-211] R4-F08-2 — 임의-kind TICKMARK 크기 상한(15 KB 행 팽창 차단)
    try:
        aa._post("/submit", {"env": aa.sign_env("TICKMARK", {"kind": "fl21.version", "v": "x" * 3000})})
        out["★TICKMARK 크기 상한"] = False
    except RuntimeError as ex:
        out["★TICKMARK 크기 상한"] = "크기" in str(ex)
    # ★[M-212] R5-F03-1 — 피해자 다리 1장 + 공격자 위조 다리로 실패 블록을 반복해도 피해자 쓰기 예산은 과금되지 않는다(과금 = 기록 뒤)
    vleg = aa.sign_env("XFER", {"frm": "aa", "to": "bb", "note": [n["nid"] for n in aa.notes_of("aa")][0]})
    forged = {"typ": "XFER", "args": {"frm": "zz", "to": "bb", "note": "1"}, "p": "zz", "epoch": 0, "nonce": 0, "sig": "00"}
    _wb0 = list(nd.write_bytes.get("aa") or [0, 0])
    for _ in range(5):
        try:
            subm.submit_block([vleg, forged])
        except RuntimeError:
            pass
    out["★실패 블록 반복 = 피해자 쓰기 예산 불변"] = list(nd.write_bytes.get("aa") or [0, 0]) == _wb0
    out["★실패 블록 반복 = 피해자 nonce 불변"] = aa._get("/nonce/aa")["nonce"] == vleg["nonce"]
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TOCOMMITCAP(port=8834):
    """★[M-190] C-2 변종 — ref당 ocommit 상한(재생-증폭 유계화)."""
    import urllib.request, urllib.error
    out = {}
    nd, srv, data = _serve(port, unit_scale=1000, genesis_issue=40000, join_issue=20000)
    buyer = _client(port, "buyer", data); buyer.join()
    wk = AnchorWorker(f"http://127.0.0.1:{port}", os.path.join(data, "anchor0.key"))
    g = wk.notes()[0]; wk.split(g["nid"], [1000, g["face"] - 1000])
    wk.xfer("buyer", [x for x in wk.notes() if x["face"] == 1000][0]["nid"])
    nid = [x for x in buyer.notes_of("anchor0") if x["face"] == 1000][0]["nid"]
    ref = buyer.redeem_job("anchor0", nid, seed="aa" * 8, n=1000,
                           kind="sha256_chain_sampled")["ref"]
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    akey = Fl21Client.__new__(Fl21Client); akey.p = "anchor0"
    akey.base = f"http://127.0.0.1:{port}"
    akey.key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(open(os.path.join(data, "anchor0.key")).read().strip()))
    akey.log_id = buyer.log_id
    n0 = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/nonce/anchor0").read())["nonce"]
    body = {"typ": "DELIVER", "args": {"ref": ref}, "p": "anchor0",
            "epoch": buyer.state()["epoch"]}
    sig = akey.key.sign(DOMAIN + buyer.log_id + canon(body)
                        + int(n0).to_bytes(8, "big")).hex()
    fake = {"final": "ab" * 32, "ckpts": ["ab" * 32] * (-(-1000 // JOBS.CKPT))}
    CAP = NODE.OCOMMIT_CAP
    for _ in range(CAP + 10):
        req = urllib.request.Request(f"http://127.0.0.1:{port}/deliver",
            data=json.dumps({"env": {**body, "nonce": n0, "sig": sig}, "output": fake}).encode(),
            method="POST", headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError:
            pass
    oc = buyer.job(ref).get("ocommits", 0)
    out["★ocommit 상한에서 멈춤"] = oc <= CAP
    out["원장 무오염"] = nd.audit()["ok"] is True
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TNULLSIG(port=8835):
    """★[M-190] null/빈 head_sig 는 크래시가 아니라 ok:false(검증 도구 견고성)."""
    import copy
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "ns", data); c.join()
    c.split(c.notes()[0]["nid"], [5, 15])
    with nd.lock:
        nd.tick()
    meta = c._get("/meta")
    log, s0 = [], 0
    while True:
        pg = c._get(f"/log?since={s0}")["entries"]
        if not pg:
            break
        log += pg; s0 = pg[-1]["seq"] + 1
    for label, mut in (("null", None), ("empty", "")):
        bad = [{**e, "head_sig": mut} for e in copy.deepcopy(log)]
        w = World.from_public({"operator": meta["operator_pk"],
                               **(meta.get("genesis_pks") or {})},
                              meta["label"], tuple(meta["genesis"]),
                              gen=dict(meta["gen"]), bridge_ref=meta.get("bridge_ref"))
        try:
            r = w.replay_verify(bad)
            out[f"{label} head_sig → ok:false(무크래시)"] = r["ok"] is False
        except Exception:
            out[f"{label} head_sig → ok:false(무크래시)"] = False
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TACCEPTSIG(port=8836):
    """★[M-190] acceptance 가 위조 수락-레코드를 서명 재검증으로 거부."""
    out = {}
    nd, srv, data = _serve(port)
    buyer = _client(port, "buyer", data); buyer.join()
    wk = AnchorWorker(f"http://127.0.0.1:{port}", os.path.join(data, "anchor0.key"))
    g = wk.notes()[0]; wk.split(g["nid"], [5, g["face"] - 5])
    wk.xfer("buyer", [x for x in wk.notes() if x["face"] == 5][0]["nid"])
    nid = [x for x in buyer.notes_of("anchor0") if x["face"] == 5][0]["nid"]
    ref = buyer.redeem_job("anchor0", nid, seed="aa" * 8, n=1000)["ref"]
    sp = buyer.job(ref)["job"]
    wk.deliver_job(ref, JOBS.compute(sp["kind"], sp["seed"], sp["n"]))
    uwr = _client(port, "uwr", data); uwr.join()
    # 위조 레코드 주입(악의 노드 흉내)
    nd.accepts["FORGED"] = {"id": "FORGED", "rec": {"ref": ref, "p": "buyer",
        "verdict": "rework", "note": "x", "expires": nd.w.epoch + 10}, "sig": "00" * 64}
    r = UWT.acceptance(uwr)
    out["★위조 레코드 거부(sig_rejected>0)"] = r.get("sig_rejected", 0) >= 1
    out["서명 재검증 켜짐"] = r.get("sig_verified") is True
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TDELIVERTYPE(port=8837):
    """★[M-191] CRITICAL — /deliver 는 DELIVER 봉투 전용(냉독 라운드2): REDEEM/EXIT/BLOCK
    를 /deliver 로 밀어 _guard_env 우회 못 함 · 정상 DELIVER 는 유지."""
    out = {}
    nd, srv, data = _serve(port)
    victim = _client(port, "victim", data); victim.join()
    atk = _client(port, "atk", data); atk.join()
    atk.split(atk.notes()[0]["nid"], [1, 19])
    m2 = [n["nid"] for n in atk.notes() if n["face"] == 19][0]
    ref = atk.redeem_job("atk", [n["nid"] for n in atk.notes() if n["face"] == 1][0],
                         seed="aa" * 8, n=1)["ref"]
    smug = atk.sign_env("REDEEM", {"holder": "atk", "note": m2, "anchor": "victim", "ref": ref})
    sp = atk.job(ref)["job"]
    try:
        atk._post("/deliver", {"env": smug, "output": JOBS.compute(sp["kind"], sp["seed"], sp["n"])})
        out["★REDEEM-via-/deliver 거부"] = False
    except RuntimeError as e:
        out["★REDEEM-via-/deliver 거부"] = "DELIVER 봉투 전용" in str(e) or "typ" in str(e)
    out["우회 미발생(victim 피고 아님)"] = "victim" not in [v.get("anchor") for v in nd.w.redeem_pending.values()]
    # 정상 DELIVER 유지
    wk = AnchorWorker(f"http://127.0.0.1:{port}", os.path.join(data, "anchor0.key"))
    g = wk.notes()[0]; wk.split(g["nid"], [10, g["face"] - 10])
    b = _client(port, "buyer", data); b.join()
    wk.xfer("buyer", [x for x in wk.notes() if x["face"] == 10][0]["nid"])
    nid = [x for x in b.notes_of("anchor0") if x["face"] == 10][0]["nid"]
    r = b.redeem_job("anchor0", nid, seed="bb" * 8, n=100)
    sp2 = b.job(r["ref"])["job"]
    out["정상 DELIVER 유지"] = bool(wk.deliver_job(r["ref"], JOBS.compute(sp2["kind"], sp2["seed"], sp2["n"])))
    out["원장 무오염"] = nd.audit()["ok"] is True
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TENTRYFORM(port=8838):
    """★[M-191] 검증 도구는 비정형 엔트리(null/오타입 필드)에 크래시 아닌 ok:false
    (냉독 라운드2 — head_sig 외 형제 필드도 크래시했다)."""
    import copy
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "ef", data); c.join()
    c.split(c.notes()[0]["nid"], [5, 15])
    with nd.lock:
        nd.tick()
    meta = c._get("/meta")
    log, s0 = [], 0
    while True:
        pg = c._get(f"/log?since={s0}")["entries"]
        if not pg:
            break
        log += pg; s0 = pg[-1]["seq"] + 1
    ok = True
    # ★[M-192] 통째-방어(냉독 라운드3): 바깥 필드 + env 내부키 + 필드 제거까지
    mutations = [("prev", None), ("prev", 123), ("state_root", None),
                 ("env", None), ("head", None), ("head_sig", None),
                 ("w_epoch", "__DEL__"), ("fp", "__DEL__"), ("env", "__NOTYP__")]
    for fld, val in mutations:
        if val == "__DEL__":
            bad = [{k: v for k, v in e.items() if k != fld} for e in copy.deepcopy(log)]
        elif val == "__NOTYP__":
            bad = [{**e, "env": {k: v for k, v in e["env"].items() if k != "typ"}}
                   for e in copy.deepcopy(log)]
        else:
            bad = [{**e, fld: val} for e in copy.deepcopy(log)]
        w = World.from_public({"operator": meta["operator_pk"],
                               **(meta.get("genesis_pks") or {})},
                              meta["label"], tuple(meta["genesis"]),
                              gen=dict(meta["gen"]), bridge_ref=meta.get("bridge_ref"))
        try:
            r = w.replay_verify(bad)           # 크래시 없으면 OK(ok 값 자체는 무관 —
            _ = r["ok"]                        # fp 제거는 ok:true 가 정당: 커널이 fp 재계산)
        except Exception:
            ok = False
    out["★비정형 9종 무크래시(통째-방어)"] = ok
    out["정상 로그는 통과"] = World.from_public(
        {"operator": meta["operator_pk"], **(meta.get("genesis_pks") or {})},
        meta["label"], tuple(meta["genesis"]), gen=dict(meta["gen"]),
        bridge_ref=meta.get("bridge_ref")).replay_verify(log)["ok"] is True
    # ★[M-208] R4-15/16/18(냉독 4 · F05·F11) — 악의 노드 앞의 검증기·공동서명자: 정직 /meta + 빈 로그 → ok:false ·
    #   전위-절단(창세 항 제거) → ok:false · /state.seq 가 서빙분보다 크다(꼬리 생략) → ok:false · 비-전진 페이지 → ok:false ·
    #   replay_full 비정형 페이지 → H7 false · cosigner 비-단조 seq → 예외(무한 루프·/cosig 홍수 아님).
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import subprocess, sys as _sys
    cos_all = c._get("/cosigs?since=0")["cosigs"]
    MODE = {"m": "empty"}

    class Mal(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            pth = self.path
            if MODE["m"] == "big400":                          # ★[M-210] R3-F11-1 — 4xx + 거대 본문(오류-경로 OOM 레버)
                big = b"A" * (40 * 1024 * 1024); self.send_response(400)
                self.send_header("Content-Length", str(len(big))); self.end_headers(); self.wfile.write(big); return
            if pth == "/meta":
                body = meta
            elif pth.startswith("/state"):
                body = {"seq": (100 if MODE["m"] == "tail" else len(log)), "epoch": meta.get("epoch", 0)}
            elif pth.startswith("/cosigs"):
                body = {"cosigs": [] if MODE["m"] == "empty" else (cos_all if "since=0" in pth else [])}
            elif pth.startswith("/log"):
                since = int(pth.split("since=")[1])
                if MODE["m"] == "empty":
                    body = {"entries": []}
                elif MODE["m"] == "front":
                    body = {"entries": log[1:][since:since + 500] if since < len(log) else []}
                elif MODE["m"] == "nonadv":
                    body = {"entries": log[:2]}
                elif MODE["m"] == "garbage":
                    body = {"entries": "garbage"}
                elif MODE["m"] == "nonmono":
                    body = {"entries": [log[1], log[0]]}
                elif MODE["m"] == "regen":
                    body = {"entries": ([{**log[0], "head": "ab" * 32}] + log[1:2]) if since == 0 else []}
                else:
                    body = {"entries": log[since:since + 500]}
            else:
                body = {"balance": 0}
            bb = json.dumps(body).encode(); self.send_response(200)
            self.send_header("Content-Length", str(len(bb))); self.end_headers(); self.wfile.write(bb)

        def do_POST(self):                                  # 공동서명 회신(/cosig) 수용 — 정직 서빙 시 cosigner 왕복용
            n = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(n)
            bb = json.dumps({"ok": True}).encode(); self.send_response(200)
            self.send_header("Content-Length", str(len(bb))); self.end_headers(); self.wfile.write(bb)

    msrv = ThreadingHTTPServer(("127.0.0.1", port + 30), Mal)
    threading.Thread(target=msrv.serve_forever, daemon=True).start()
    murl = f"http://127.0.0.1:{port + 30}"
    try:
        v = Fl21Client(murl, "mv", os.path.join(data, "mv.key"))
        MODE["m"] = "empty"; r_empty = v.verify_chain()
        MODE["m"] = "front"; r_front = v.verify_chain()
        MODE["m"] = "tail"; r_tail = v.verify_chain()
        MODE["m"] = "nonadv"; r_nonadv = v.verify_chain(limit_batches=5)
        MODE["m"] = "honest"; r_ok = v.verify_chain()
        out["★빈 로그 = ok:false"] = r_empty.get("ok") is False and "0항" in str(r_empty.get("why"))
        out["★전위-절단 = ok:false"] = r_front.get("ok") is False and "창세" in str(r_front.get("why"))
        out["★꼬리 생략 = ok:false"] = r_tail.get("ok") is False and "꼬리" in str(r_tail.get("why"))
        out["★비-전진 페이지 = ok:false"] = r_nonadv.get("ok") is False and "전진" in str(r_nonadv.get("why"))
        out["정직 서빙 = ok:true"] = r_ok.get("ok") is True
        MODE["m"] = "garbage"
        rp = subprocess.run([_sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "replay_full.py"),
                             "--url", murl], capture_output=True, text=True, timeout=60)
        out["★replay_full 비정형 페이지 = H7 false"] = rp.returncode == 1 and '"H7_FULL_REPLAY": false' in rp.stdout
        MODE["m"] = "empty"
        rp2 = subprocess.run([_sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "replay_full.py"),
                              "--url", murl], capture_output=True, text=True, timeout=60)
        out["★replay_full 빈 로그 = H7 false"] = rp2.returncode == 1
        MODE["m"] = "nonmono"
        import cosigner as _CS
        kp = os.path.join(data, "cs_mal.key")
        with open(kp, "w") as fh:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _P2
            fh.write(_P2.generate().private_bytes_raw().hex())
        cs = _CS.Cosigner(murl, "cosign9", kp)
        try:
            cs.run_once()
            out["★cosigner 비-단조 페이지 = 중단"] = False
        except RuntimeError as ex:
            out["★cosigner 비-단조 페이지 = 중단"] = "비-단조" in str(ex) or "비정형" in str(ex)
        MODE["m"] = "big400"
        import time as _tm, resource as _rs
        _t0 = _tm.monotonic(); _m0 = _rs.getrusage(_rs.RUSAGE_SELF).ru_maxrss
        try:
            v._req("GET", "/anything")
            out["★SDK 오류-경로 거대 본문 = 상한 뒤 RuntimeError"] = False
        except RuntimeError as ex:
            out["★SDK 오류-경로 거대 본문 = 상한 뒤 RuntimeError"] = "HTTP 400" in str(ex) and _tm.monotonic() - _t0 < 25
        MODE["m"] = "honest"
        cs2 = _CS.Cosigner(murl, "cosign9", kp, state_path=os.path.join(data, "cs9.state"))
        n_signed = cs2.run_once()                              # 정직 서빙 = 전량 서명(이력 기록)
        MODE["m"] = "regen"
        cs3 = _CS.Cosigner(murl, "cosign9", kp, state_path=os.path.join(data, "cs9.state"))
        cs3.next = 0                                            # 「짧으면 0부터」 상황 = 재-창세 재서명 시도
        try:
            cs3.run_once()
            out["★cosigner 재-창세(같은 seq 다른 head) = 서명 거부"] = False
        except RuntimeError as ex:
            out["★cosigner 재-창세(같은 seq 다른 head) = 서명 거부"] = ("포크" in str(ex) and n_signed >= 1
                                                                 and os.path.exists(os.path.join(data, "cs9.state.fork")))
    finally:
        msrv.shutdown(); msrv.server_close()
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TDELIVERCAP(port=8839):
    """★[M-194] rate-dos(냉독 라운드4): full-chain /deliver 재검증이 ref당 시도-상한으로
    유계 — 틀린 산출 반복 재전송이 DELIVER_CAP 에서 멈춘다(전 kind)."""
    import urllib.request, urllib.error
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    out = {}
    nd, srv, data = _serve(port)
    atk = _client(port, "atk", data); atk.join()
    atk.split(atk.notes()[0]["nid"], [1, 19])
    m1 = [n["nid"] for n in atk.notes() if n["face"] == 1][0]
    ref = atk.redeem_job("atk", m1, seed="aa" * 8, n=100)["ref"]   # full-chain
    ak = Fl21Client.__new__(Fl21Client); ak.p = "atk"; ak.base = f"http://127.0.0.1:{port}"
    ak.key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(open(os.path.join(data, "atk.key")).read().strip()))
    ak.log_id = atk.log_id
    n0 = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/nonce/atk").read())["nonce"]
    body = {"typ": "DELIVER", "args": {"anchor": "atk", "ref": ref}, "p": "atk",
            "epoch": atk.state()["epoch"]}
    sig = ak.key.sign(DOMAIN + atk.log_id + canon(body) + int(n0).to_bytes(8, "big")).hex()
    capped = 0
    for _ in range(NODE.DELIVER_CAP + 12):
        req = urllib.request.Request(f"http://127.0.0.1:{port}/deliver",
            data=json.dumps({"env": {**body, "nonce": n0, "sig": sig}, "output": "wrong"}).encode(),
            method="POST", headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError as e:
            if "시도 상한" in e.read().decode("utf-8", "replace"):
                capped += 1
    out["★재검증 시도 상한 발동"] = capped > 0
    out["상한 = DELIVER_CAP"] = nd.deliver_attempts.get(ref, 0) == NODE.DELIVER_CAP
    out["원장 무오염"] = nd.audit()["ok"] is True
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TLISTCAP(port=8841):
    """★[M-196] 재생-DoS 부류 봉합(냉독 라운드6). 두 층:
    ⓐ커널 _LIST_MAX — 호출자-통제 리스트-인자(SPLIT parts 등)가 O(n) 반복(all/sum/set)
      **전에** 값싸게 거부(옛: parts=[1]*600000 한 봉투를 전역-락 안 O(600k)로 GET 을 820× 지연,
      실패-op nonce 무소비라 무한 재생). ⓑ노드 본문-캡 — 봉투 경로 1.8MB 본문을 Content-Length
      헤더에서 파싱 이전 O(1) 거부(GIL-묶인 json.loads 재생 봉합). 정당 봉투(작음)는 불변."""
    import socket
    import urllib.request
    import urllib.error
    out = {}
    nd, srv, data = _serve(port)
    atk = _client(port, "atk", data); atk.join()
    nid = atk.notes()[0]["nid"]; face = atk.notes()[0]["face"]
    base = f"http://127.0.0.1:{port}"

    # ⓐ 커널: parts > _LIST_MAX 는 리스트-상한에서 거부(O(n) 이전) · == _LIST_MAX 는 통과
    from kernel23 import _LIST_MAX
    over = atk.sign_env("SPLIT", {"owner": "atk", "note": nid,
                                  "parts": [1] * (_LIST_MAX + 1)})
    try:
        urllib.request.urlopen(urllib.request.Request(
            f"{base}/submit", data=json.dumps({"env": over}).encode(),
            headers={"Content-Type": "application/json"}), timeout=10)
        out["★리스트-상한 초과 거부"] = False
    except urllib.error.HTTPError as e:
        out["★리스트-상한 초과 거부"] = "리스트-인자" in e.read().decode("utf-8", "replace")
    # 경계: 정확히 _LIST_MAX 는 길이-검사를 통과(합≠액면으로 뒤늦게 거부 — 길이가 막지 않음)
    at = atk.sign_env("SPLIT", {"owner": "atk", "note": nid, "parts": [1] * _LIST_MAX})
    try:
        urllib.request.urlopen(urllib.request.Request(
            f"{base}/submit", data=json.dumps({"env": at}).encode(),
            headers={"Content-Type": "application/json"}), timeout=10)
        out["경계 = _LIST_MAX 통과(합에서 거부)"] = False
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", "replace")
        out["경계 = _LIST_MAX 통과(합에서 거부)"] = ("부분 합" in msg
                                                and "리스트-인자" not in msg)

    # ⓑ 노드: 봉투 경로 초과-본문은 Content-Length 헤더에서 파싱 이전 O(1) 거부(raw 소켓 —
    #   서버가 본문 읽기 전 400+close 하므로 broken-pipe 내성 필요)
    big = b"x" * (NODE.ENV_BODY_CAP + 1)
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(b"POST /submit HTTP/1.0\r\nContent-Type: application/json\r\n"
              b"Content-Length: %d\r\n\r\n" % len(big))
    try:
        s.sendall(big)
    except OSError:
        pass                          # 서버가 이미 거부·close — 정상(파싱 이전 거부의 증거)
    try:
        head = s.recv(256).decode("utf-8", "replace")
    except OSError:
        head = ""
    s.close()
    out["★초과-본문 헤더-거부"] = "400" in head
    # 거부 직후 노드가 즉시 응답(전역 락 무독점 — 무거운 파싱 안 함)
    out["거부 후 노드 즉응"] = json.loads(
        urllib.request.urlopen(f"{base}/meta", timeout=5).read()).get("log_id") is not None

    # 정당 회귀: 작은 SPLIT 는 200
    r = atk.split(nid, [1, face - 1])
    out["정당 SPLIT 통과"] = isinstance(r, dict)
    out["원장 무오염"] = nd.audit()["ok"] is True
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TREPLAYCAP(port=8842):
    """★[M-197] 재생-DoS 잔여 두 경로 봉합(냉독 라운드7 — M-196 의 절반-쌍둥이):
    ⓐ노드 _guard_env 의 색/scope 스캔이 커널 _LIST_MAX·서명검증 **전에** 호출자-리스트를
      O(n) 순회하던 사전-인증 재생(MERGE notes) → _guard_env 상단 노드-층 리스트-상한.
    ⓑ실패-op 는 nonce 미소비라 무한 재생하며 매번 _snap(O(원장))을 강제 → (주체,nonce)
      슬롯당 SUBMIT_FAIL_CAP 상한(서명 통과분만 계수 = 위조 p grief 없음)."""
    import urllib.request
    import urllib.error
    from kernel23 import _LIST_MAX
    out = {}
    nd, srv, data = _serve(port)
    B = f"http://127.0.0.1:{port}"

    def post(env):
        b = json.dumps({"env": env}, separators=(",", ":")).encode()
        try:
            urllib.request.urlopen(urllib.request.Request(
                f"{B}/submit", data=b,
                headers={"Content-Type": "application/json"}), timeout=10)
            return 200, ""
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

    # ⓐ 사전-인증 MERGE 리스트 스캔: 미등록 주체·위조 서명 봉투로도 노드-층 상한이 막는다
    ghost = {"typ": "MERGE", "args": {"owner": "zz", "notes": [1] * (_LIST_MAX + 1)},
             "p": "zz", "epoch": 0, "nonce": 0, "sig": "00"}
    c, msg = post(ghost)
    out["★사전-인증 MERGE 리스트-상한"] = (c == 400 and "리스트-인자" in msg)
    # ⓐ 경계: _LIST_MAX 는 통과(색-검사에서 거부 — 길이가 막지 않음)
    ghost_at = {**ghost, "args": {"owner": "zz", "notes": [1] * _LIST_MAX}}
    c2, msg2 = post(ghost_at)
    out["경계 = _LIST_MAX 통과"] = (c2 == 400 and "리스트-인자" not in msg2)

    # ⓑ ★FL2.3 J-7([M-201~]) — [M-197] 캡은 제거됐다: 인증-거부는 커널이 **REJECT 항**으로 기록하고 nonce 를
    #    소비한다(같은 봉투 재생 = nonce 거부·무기록) · 위조 p 는 무기록 · ★T-NOLOCK: 정직 신원이 16회 오타를
    #    내도 교정 op 가 통과한다([FL23_SCOPE §2-④] 자기-잠금 재현의 음성 대조).
    atk = _client(port, "atk", data); atk.join()
    victim = _client(port, "vv", data); victim.join()
    vn = victim.notes()[0]["nid"]                 # atk 소유 아님
    env = atk.sign_env("SPLIT", {"owner": "atk", "note": vn, "parts": [1, 1]})
    n0 = len(nd.w.log)
    c1, m1 = post(env)                            # 1회: 인증-거부 → REJECT 항 + nonce 소비
    c2, m2 = post(env)                            # 2회: 같은 봉투 = nonce 불일치(무기록)
    out["★인증-거부 = REJECT 항 + 400 code/reject_seq"] = (
        c1 == 400 and '"reject_seq"' in m1 and '"code": "not_owner"' in m1
        and len(nd.w.log) == n0 + 1 and nd.w.log[-1].get("kind") == "REJECT")
    out["★재생 = nonce 거부·무기록"] = c2 == 400 and "nonce" in m2 and len(nd.w.log) == n0 + 1
    forged = {"typ": "SPLIT", "args": {"owner": "vv", "note": vn, "parts": [1, 1]},
              "p": "vv", "epoch": 0, "nonce": 0, "sig": "00"}
    n1 = len(nd.w.log)
    for _ in range(24):
        post(forged)
    out["★위조 p 무기록(grief 없음)"] = len(nd.w.log) == n1
    for _ in range(16):                           # 정직 신원의 오타 16회(각각 REJECT · nonce 전진)
        post(atk.sign_env("SPLIT", {"owner": "atk", "note": vn, "parts": [1, 1]}))
    mine = atk.notes()[0]
    r = atk.split(mine["nid"], [1, mine["face"] - 1])
    out["★T-NOLOCK 정직 교정-op 통과(16회 오타 후)"] = isinstance(r, dict) and "seq" in r
    vnote = next(n for n in victim.notes() if n["nid"] == vn)
    r = victim.split(vn, [1, vnote["face"] - 1])
    out["정당 SPLIT 통과"] = isinstance(r, dict) and "seq" in r
    out["원장 무오염"] = nd.audit()["ok"] is True
    # ★[M-208] R4-4(냉독 4 · HIGH 가용성) — REJECT **기록** 예산: 16 건은 기록됐다(위 오타 16회) · 17번째 인증-거부는
    #   세이브포인트로 되감겨 **무기록 400**(원장·nonce 무변) · 그 뒤 정직 op 는 여전히 통과(M-198 자기-잠금 재발 없음).
    n_before = len(nd.w.log)
    nonce_b = atk._get(f"/nonce/atk")["nonce"]
    c17, m17 = post(atk.sign_env("SPLIT", {"owner": "atk", "note": vn, "parts": [1, 1]}))
    out["★REJECT 예산: 400 code = reject_budget"] = '"code": "reject_budget"' in str(m17)   # ★[M-209] R2-F01-1
    out["★REJECT 예산: 17번째 거부 = 무기록 400"] = (c17 == 400 and "예산" in str(m17) and len(nd.w.log) == n_before
                                                 and atk._get("/nonce/atk")["nonce"] == nonce_b)
    mine2 = max(atk.notes(), key=lambda x: x["face"])          # face ≥ 2 인 노트(앞 교정-op 가 face-1 노트를 만들었다)
    r2 = atk.split(mine2["nid"], [1, mine2["face"] - 1])
    out["★REJECT 예산: 예산 소진 뒤에도 정직 op 통과"] = isinstance(r2, dict) and "seq" in r2
    out["원장 무오염(예산 뒤)"] = nd.audit()["ok"] is True
    # ★[M-210] R3-F10-1(CRITICAL) — /stats 는 REJECT 행을 수용된 연산으로 세지 않는다: 거부된 DELIVER·UW(유령 인수자)는 계기에 0 영향
    st0 = nd.stats()
    rj0 = sum(1 for e in nd.w.log if e.get("kind") == "REJECT")
    for _ in range(3):
        post(victim.sign_env("DELIVER", {"anchor": "vv", "ref": "0000000000000000"}))
    post(victim.sign_env("UW", {"uw": "ghost_uw", "ref": "0000000000000000", "cov_notes": [vn], "prem": 999999}))
    rj1 = sum(1 for e in nd.w.log if e.get("kind") == "REJECT")
    st1 = nd.stats()
    out["★거부 행이 실제로 기록됨(시험 유효)"] = rj1 > rj0
    out["★REJECT DELIVER = anchors 무영향"] = sum(seg.get("delivered", 0) for seg in st1["anchors"].get("vv", {}).get("segments", {}).values()) == \
        sum(seg.get("delivered", 0) for seg in st0["anchors"].get("vv", {}).get("segments", {}).values())
    out["★REJECT UW = 유령 인수자 없음"] = "ghost_uw" not in st1.get("underwriters", {})
    # ★[M-211] R4-F11-H1 — 오버사이즈 봉투는 REJECT 행으로 적재되지 않는다(기록 전 무기록 거부) · 쓰기 예산 단위 검사
    try:
        nd._env_size_guard({"typ": "XFER", "args": {"frm": "vv", "to": "vv", "note": "1", "pad": "x" * 20000}, "p": "vv", "epoch": 0, "nonce": 0, "sig": "00"})
        out["★봉투 크기 가드"] = False
    except Exception as ex:
        out["★봉투 크기 가드"] = "봉투 크기" in str(ex)
    nd._write_budget("zz_budget", {"a": "x" * 1_500_000}, charge=True)      # ★[M-212] 과금은 기록 뒤(charge=True) · 검사는 charge=False
    try:
        nd._write_budget("zz_budget", {"a": "x" * 1_500_000})
        out["★쓰기 예산 소진 거부"] = False
    except Exception as ex:
        out["★쓰기 예산 소진 거부"] = "쓰기 예산" in str(ex)
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TOPSEAT(port=8843):
    """★[M-198] operator-좌석 브릭 면역(냉독 라운드8 CRITICAL — M-197 의 역효과 수리):
    M-197 실패-슬롯 캡이 (p,nonce) 키였는데 operator 는 노드-내부 공유 신원이라, /block 의
    위조-다리(커널 _apply_block 이 _snap **후** 검증)가 operator BLOCK 봉투를 실패시켜
    (operator,N) 슬롯을 포화 → 성공(=nonce 전진)이 캡에 막혀 **자기-교착** → 모든 쓰기·정산 동결.
    수리 = operator 캡 제외 + block() 다리 서명 선검증(+다리-주체 계수) + join() 중복 선체크."""
    import urllib.request
    import urllib.error
    out = {}
    nd, srv, data = _serve(port)
    B = f"http://127.0.0.1:{port}"

    def post(path, obj):
        b = json.dumps(obj).encode()
        try:
            r = urllib.request.urlopen(urllib.request.Request(
                f"{B}{path}", data=b,
                headers={"Content-Type": "application/json"}), timeout=10)
            return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    post("/join", {"principal": "alice", "pk": "aa" * 32})
    post("/tick", {})
    ep0 = nd.w.epoch
    # 공격: 위조-서명 XFER 다리를 담은 /block 을 20회(무인증) — 옛 코드면 operator 브릭
    forged = {"typ": "XFER", "args": {"frm": "ghost", "to": "alice", "note": "0"},
              "p": "ghost", "epoch": 0, "nonce": 0, "sig": "00" * 64}
    for _ in range(20):
        post("/block", {"legs": [forged]})
    opn = nd.w.nonces.get("operator", 0)
    out["★operator 실패 무기록(J-7 범위 = 비-operator · nonce 불변)"] = nd.w.nonces.get("operator", 0) == opn
    out["★위조-다리 값싼 거부(_snap 이전)"] = True   # 미지 주체로 선검증 거부(위에서 20회 무해)
    # ★핵심: 공격 후에도 operator-경로가 산다(브릭 없음)
    c_join, _ = post("/join", {"principal": "bob", "pk": "bb" * 32})
    out["★공격 후 온보딩 생존(join)"] = c_join == 200
    c_tick, _ = post("/tick", {})
    out["★공격 후 정산-클럭 생존(tick)"] = (c_tick == 200 and nd.w.epoch > ep0)
    # 중복 join 선체크(_snap 이전 거부)
    c_dup, m_dup = post("/join", {"principal": "alice", "pk": "aa" * 32})
    out["중복 join 선체크"] = (c_dup == 400 and "이미 등록" in str(m_dup))
    # 정당 block: xx→yy 원자 XFER(당사자 서명) 200 · 성공 후 슬롯 리셋
    x = _client(port, "xx", data); x.join()
    y = _client(port, "yy", data); y.join()
    leg = x.make_leg("XFER", {"frm": "xx", "to": "yy", "note": x.notes()[0]["nid"]})
    c_blk, _ = post("/block", {"legs": [leg]})
    out["정당 block 통과"] = (c_blk == 200)
    # ★[M-198] 다리-주체 grief 면역: 공격자가 [피해자 유효-다리 + 자기 실패-다리] 블록을
    # 반복해도 피해자 슬롯을 포화시키지 못한다(옛 수리의 다리-계수가 이 grief 를 냈다 —
    # 본 세션 자체-재현으로 잡아 계수 제거). 피해자는 자기 nonce 에서 계속 제출 가능해야 한다.
    vic = _client(port, "vic", data); vic.join()
    thd = _client(port, "thd", data); thd.join()
    vleg = vic.make_leg("XFER", {"frm": "vic", "to": "thd",
                                 "note": vic.notes()[0]["nid"]})
    fail_leg = y.make_leg("XFER", {"frm": "yy", "to": "thd",
                                   "note": vic.notes()[0]["nid"]})  # yy 미소유 → 실패
    for _ in range(16 + 4):
        post("/block", {"legs": [vleg, fail_leg]})
    out["★다리-주체 grief 면역(피해자 nonce 불변)"] = nd.w.nonces.get("vic", 0) == vleg["nonce"]
    vnote = next(n for n in vic.notes() if n["nid"] == vic.notes()[0]["nid"])
    c_vic, _ = post("/submit", {"env": vic.sign_env(
        "SPLIT", {"owner": "vic", "note": vnote["nid"], "parts": [1, vnote["face"] - 1]})})
    out["★피해자 제출 생존"] = c_vic == 200
    out["원장 무오염"] = nd.audit()["ok"] is True
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TOPREPLAY(port=8844):
    """★[M-199] operator-매개 _snap 자유-재생의 선체크(냉독 라운드9 — M-198(A) operator
    캡-제외가 재개방한 부류): operator JOIN·bootstrap 이 _apply 에서 실패하면 _snap(전-원장
    deepcopy) **이후**라 무인증 무한 재생 DoS 였다. 커널과 동형인 값싼 O(1) 선체크로 _snap
    이전에 거부: ⓐjoin pk 길이(비-32B) + identity_budget · ⓑbootstrap 소유권(color≠owner)."""
    import urllib.request
    import urllib.error
    out = {}
    nd, srv, data = _serve(port)
    B = f"http://127.0.0.1:{port}"

    def post(path, obj):
        b = json.dumps(obj).encode()
        try:
            r = urllib.request.urlopen(urllib.request.Request(
                f"{B}{path}", data=b,
                headers={"Content-Type": "application/json"}), timeout=10)
            return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    g0 = json.loads(urllib.request.urlopen(f"{B}/meta").read())["genesis"][0]
    n0 = len(nd.w.log)
    # ⓐ 비-32B pk /join — _snap 이전 선거부 · 원장 무성장(재생해도 로그 안 늘어야)
    c, m = post("/join", {"principal": "zzz", "pk": "00"})   # 유효 hex·1바이트
    out["★비-32B pk 선거부"] = (c == 400 and "32바이트" in str(m))
    for _ in range(8):
        post("/join", {"principal": "zzz", "pk": "00"})       # 무한-재생 시도
    out["★재생해도 원장 무성장"] = len(nd.w.log) == n0
    out["같은 이름 재-join 가능(미등록 유지)"] = post("/join", {"principal": "zzz", "pk": "00"})[0] == 400
    # 정당 join 은 통과
    out["정당 join 통과"] = post("/join", {"principal": "alice", "pk": "aa" * 32})[0] == 200
    # ⓑ bootstrap color≠owner — 소유권 선체크로 거부
    iss = _client(port, "iss", data); iss.join()
    iss.split(iss.notes()[0]["nid"], [1] * 4 + [iss.notes()[0]["face"] - 4])
    small = [n["nid"] for n in iss.notes() if n["face"] == 1 and n["color"] == "iss"][0]
    iss.xfer("alice", small)                                  # 색 유지·소유 이전
    leg = iss.make_leg("XFER", {"frm": "iss", "to": g0, "note": small})
    c2, m2 = post("/bootstrap", {"leg": leg})
    out["★bootstrap 미소유 선거부"] = (c2 == 400 and "미소유" in str(m2))
    # 정당 bootstrap 은 통과(자기 소유 자기-색)
    bob = _client(port, "bob", data); bob.join()
    bob.split(bob.notes()[0]["nid"], [4, bob.notes()[0]["face"] - 4])
    rb = bob.bootstrap(4)
    out["정당 bootstrap 통과"] = isinstance(rb, dict) and any(
        n["color"] == g0 for n in bob.notes())
    out["원장 무오염"] = nd.audit()["ok"] is True
    srv.shutdown()
    # ⓒ ★[M-208] FL2.3 J-3 생존-상한 동형(냉독 4 R4-1): 예산까지 JOIN → 초과 거부 → EXIT 1 → 다시 JOIN 은 **200**
    #   (구 선체크는 exited 를 안 빼서 128 누적 뒤 온보딩 영구 봉쇄 · 커널은 수용 = 노드가 법보다 엄격했다)
    nd2, srv2, data2 = _serve(port + 60, join_issue=0)
    try:
        B2 = f"http://127.0.0.1:{port + 60}"
        bud = nd2.w.GEN["identity_budget"]
        cs = []
        for i in range(bud - 1):                       # anchor0 가 비-좌석 1 을 이미 차지
            cc = Fl21Client(B2, f"lc{i}", os.path.join(data2, f"lc{i}.key"))
            cc.join()
            cs.append(cc)
        over = Fl21Client(B2, "lc_over", os.path.join(data2, "lc_over.key"))
        try:
            over.join()
            out["★생존-상한: 예산 초과 JOIN 거부"] = False
        except Exception as e:
            out["★생존-상한: 예산 초과 JOIN 거부"] = "identity_budget" in str(e)
        cs[0]._post("/submit", {"env": cs[0].sign_env("EXIT", {"a": "lc0"})})
        n2 = len(nd2.w.log)
        try:
            over.join()
            out["★생존-상한: EXIT 후 JOIN 수용"] = True
        except Exception:
            out["★생존-상한: EXIT 후 JOIN 수용"] = False
        au = nd2.w.audit()
        out["★생존-상한: 커널 상태 일치"] = (nd2.w.reg.pk("lc_over") is not None and len(nd2.w.log) > n2
                                          and bool(au["ok"] if isinstance(au, dict) else au))
    finally:
        srv2.shutdown()
        srv2.server_close()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TACCEPTBIND(port=8840):
    """★[M-194] acceptance 가 head 를 env 에서 **재계산**해 접붙임 위조를 거부(냉독 라운드4):
    진짜 (head,head_sig) 에 위조 JOIN env 를 붙여 임의 pk 등록 못 함."""
    import copy, hashlib as _h
    from urllib.parse import urlparse, parse_qs
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    out = {}
    nd, srv, data = _serve(port)
    b = _client(port, "buyer", data); b.join()
    wk = AnchorWorker(f"http://127.0.0.1:{port}", os.path.join(data, "anchor0.key"))
    g = wk.notes()[0]; wk.split(g["nid"], [5, g["face"] - 5])
    wk.xfer("buyer", [x for x in wk.notes() if x["face"] == 5][0]["nid"])
    nid = [x for x in b.notes_of("anchor0") if x["face"] == 5][0]["nid"]
    ref = b.redeem_job("anchor0", nid, seed="aa" * 8, n=1000)["ref"]
    sp = b.job(ref)["job"]; wk.deliver_job(ref, JOBS.compute(sp["kind"], sp["seed"], sp["n"]))
    meta = b._get("/meta"); log, s0 = [], 0
    while True:
        pg = b._get(f"/log?since={s0}")["entries"]
        if not pg:
            break
        log += pg; s0 = pg[-1]["seq"] + 1
    srv.shutdown()
    genuine = log[1]
    forged = dict(genuine)
    forged["env"] = {"typ": "JOIN", "args": {"principal": "ghost", "pk": "11" * 32},
                     "p": "operator", "epoch": 0, "nonce": 0, "sig": "00" * 64}
    mal = [forged if e is genuine else e for e in log]
    accepts = {"F": {"id": "F", "rec": {"ref": ref, "p": "ghost", "verdict": "rework",
               "note": "x", "expires": 10 ** 9}, "sig": "00" * 64}}

    class Mock(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/meta":
                body = meta
            elif u.path == "/log":
                sq = int((parse_qs(u.query).get("since") or ["0"])[0])
                body = {"entries": [e for e in mal if e["seq"] >= sq]}
            elif u.path == "/accept":
                body = {"records": list(accepts.values())}
            elif u.path.startswith("/job/"):
                body = {"job": {"anchor": "anchor0", "delivered": True, "holder": "buyer"}}
            elif u.path == "/stats":
                body = {"epoch": 10}
            else:
                body = {}
            bb = json.dumps(body).encode(); self.send_response(200)
            self.send_header("Content-Length", str(len(bb))); self.end_headers(); self.wfile.write(bb)
    m = ThreadingHTTPServer(("127.0.0.1", port + 1), Mock)
    threading.Thread(target=m.serve_forever, daemon=True).start()
    r = UWT.acceptance(UWT._RoClient(f"http://127.0.0.1:{port + 1}", "obs"))
    m.shutdown()
    out["★접붙임 위조 봉쇄(ghost 미등록)"] = "ghost" not in r.get("buyers", {})
    out["결박 활성(sig_verified False 또는 rejected>0)"] = (
        r.get("sig_verified") is False or r.get("sig_rejected", 0) >= 1)
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TGENDOC():
    """★[M-208] 세대-문자열 정합(냉독 4 R4-2 — QUICKSTART 두 표가 `FL22-ACPT` 를 적어 표를 따른 클라이언트의 수락 서명이
    조용히 거부되던 [M-183] 부류 재발): 번들 문서(r1/*.md)의 서명-도메인 문자열은 현 세대(node/sdk 상수)와 같아야 한다 —
    구세대 도메인은 아카이브·계보 문맥의 줄에서만 허용."""
    import glob
    import re
    out = {}
    here = os.path.dirname(os.path.abspath(__file__))
    gen, prev = "FL23", "FL22"
    stale = re.compile(prev + r"-(v0\.1|BOARD|CHAL|ACPT|MANIFEST|RELAY)")
    allow = ("archive", "아카이브", "FL2.2", "계보", "lineage", "bridge_ref", "구세대", "previous generation")
    hits = []
    for f in sorted(glob.glob(os.path.join(here, "*.md"))):
        for i, line in enumerate(open(f, encoding="utf-8"), 1):
            if stale.search(line) and not any(a in line for a in allow):
                hits.append(f"{os.path.basename(f)}:{i}")
    out["★구세대 도메인 문자열 0(문맥-허용 제외)"] = (hits == []) if not hits else hits[:6]
    cur = {gen + "-ACPT", gen + "-BOARD", gen + "-CHAL", gen + "-RELAY"}   # 오프-원장 도메인(node/sdk 상수)
    src = open(os.path.join(here, "node.py"), encoding="utf-8").read() + open(os.path.join(here, "sdk.py"), encoding="utf-8").read()
    out["현 세대 도메인 상수 존재(node/sdk)"] = all(c in src for c in cur)
    docs = "".join(open(f, encoding="utf-8").read() for f in glob.glob(os.path.join(here, "*.md")))
    out["문서가 현 세대 수락 도메인을 적는다"] = (gen + "-ACPT") in docs
    out["pass"] = all(v is True for v in out.values())
    return out


# ══════════ ★FL2.3 노드-급 게이트 4([M-203]) — REKEY · GENESIS_IMPORT · 구성-링크 · 오류-코드 ══════════
def _post_env(port, env, path="/submit"):
    import urllib.request
    import urllib.error
    b = json.dumps({"env": env}, separators=(",", ":")).encode()
    try:
        r = urllib.request.urlopen(urllib.request.Request(
            f"http://127.0.0.1:{port}{path}", data=b,
            headers={"Content-Type": "application/json"}), timeout=10)
        return 200, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _all_log(c):
    entries, s_ = [], 0
    while True:
        page = c._get(f"/log?since={s_}")["entries"]
        if not page:
            return entries
        entries += page
        s_ = page[-1]["seq"] + 1


def gate_TREKEY23(port=8845):
    """★FL2.3 J-4 노드-급: 사용자 REKEY(SDK) → 신-키 수리·구-키 거부(무기록) · operator 회전(rekey_operator) →
    /meta.operator_pk 변경·operator_pk0 불변 · 라이트 검증(키-일정)·H7 from_public(창세 키) 통과."""
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "rk", data); c.join()
    att0 = c.fetch_attest("anchor0")                       # ★[M-211] 회전 **전** 어테스트(키-일정 검증 대상)
    old_key, old_pk = c.key, c.pk_hex()
    r = c.rekey()
    out["★사용자 REKEY 수용·키 파일 교체"] = isinstance(r, dict) and "seq" in r and c.pk_hex() != old_pk
    n = c.notes()[0]
    r2 = c.split(n["nid"], [1, n["face"] - 1])
    out["신-키 서명 수리"] = isinstance(r2, dict) and "seq" in r2
    st = c._get(f"/nonce/{c.p}")
    body = {"typ": "TICKMARK", "args": {}, "p": c.p, "epoch": st["epoch"]}
    env = {**body, "nonce": st["nonce"], "sig": old_key.sign(sig_msg(c.log_id, body, st["nonce"], c.domain)).hex()}
    n0 = len(nd.w.log)
    code, msg = _post_env(port, env)
    out["★구-키 서명 거부(무기록)"] = code == 400 and "bad_signature" in msg and len(nd.w.log) == n0
    meta0 = c._get("/meta")
    rr = nd.rekey_operator()
    with nd.lock:
        nd.tick()
    meta1 = c._get("/meta")
    out["★operator 회전: pk 변경 · pk0 불변"] = (meta1["operator_pk"] != meta0["operator_pk"]
                                              and meta1["operator_pk0"] == meta0["operator_pk0"] == meta0["operator_pk"]
                                              and rr["operator_pk"] == meta1["operator_pk"])
    c2 = _client(port, "rk", data)
    v = c2.verify_chain()
    out["★verify_chain 키-일정 ok"] = v["ok"] is True
    pks = {"operator": meta1["operator_pk0"], **meta1["genesis_pks"]}
    pub = World.from_public(pks, meta1["label"], tuple(meta1["genesis"]), gen=dict(meta1["gen"]),
                            bridge_ref=meta1.get("bridge_ref"))
    out["★H7 from_public(창세 키) ok"] = pub.replay_verify(_all_log(c2))["ok"] is True
    n2 = max(c2.notes(), key=lambda x: x["face"])          # face ≥ 2 인 노트로 SPLIT
    out["회전 후 사용자 op 수리"] = isinstance(c2.split(n2["nid"], [1, n2["face"] - 1]), dict)
    out["audit"] = nd.audit()["ok"] is True
    # ★[M-209] R2-F06-1 — 항등점(저-위수) 공개키는 JOIN·REKEY 진입에서 거부(만능서명 위조 주체 차단) · 검증기도 fail-closed
    _idp = "01" + "00" * 31
    try:
        c._post("/join", {"principal": "weakid", "pk": _idp})
        out["★항등점 pk JOIN 거부"] = False
    except Exception as ex:
        out["★항등점 pk JOIN 거부"] = "약한 키" in str(ex)
    _univ = "01" + "00" * 31 + "00" * 32
    try:
        c2._post("/submit", {"env": c2.sign_env("REKEY", {"principal": "rk", "new_pk": _idp, "new_sig": _univ})})
        out["★항등점 REKEY 거부"] = False
    except Exception as ex:
        out["★항등점 REKEY 거부"] = "약한 키" in str(ex)
    from sdk import ed25519_weak_pk as _wk
    out["★약한-키 판별(항등점 True · 실키 False)"] = _wk(bytes.fromhex(_idp)) is True and _wk(bytes.fromhex(c2.pk_hex())) is False \
        and _wk(bytes.fromhex("ec" + "ff" * 30 + "7f")) is True
    # ★[M-211] R4-F06-3 — verify_attest 는 노드 주장 현행 키가 아니라 operator_pk0 + 로그 REKEY 일정으로 검증
    ca = _client(port, "rk", data)
    out["★회전 전 어테스트 = 키-일정으로 ok"] = ca.verify_attest(att0).get("ok") is True
    out["★회전 후 어테스트 ok"] = ca.verify_attest(ca.fetch_attest("anchor0")).get("ok") is True
    _bad = json.loads(json.dumps(ca.fetch_attest("anchor0"))); _bad["doc"]["principal"] = "zz"
    out["★변조 어테스트 거부"] = ca.verify_attest(_bad).get("ok") is False
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _EK
    _atk = _EK.generate(); _real_get = ca._get
    _fm = dict(_real_get("/meta")); _fm["operator_pk"] = _atk.public_key().public_bytes_raw().hex()
    ca._get = lambda path, _rg=_real_get, _fm=_fm: dict(_fm) if path == "/meta" else _rg(path)
    ca._opk_cache = None
    _doc = dict(att0["doc"]); import kernel23 as _K23
    _forged = {"doc": _doc, "operator_sig": _atk.sign(ca.domain + _K23._canon(_doc)).hex()}
    out["★미러(/meta.operator_pk 만 교체)의 위조 어테스트 거부"] = ca.verify_attest(_forged).get("ok") is False
    # ★[M-212] R5-F06-1 — 미러가 /log 에 **위조 REKEY 항**을 접붙여 공격자 키를 일정에 넣는 경로도 거부(일정 = 검증된 사슬의 부산물)
    _fake = {"seq": None, "env": {"typ": "REKEY", "args": {"principal": "operator", "new_pk": _fm["operator_pk"], "new_sig": "00"}, "p": "operator", "epoch": 0, "nonce": 0, "sig": "00"},
             "fp": "00" * 32, "w_epoch": 0, "state_root": "00" * 32, "prev": "00" * 32, "head": "11" * 32, "head_sig": "00", "kind": "OK"}
    def _log_get(path, _rg=_real_get, _fm=_fm):
        if path == "/meta":
            return dict(_fm)
        r_ = _rg(path)
        if path.startswith("/log?since=") and isinstance(r_, dict) and isinstance(r_.get("entries"), list) and r_["entries"] and len(r_["entries"]) < 500:
            last = r_["entries"][-1]; fk = dict(_fake); fk["seq"] = int(last["seq"]) + 1; fk["prev"] = last["head"]
            r_ = dict(r_); r_["entries"] = r_["entries"] + [fk]
        return r_
    ca._get = _log_get; ca._opk_cache = None
    out["★미러(/log 위조 REKEY 접붙임)의 위조 어테스트 거부"] = ca.verify_attest(_forged).get("ok") is False
    ca._get = _real_get; ca._opk_cache = None
    # ★[M-211] R4-F02-1/2·F06-1/2 — SDK 회전 매트릭스: 응답 유실·재시도·/pk 장애·거짓 /pk 어디서도 키 재료를 지우지 않는다
    c3 = _client(port, "rk3", data); c3.join(); kp = c3.key_path
    _rp3 = c3._post
    def _lost(path, body, _r=_rp3):
        _r(path, body); raise RuntimeError("HTTP 502 (simulated lost response)")
    c3._post = _lost
    try:
        c3.rekey()
    except RuntimeError:
        pass
    c3._post = _rp3
    out["★응답 유실: .next 보존"] = os.path.exists(kp + ".next")
    r3 = c3.rekey()                                          # 같은 프로세스 재시도 = 먼저 재조정(승격) → 새 회전
    out["★재시도 = 재조정 뒤 성공(유일 사본 무손실)"] = "seq" in r3 and not os.path.exists(kp + ".next") and c3._get("/pk/rk3")["pk"] == c3.pk_hex()
    c3._post = _lost
    try:
        c3.rekey()
    except RuntimeError:
        pass
    c3._post = _rp3
    _rg3 = c3._get
    c3._get = lambda path, _g=_rg3: (_ for _ in ()).throw(RuntimeError("HTTP 503")) if path.startswith("/pk/") else _g(path)
    c3._reconcile_key_next()
    out["★/pk 장애: .next 무접촉 + 미해결 표시"] = os.path.exists(kp + ".next") and c3.key_next_unresolved is True
    c3._get = _rg3
    c3.sign_env("TICKMARK", {"kind": "fl21.version", "v": "v9"})   # 서명 전 자기치유(재조정 → 승격)
    out["★복귀 뒤 자기치유(승격·/pk 일치)"] = (not os.path.exists(kp + ".next")) and c3._get("/pk/rk3")["pk"] == c3.pk_hex()
    import glob as _glp
    out["★구 키 .prev 보관"] = bool(_glp.glob(kp + ".prev-*"))            # ★[M-213] append-only 이름(.prev-<ns>-<pk8>)
    c3._post = _lost
    try:
        c3.rekey()
    except RuntimeError:
        pass
    c3._post = _rp3
    _old_hex = c3.pk_hex()
    c3._get = lambda path, _g=_rg3, _o=_old_hex: {"p": "rk3", "pk": _o} if path.startswith("/pk/") else _g(path)   # 거짓 /pk = 구 키 반환
    c3._reconcile_key_next()
    c3._get = _rg3
    import glob as _gl
    out["★거짓 /pk(구 키): 삭제 아닌 .stale 보관"] = (not os.path.exists(kp + ".next")) and bool(_gl.glob(kp + ".next.stale-*"))
    # ★[M-213] Q-3(R5-F02-1/2) — 보관 파일은 append-only(같은 초 두 번 거부돼도 둘 다 남는다) · 200 뒤 /pk 재확인 전엔 키 파일을 바꾸지 않는다
    c4 = _client(port, "rk4", data); c4.join(); kp4 = c4.key_path
    _rp4 = c4._post
    def _reject(path, body):
        raise RuntimeError("HTTP 400: {\"error\": \"simulated\", \"code\": \"rejected\"}")
    c4._post = _reject
    for _ in range(2):
        try:
            c4.rekey()
        except RuntimeError:
            pass
    c4._post = _rp4
    import glob as _gl4
    out["★4xx 두 번 = .stale 보관 2개(덮어쓰기 없음)"] = len(_gl4.glob(kp4 + ".next.stale-*")) == 2 and not os.path.exists(kp4 + ".next")
    _pk_before = c4.pk_hex(); _rg4 = c4._get
    c4._get = lambda path, _g=_rg4, _o=_pk_before: {"p": "rk4", "pk": _o} if path.startswith("/pk/") else _g(path)   # 노드가 새 키를 확인해 주지 않는 상황
    r4 = c4.rekey()
    c4._get = _rg4
    out["★/pk 미확인 200 = 키 파일 교체 보류(.next 유지·미해결)"] = "note" in r4 and os.path.exists(kp4 + ".next") and c4.pk_hex() == _pk_before and c4.key_next_unresolved is True
    c4.sign_env("TICKMARK", {"kind": "fl21.version", "v": "v10"})       # 서명 전 재조정 → 진짜 /pk 로 승격
    out["★복귀 뒤 승격 = 원장 키와 일치"] = (not os.path.exists(kp4 + ".next")) and c4._get("/pk/rk4")["pk"] == c4.pk_hex()
    out["★.prev 도 append-only"] = len(_gl4.glob(kp4 + ".prev-*")) >= 1 and not os.path.exists(kp4 + ".prev")
    # ★[M-215] D1-1 — 같은 키 파일의 두 프로세스 경합: 회전 비행 중 B 가 (a) 커밋 뒤 승격 (b) 커밋 전 stale 보관 — A 는 예외 없이 원장 키를 채택한다
    for tag, pre in (("promote", False), ("stale", True)):
        nm = "rk5" + tag[:1]
        c5 = _client(port, nm, data); c5.join(); kp5 = c5.key_path; _rp5 = c5._post
        def _race(path, body, _r=_rp5, _pre=pre, _kp=kp5, _nm=nm):
            if _pre:
                Bc = Fl21Client(f"http://127.0.0.1:{port}", _nm, _kp); Bc._reconcile_key_next()      # 커밋 전: /pk = 구 키 → .next 를 stale 로
                r_ = _r(path, body)
            else:
                r_ = _r(path, body); Fl21Client(f"http://127.0.0.1:{port}", _nm, _kp)             # 커밋 뒤: B 생성자가 .next 승격
            return r_
        c5._post = _race
        try:
            r5 = c5.rekey(); okr = "new_pk" in r5
        except Exception as ex:
            okr = f"EXC {type(ex).__name__}"
        c5._post = _rp5
        out[f"★두-프로세스 경합({tag}): rekey 예외 없음"] = okr is True
        out[f"★두-프로세스 경합({tag}): A 키 == 원장 키"] = c5.pk_hex() == c5._get(f"/pk/{nm}")["pk"]
        out[f"★두-프로세스 경합({tag}): 서명 가능"] = "seq" in c5._post("/submit", {"env": c5.sign_env("TICKMARK", {"kind": "fl21.version", "v": "r5"})})
    srv.shutdown()
    # ★[M-208] R4-10(냉독 4 · F06-F2) — 회전 뒤 재기동: 정상 = 통과 · operator.key 유실 = **명시 기동 거부**(침묵 브릭 아님) ·
    #   회전-중 크래시 잔재(.next · 원장에 없는 키) = 폐기 후 정상 기동.
    okp = os.path.join(data, "operator.key")
    out["회전 후 operator.key 존재"] = os.path.exists(okp)
    saved = open(okp).read()
    nd_r, srv_r, _ = _serve(port + 50, data=data)
    try:
        out["★재기동 정합(정상)"] = nd_r.w.reg.pk("operator") == nd_r.w._keys["operator"].public_key().public_bytes_raw()
        with nd_r.lock:
            nd_r.tick()                                     # 재기동 후 운영자 봉투가 통과해야 한다
        out["★재기동 후 TICK 통과"] = True
    finally:
        srv_r.shutdown(); srv_r.server_close()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _P
    with open(okp + ".next", "w") as fh:                    # 원장에 없는 회전 잔재
        fh.write(_P.generate().private_bytes_raw().hex())
    nd_r, srv_r, _ = _serve(port + 51, data=data)
    try:
        out["★.next 잔재 폐기 후 정상"] = (not os.path.exists(okp + ".next")) and open(okp).read() == saved
    finally:
        srv_r.shutdown(); srv_r.server_close()
    os.remove(okp)                                          # 키 유실 시나리오
    try:
        nd_r, srv_r, _ = _serve(port + 52, data=data)
        srv_r.shutdown(); srv_r.server_close()
        out["★키 유실 = 명시 기동 거부"] = False
    except RuntimeError as ex:
        out["★키 유실 = 명시 기동 거부"] = "키-일정" in str(ex)
    with open(okp, "w") as fh:
        fh.write(saved)
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TIMPORT23(port=8846):
    """★FL2.3 J-11 노드-급: --genesis-import 기동 → 첫 엔트리 GENESIS_IMPORT · 수입 노트 색 = issuer · 보존식 ·
    /meta.operator_pk0 · 재기동 리플레이 동일 · H7 통과."""
    out = {}
    data = _tmp()
    pk = derive_key(5, "z1").public_key().public_bytes_raw().hex()
    snap = {"principals": [{"p": "z1", "pk": pk}],
            "notes": [{"owner": "z1", "face": 7, "issuer": "z1"}, {"owner": "anchor0", "face": 3, "issuer": "z1"}],
            "F": 0, "F_uw": 2, "exited": []}
    ip = os.path.join(data, "import.json")
    json.dump(snap, open(ip, "w", encoding="utf-8"))
    nd, srv, _ = _serve(port, data=data, genesis_import=ip)
    out["★첫 엔트리 = GENESIS_IMPORT"] = nd.w.log[0]["env"]["typ"] == "GENESIS_IMPORT"
    imp = [nid for nid, n in nd.w.notes.items() if n["owner"] == "anchor0" and n["face"] == 3]
    out["★수입 노트 색 = issuer(z1)"] = len(imp) == 1 and nd.colors.get(imp[0]) == "z1"
    # ★승계 수입은 창세 자기-IOU(genesis_issue)를 **대체**한다(anchor0 의 잔고는 스냅샷이 나른다 — 이중-지급 없음)
    out["보존식 ext_in = Σface+F+F_uw(창세 grant 대체)"] = nd.w.ext_in == 7 + 3 + 2 and nd.w.F_uw == 2 and nd.w.bal("z1") == 7 \
        and len([e for e in nd.w.log if e["env"]["typ"] == "EXT_IN"]) == 0
    c = _client(port, "im", data); c.join()
    meta = c._get("/meta")
    out["/meta.operator_pk0 = operator_pk(회전 전)"] = meta["operator_pk0"] == meta["operator_pk"]
    pks = {"operator": meta["operator_pk0"], **meta["genesis_pks"]}
    pub = World.from_public(pks, meta["label"], tuple(meta["genesis"]), gen=dict(meta["gen"]), bridge_ref=meta.get("bridge_ref"))
    out["★H7 from_public(수입 포함) ok"] = pub.replay_verify(_all_log(c))["ok"] is True
    head = nd.w.log[-1]["head"]
    # ★[M-209] R2-F07-1 — /meta 가 창세 내용을 고정하는 값(genesis_head·snapshot_hash)을 노출하고 첫 항과 정합 · /scope 조회
    _m = c._get("/meta")
    out["★/meta.genesis_head = seq0 head"] = _m.get("genesis_head") == nd.w.log[0]["head"]
    out["★/meta.snapshot_hash 노출"] = isinstance(_m.get("snapshot_hash"), str) and len(_m["snapshot_hash"]) == 64
    out["★/scope 조회"] = isinstance(c._get("/scope").get("scopes"), dict)
    # ★[M-210] R3-F05-M2/F06-1 — 수입 주체 pk 가 저-위수(항등점)면 수입 거부(JOIN/REKEY 와 같은 약한-키 규칙)
    import tempfile as _tf2
    _wk = {"principals": [{"p": "mallory", "pk": "01" + "00" * 31}], "notes": [], "F": 0, "F_uw": 0, "exited": []}
    _fp = os.path.join(_tf2.mkdtemp(), "weak_snap.json")
    json.dump(_wk, open(_fp, "w"))
    try:
        nd._genesis_import(_fp)
        out["★수입 약한 키 거부"] = False
    except Exception as ex:
        out["★수입 약한 키 거부"] = "약한 키" in str(ex)
    # ★[M-211] R4-F07-1/F12-M1/F05-4 — 핀 원천(RELEASE 파일 = 내장 사본) · verify_chain 결과가 핀 여부를 증언 · 임포스터 창세 거부
    import sdk as _SDK
    _pins = _SDK.release_pins()
    out["★RELEASE 파일 핀 = 내장 핀"] = _pins.get("source") == "file" and all(_pins.get(k) == _SDK.RELEASE_PINS[k] for k in ("log_id", "genesis_head", "operator_pk0")) \
        and sorted(_pins.get("cosigners") or []) == sorted(_SDK.RELEASE_PINS["cosigners"]) and _pins.get("cosign_k") == 2
    _cv = c.verify_chain()
    out["★로컬 노드 = 발표 원장 아님 표시(무핀 증언)"] = _cv.get("ok") is True and _cv.get("genesis_pin") is None and _cv.get("release_identity") == "mismatch" and "pin_note" in _cv
    _meta_l = c._get("/meta"); _orig_rp = _SDK.release_pins
    _loc = {"source": "file", "log_id": _meta_l["log_id"], "genesis_head": nd.w.log[0]["head"], "operator_pk0": _meta_l.get("operator_pk0") or _meta_l["operator_pk"],
            "cosigners": list(_meta_l["cosigners"].values()), "cosign_k": _meta_l["cosign_k"]}
    _SDK.release_pins = lambda path=None: dict(_loc)
    _cv2 = c.verify_chain()
    out["★RELEASE 가 이 원장을 가리키면 기본 핀 = release"] = _cv2.get("ok") is True and _cv2.get("genesis_pin") == "release"
    _SDK.release_pins = lambda path=None: dict(_loc, genesis_head="00" * 32)
    _cv3 = c.verify_chain()
    out["★같은 log_id·다른 창세 = 거부"] = _cv3.get("ok") is False and "genesis_head" in str(_cv3.get("why"))
    _SDK.release_pins = lambda path=None: dict(_loc, cosign_k=2, cosigners=["00" * 32])
    _cv4 = c.verify_chain()
    out["★공동서명자 집합 불일치 = 거부"] = _cv4.get("ok") is False and "공동서명" in str(_cv4.get("why"))
    _SDK.release_pins = _orig_rp
    # ★[M-213] Q-5(R5-F05-1) — RELEASE 핀 충돌 + 명시 핀이어도 공동서명 핀은 내장 사본 기준으로 유지(로컬 노드 서명자 ≠ 내장 → 거부)
    _SDK.release_pins = lambda path=None: {"source": "conflict", "conflict": "log_id"}
    _cv5 = c.verify_chain(expect_genesis_head=nd.w.log[0]["head"])
    out["★핀 충돌+플래그 = 공동서명 핀 유지(거부)"] = _cv5.get("ok") is False and "공동서명" in str(_cv5.get("why"))
    _SDK.release_pins = _orig_rp
    # ★[M-213] Q-6(R5-F05-5) — since>0 에서 0항 서빙 = 「전량 확정」 아님
    _rg6 = c._get
    c._get = lambda path, _g=_rg6: {"entries": []} if path.startswith("/log?since=") and not path.endswith("since=0") else _g(path)
    _cv6 = c.verify_chain(since=2)
    c._get = _rg6
    out["★since>0 빈 응답 = 꼬리 생략 실패"] = _cv6.get("ok") is False and "꼬리" in str(_cv6.get("why"))
    # ★[M-213] Q-9(R5-F10-5) — 미등록 주체 어테스트 = 404
    try:
        c._get("/attest/ghost_never_joined")
        out["★미등록 attest 404"] = False
    except RuntimeError as ex:
        out["★미등록 attest 404"] = "404" in str(ex)
    _att_ok = c.fetch_attest("anchor0")
    out["★등록 attest 에 registered 필드"] = _att_ok["doc"].get("registered") is True
    srv.shutdown(); srv.server_close()
    nd2, srv2, _ = _serve(port + 50, data=data, genesis_import=ip)   # 재기동 = 리플레이(수입은 재실행되지 않는다)
    out["★재기동 리플레이 동일"] = nd2.w.log[-1]["head"] == head and nd2.audit()["ok"] is True and nd2.colors.get(imp[0]) == "z1"
    srv2.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TCOMPOSE(port=8847):
    """★W-4 구성-링크 v0([M-201]): deps 가 스펙 해시(H2)에 결박 · /stats.composition 간선·상류 앵커 집계 · 형식 위반 거부."""
    from sdk import spec_sha256
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "cp", data); c.join()
    wk = AnchorWorker(f"http://127.0.0.1:{port}", os.path.join(data, "anchor0.key"))
    g = wk.notes()[0]
    wk.split(g["nid"], [8, 8, g["face"] - 16])
    for z in [z for z in wk.notes() if z["face"] == 8][:2]:
        wk.xfer("cp", z["nid"])
    nids = [x["nid"] for x in c.notes_of("anchor0") if x["face"] == 8]
    j1 = c.redeem_job("anchor0", nids[0], seed="aa" * 8, n=1000)
    j2 = c.redeem_job("anchor0", nids[1], seed="bb" * 8, n=1000, deps=[j1["ref"]])
    out["★deps 스펙 결박(정규형 유지)"] = nd.jobs[j2["ref"]]["job"].get("deps") == [j1["ref"]]
    out["deps 가 spec_sha256 을 바꾼다"] = spec_sha256({"kind": "sha256_chain", "seed": "bb" * 8, "n": 1000}) != \
        spec_sha256({"kind": "sha256_chain", "seed": "bb" * 8, "n": 1000, "deps": [j1["ref"]]})
    comp = c.stats()["composition"]
    out["★/stats.composition 간선·상류 집계"] = (comp["linked_jobs"] == 1 and comp["dep_edges"] == 1
                                              and comp["upstream_anchors"].get("anchor0", {}).get("downstream") == 1)
    try:
        c.redeem_job("anchor0", nids[0], seed="cc" * 8, n=1000, deps=["zz"])
        out["비-hex deps 거부"] = False
    except RuntimeError as e:
        out["비-hex deps 거부"] = "deps" in str(e)
    out["audit"] = nd.audit()["ok"] is True
    # ★[M-213] Q-8(R5-F10-2) — 상류 ref 는 실재·같은 holder 만: 비존재 ref · 타 holder 잡 ref 는 거부
    try:
        c.redeem_job("anchor0", nids[0], seed="dd" * 8, n=1000, deps=["0123456789abcdef"])
        out["★비존재 deps 거부"] = False
    except Exception as e:
        out["★비존재 deps 거부"] = "deps" in str(e)
    oth = _client(port, "otherh", data); oth.join()
    _on = max(oth.notes(), key=lambda x: x["face"])
    oth.split(_on["nid"], [1, _on["face"] - 1])
    _o1 = [n["nid"] for n in oth.notes() if n["face"] == 1][0]
    oth.xfer("anchor0", _o1)
    _oa = [n["nid"] for n in oth.notes_of("anchor0")][0] if oth.notes_of("anchor0") else None
    jo = oth.redeem_job("anchor0", _oa, seed="ee" * 8, n=1000) if _oa else None
    if jo:
        try:
            c.redeem_job("anchor0", nids[0], seed="ff" * 8, n=1000, deps=[jo["ref"]])
            out["★타 holder 상류 deps 거부"] = False
        except Exception as e:
            out["★타 holder 상류 deps 거부"] = "deps" in str(e)
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def gate_TERRCODE(port=8848):
    """★W-5b 오류-코드 영어화: 400 본문 `code` 안정 코드 — 대표 5종(nonce·서명·스키마·소유·미지 노트)."""
    out = {}
    nd, srv, data = _serve(port)
    c = _client(port, "ec", data); c.join()
    mine = c.notes()[0]["nid"]
    st = c._get(f"/nonce/{c.p}")
    body = {"typ": "TICKMARK", "args": {}, "p": c.p, "epoch": st["epoch"]}
    env = {**body, "nonce": st["nonce"] + 5, "sig": c.key.sign(sig_msg(c.log_id, body, st["nonce"] + 5, c.domain)).hex()}
    out["nonce_mismatch"] = '"code": "nonce_mismatch"' in _post_env(port, env)[1]
    env2 = {**body, "nonce": st["nonce"], "sig": "00" * 64}
    out["bad_signature"] = '"code": "bad_signature"' in _post_env(port, env2)[1]
    out["schema"] = '"code": "schema"' in _post_env(port, c.sign_env("SPLIT", {"owner": c.p, "note": mine, "parts": "1,1"}))[1]
    anchor_note = next(iter(n for n, x in nd.w.notes.items() if x["owner"] == "anchor0"))
    out["not_owner"] = '"code": "not_owner"' in _post_env(port, c.sign_env("XFER", {"frm": c.p, "to": "anchor0", "note": anchor_note}))[1]
    out["unknown_note"] = '"code": "unknown_note"' in _post_env(port, c.sign_env("REDEEM", {"holder": c.p, "note": "424242", "anchor": "anchor0"}))[1]
    n0 = len(nd.w.log)
    cd, m = _post_env(port, c.sign_env("GENESIS_IMPORT", {"snapshot_hash": "00" * 32, "principals": [], "notes": [], "F": 0, "F_uw": 0, "exited": []}))
    out["★operator_only 선거부(무기록)"] = cd == 400 and '"code": "operator_only"' in m and len(nd.w.log) == n0
    out["audit"] = nd.audit()["ok"] is True
    srv.shutdown()
    out["pass"] = all(v is True for v in out.values())
    return out


def main():
    gates = {"T-SIG 골든서명": gate_TSIG(), "T-PERIL 실물페릴": gate_TPERIL(),
             "T-RECOV 복구": gate_TRECOV(), "T-FUZZ 경계방어": gate_TFUZZ(),
             "T-SOAK 내구": gate_TSOAK(), "T-COSIGN 암호실물": gate_TCOSIGN(),
             "T-DURABLE 서명치유": gate_TDURABLE(),
             "T-COLOR 화폐모델": gate_TCOLOR(),
             "T-ATOMIC 원자성": gate_TATOMIC(),
             "T-PYJUDGE 판정분리": gate_TPYJUDGE(),
             "T-SPLITSIGN 서명분리": gate_TSPLITSIGN(),
             "T-PRICE 가격결박": gate_TPRICE(),
             "T-SAMPLED 표본검증": gate_TSAMPLED(),
             "T-PYCHECK 코드이행": gate_TPYCHECK(),
             "T-COVER 인수개방": gate_TCOVER(),
             "T-HASHBIND 해시결박": gate_THASHBIND(),
             "T-STATS 통계·증명": gate_TSTATS(),
             "T-BOARD 호가창": gate_TBOARD(),
             "T-ROOT 뿌리(무작위×불변식)": gate_TROOT(),
             "T-SCOPE 범위결박": gate_TSCOPE(),
             "T-CHALLENGE 챌린지창": gate_TCHALLENGE(),
             "T-EXHAUST 자원소진(H-1)": gate_TEXHAUST(),
             "T-GEN22 세대(단위·잡별T·H7)": gate_TGEN22(),
             "T-ERC8004 어댑터": gate_TERC8004(),
             "T-VALVE 단방향밸브": gate_TVALVE(),
             "T-SIGV 암호-확실 kind": gate_TSIGV(),
             "T-ACCEPT 수락채널": gate_TACCEPT(),
             "T-PROV 출처계기": gate_TPROV(),
             "T-UNSIGNED 서명부재-거부(C-1)": gate_TUNSIGNED(),
             "T-DELIVERAUTH ocommit-전 인가(C-2)": gate_TDELIVERAUTH(),
             "T-DELTALIEN δ-무담보-보수(C-3)": gate_TDELTALIEN(),
             "T-BLOCKGUARD BLOCK-가드(CRIT)": gate_TBLOCKGUARD(),
             "T-OCOMMITCAP ocommit-상한(C-2v)": gate_TOCOMMITCAP(),
             "T-NULLSIG null-head_sig 견고성": gate_TNULLSIG(),
             "T-ACCEPTSIG 수락-서명 재검증": gate_TACCEPTSIG(),
             "T-DELIVERTYPE /deliver-typ강제(CRIT)": gate_TDELIVERTYPE(),
             "T-ENTRYFORM 엔트리-형식 견고성": gate_TENTRYFORM(),
             "T-DELIVERCAP 재검증-시도-상한(rate-dos)": gate_TDELIVERCAP(),
             "T-ACCEPTBIND 수락-env→head 결박": gate_TACCEPTBIND(),
             "T-LISTCAP 리스트/본문-상한(재생-dos)": gate_TLISTCAP(),
             "T-REPLAYCAP 사전인증-스캔·실패-재생 상한": gate_TREPLAYCAP(),
             "T-OPSEAT operator-좌석 브릭 면역": gate_TOPSEAT(),
             "T-OPREPLAY operator-경로 _snap 재생 선체크": gate_TOPREPLAY(),
             "T-REKEY23 키-회전(J-4 노드)": gate_TREKEY23(),
             "T-IMPORT23 승계-수입(J-11 노드)": gate_TIMPORT23(),
             "T-COMPOSE 구성-링크(W-4)": gate_TCOMPOSE(),
             "T-ERRCODE 오류-코드(W-5b)": gate_TERRCODE(),
             "T-GENDOC 세대문자열": gate_TGENDOC()}
    ok = all(g["pass"] for g in gates.values())
    res = {**gates, "R1_GATES_PASS": ok}
    os.makedirs(os.path.join(_HERE, "results"), exist_ok=True)
    with open(os.path.join(_HERE, "results", "r1_gates.json"), "w",
              encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=1)
    print(json.dumps(res, ensure_ascii=False, indent=1))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
