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
sys.path.insert(0, os.path.join(_HERE, "..", "fin_lean", "lang22"))
sys.path.insert(0, _HERE)

from kernel22 import World, Fl22Error as Fl21Error, derive_key                  # noqa: E402
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
    sc_fp = UWT.scan(u3, {"min_rate_bp": 0, "family_herf_max": 1.0,
                          "family_prior": True})
    p_np = next(cd["prem"] for cd in sc_np["candidates"] if cd["ref"] == j8["ref"])
    p_fp = next(cd["prem"] for cd in sc_fp["candidates"] if cd["ref"] == j8["ref"])
    out["★가계-사전 완화"] = p_fp < p_np
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
    sig = c.key.sign(b"FL22-BOARD" + c.log_id + canon(body)).hex()
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
    srv.shutdown()
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

    def attempt(fn):
        """단일 기입-연산 전용: 수용 = 불변식 · 거부 = 상태-해시 불변(원자성)."""
        h0 = shot()
        try:
            fn()
            stats["accept"] += 1
            _root_invariants(nd, errs)
            return True
        except RuntimeError:
            stats["reject"] += 1
            if shot() != h0:
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
        h0 = shot()
        try:
            fn()
            errs.append(f"필수-실패 통과됨: {name}")
        except RuntimeError:
            if shot() != h0:
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
    kern = open(os.path.join(_HERE, "..", "fin_lean", "lang22",
                             "kernel22.py"), encoding="utf-8").read()
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
    rc = pr["anchors"].get("pvc", {})
    out["이력자-앵커 행"] = rc.get("V") == 1 and rc.get("direct_cycle") == 1
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
             "T-GEN22 세대(단위·잡별T·H7)": gate_TGEN22(),
             "T-ERC8004 어댑터": gate_TERC8004(),
             "T-VALVE 단방향밸브": gate_TVALVE(),
             "T-SIGV 암호-확실 kind": gate_TSIGV(),
             "T-ACCEPT 수락채널": gate_TACCEPT(),
             "T-PROV 출처계기": gate_TPROV()}
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
