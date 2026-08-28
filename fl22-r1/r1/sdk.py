#!/usr/bin/env python3
"""sdk.py — FL2.2 R1 클라이언트 SDK ([M-95] · E-2 · A-2/A-6).

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
import os
import urllib.request

_CKPT = 50_000                       # 표본-검증 클래스의 체크포인트 간격(노드와 동일)

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.exceptions import InvalidSignature

DOMAIN = b"FL22-v0.1" + b"\x00" * 7          # 커널 FL22_DOMAIN과 동일(골든 결박)
BOARD_DOMAIN = b"FL22-BOARD"                 # ★호가 창(오프-원장) — 원장 봉투와 도메인 분리
RELAY_DOMAIN = b"FL22-RELAY"                 # ★[M-162] leg-릴레이(서명 사서함)
# ★[M-144] 명시 User-Agent: ⓐ기계 클라이언트의 정직한 자기-식별(트래픽이 로그에서
# 읽힌다) ⓑ★실전 필수 — 기본값 `Python-urllib/*`는 CDN·WAF의 봇 차단에 걸린다(실측:
# node.vlue.ai 이관 직후 SDK만 403 error 1010 · curl·브라우저는 200). 에이전트 경제의
# 정문이 「기계라서」 닫히면 K5′는 수요 0을 거짓 기록한다.
USER_AGENT = "vlue-sdk/0.1 (+https://vlue.ai)"


def canon(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode()


def sig_msg(log_id: bytes, body: dict, nonce: int) -> bytes:
    return DOMAIN + log_id + canon(body) + int(nonce).to_bytes(8, "big")


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
    if k == "pycheck":
        return {"kind": "pycheck", "test_b64": job["test_b64"]}
    spec = {"kind": "pyjudge", "checker_b64": job["checker_b64"]}
    if job.get("input_b64"):
        spec["input_b64"] = job["input_b64"]
    return spec


def spec_sha256(job: dict) -> str:
    """REDEEM에 결박할 명세 해시 = sha256(canon(정규형 스펙))."""
    return hashlib.sha256(canon(spec_norm(job))).hexdigest()


def output_sha256(output) -> str:
    """DELIVER에 결박할 산출 해시 = sha256(canon(output)) — 문자열·객체 형 공통."""
    return hashlib.sha256(canon(output)).hexdigest()


def _co_ok(co_pks, name, sig_hex, head_hex):
    try:
        co_pks[name].verify(bytes.fromhex(sig_hex),
                            DOMAIN + bytes.fromhex(head_hex))
        return True
    except (KeyError, InvalidSignature, ValueError):
        return False


class Fl21Client:
    """외부 참여자 클라이언트 — 키 자율 보관·서명·제출·라이트 검증."""

    def __init__(self, base_url, principal, key_path):
        self.url = base_url.rstrip("/")
        self.p = principal
        self.key_path = key_path
        self.key = self._ensure_key()
        self.meta = self._get("/meta")
        self.log_id = bytes.fromhex(self.meta["log_id"])

    # ── 키(클라이언트 보관 — 노드에 비밀이 가지 않는다) ──
    def _ensure_key(self):
        if os.path.exists(self.key_path):
            raw = bytes.fromhex(open(self.key_path).read().strip())
            return Ed25519PrivateKey.from_private_bytes(raw)
        k = Ed25519PrivateKey.generate()
        # ★비밀 원자-권한 생성([M-143] F-D): write-후-chmod의 umask 노출 창 제거
        fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(k.private_bytes_raw().hex())
        return k

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

    # ── HTTP ──
    def _req(self, method, path, obj=None):
        data = json.dumps(obj).encode() if obj is not None else None
        r = urllib.request.Request(self.url + path, data=data, method=method,
                                   headers={"Content-Type": "application/json",
                                            "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(r, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            err = e.read().decode()[:300]
            raise RuntimeError(f"HTTP {e.code}: {err}") from None

    def _get(self, path):
        return self._req("GET", path)

    def _post(self, path, obj):
        return self._req("POST", path, obj)

    # ── 봉투 서명(커널과 바이트-동일 — 골든 결박) ──
    def sign_env(self, typ, args):
        st = self._get(f"/nonce/{self.p}")
        body = {"typ": typ, "args": args, "p": self.p, "epoch": st["epoch"]}
        sig = self.key.sign(sig_msg(self.log_id, body, st["nonce"]))
        return {**body, "nonce": st["nonce"], "sig": sig.hex()}

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
                   k=None):
        """★T = 잡별 시한(FL2.2 J-1) · ★k = 표본-검증 깊이([M-162] — 2~16 ·
        무지정 = 서버 기본 2 · H2가 깊이까지 결박: 깊이↔가격 쌍대의 매수자-다이얼)."""
        _pg_face = self._policy_guard(anchor, nid, kind, k)   # ★M-3 선언-가드
        job = {"kind": kind, "seed": seed, "n": n}
        if k is not None:
            job["k"] = int(k)
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
        body = {"ref": str(ref), "p": self.p}
        sig = self.key.sign(b"FL22-CHAL" + self.log_id + canon(body)).hex()
        return self._post("/challenge", {**body, "sig": sig})

    # ── ★호가 창(R2-a) — 오프-원장 서명 게시판(ASK = 매도 호가 · WANT = 매수 호가) ──
    # ⚠️게시는 자문(무-에스크로·무-구속) — 구속·정산은 온-원장(redeem_job·submit_block)만.
    def board(self):
        """현재 호가 창: asks(가격 오름차순 = 최우선 매도부터)·wants(내림차순)."""
        return self._get("/board")

    def _board_send(self, body):
        sig = self.key.sign(BOARD_DOMAIN + self.log_id + canon(body)).hex()
        return self._post("/board", {"post": body, "sig": sig})

    # ── ★[M-162] leg-릴레이 — 원자-체결의 대역-외 leg 교환 자기-서비스 ──
    def send_leg(self, to, payload):
        """서명-leg(들)를 상대 사서함으로 — payload = 임의 JSON(관례: {"ref", "legs"}).
        ⚠️노드는 무해석·무구속(자문층) · leg 봉투는 nonce-1회용이라 중계 탈취 이득 0."""
        body = {"p": self.p, "to": to,
                "blob": json.dumps(payload, ensure_ascii=False),
                "epoch": self.state()["epoch"]}   # ★R-1 신선도(재전송 차단)
        sig = self.key.sign(RELAY_DOMAIN + self.log_id + canon(body)).hex()
        return self._post("/relay", {"msg": body, "sig": sig})

    def fetch_legs(self):
        """내 사서함 수신(읽고-지움) — [{frm, payload, epoch}]."""
        body = {"p": self.p, "fetch": True}
        sig = self.key.sign(RELAY_DOMAIN + self.log_id + canon(body)).hex()
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
        ⚠️p̂×exposure는 총-기대손실 상한 — 인수자는 가해자-층 뒤 2차-손실이므로 실제
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

    def verify_attest(self, att):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey as _PK)
        doc = att["doc"]
        if doc.get("complete") is not True:
            return {"ok": False, "why": "부분 발췌 = 무효(전량-아니면-무)"}
        pk = _PK.from_public_bytes(bytes.fromhex(self.meta["operator_pk"]))
        try:
            pk.verify(bytes.fromhex(att["operator_sig"]),
                      DOMAIN + canon(doc))
            return {"ok": True, "principal": doc["principal"],
                    "upto_seq": doc["upto_seq"]}
        except InvalidSignature:
            return {"ok": False, "why": "서명 위조"}

    # ── 라이트 검증(A-6 · R-6 봉합): 확정 높이까지 엄격 검증 + 미서명 최신 꼬리는 pending ──
    def verify_chain(self, since=0, limit_batches=200):
        """head 사슬·운영자 서명은 전량 엄격. 공동-서명(k-of-n)은 비동기 도착하므로
        ★공동-서명이 아직 부족한 **최신 연속 꼬리**는 위반이 아니라 `pending`(확정 미도달).
        블록체인 confirmation-depth 시맨틱 — 확정 prefix가 정합이면 ok(pending 별도 보고).
        위반은 오직: head 불일치·사슬 단절·운영자 서명 위조·★확정된(공동서명 완비) 항목의
        서명 실패(= 진짜 변조). ★limit_batches 소진 = 절단 명시 실패([M-143] F-A —
        부분 검증을 ok로 보고하지 않는다 · 큰 원장은 인자를 올려 전량 검증)."""
        meta = self.meta
        op_pk = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(meta["operator_pk"]))
        co_pks = {c: Ed25519PublicKey.from_public_bytes(bytes.fromhex(h))
                  for c, h in meta["cosigners"].items()}
        k_need = meta["cosign_k"]
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
            for r in batch:      # ★D-2 병합 — 분리 서명자의 부분-서명 줄들을 합친다
                m = cos.setdefault(r["seq"], {"head": r["head"], "sigs": {}})
                if r["head"] == m["head"]:
                    for cnm, sg in r["sigs"].items():
                        m["sigs"].setdefault(cnm, sg)
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
            s = page[-1]["seq"] + 1
        # ★F-A([M-143]) — 침묵-절단 금지: limit_batches가 소진돼 전량을 못 가져왔으면
        # 부분-검증을 ok로 보고하지 않는다(「전량-아니면-무」 — attest와 같은 규범).
        # 검증기 자신이 유일한 침묵 상한이던 자리의 봉합 — 명시 실패 + 인자 상향 안내.
        if not (cos_complete and log_complete):
            return {"ok": False, "truncated": True,
                    "fetched": len(entries),
                    "why": f"절단: limit_batches({limit_batches}) 소진 — 전량 미조회"
                           "(부분 검증은 판정이 아니다 · 인자를 올려 재실행)"}
        prev = None
        confirmed = 0
        pending = 0
        for e in entries:
            base = {k: e[k] for k in ("env", "fp", "w_epoch", "state_root")}
            if "_force" in e:
                base = base | {"_force": e["_force"]}
            head = hashlib.sha256(e["prev"].encode() + canon(base)).hexdigest()
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
            if env.get("typ") == "JOIN":             # 이후 봉투의 서명자 pk 등록
                a_ = (env.get("args") or {})
                env_pks[a_.get("principal")] = \
                    Ed25519PublicKey.from_public_bytes(bytes.fromhex(a_["pk"]))
            if "head_sig" in e:
                try:
                    op_pk.verify(bytes.fromhex(e["head_sig"]),
                                 DOMAIN + bytes.fromhex(e["head"]))
                except InvalidSignature:
                    return {"ok": False, "why": f"운영자 서명 위조 seq {e['seq']}"}
            r = cos.get(e["seq"])
            good = 0
            if r and r["head"] == e["head"]:
                for c, sig in r["sigs"].items():
                    try:
                        co_pks[c].verify(bytes.fromhex(sig),
                                         DOMAIN + bytes.fromhex(e["head"]))
                        good += 1
                    except (KeyError, InvalidSignature):
                        pass
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
                       if _co_ok(co_pks, c, sig, e["head"]))
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
