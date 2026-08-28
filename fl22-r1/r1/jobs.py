#!/usr/bin/env python3
"""jobs.py — R1 실물 페릴: 작업 클래스·검증·가격 ([M-95] A-1 · [M-99] P-2/P-3′ 확장).

★독트린([VERIFICATION_DOCTRINE]): 검증 = **약속-일치** — 약속(명세·테스트·표본-프로토콜)
은 REDEEM 시점에 결박되고, 검증은 그 약속과 산출의 일치만 가른다(불일치 = 미이행 = 시한).

클래스 사다리 v1([VERIFICATION_OBJECT_STUDY §3] — [M-99]):
  sha256_chain          결정론 재계산형(v0 데모 잔존 — 전수-검증 · 검증비 = 작업비)
  ★sha256_chain_sampled 표본-검증형 — 체크포인트 제출 · 검증 = 무작위 구간 k개 재계산
                        (검증-시점 표본 — 이행자는 어느 구간이 검사될지 모른다) ·
                        잔여 위험은 인수의 몫(쌍대 — R-SAMPLE이 잰다)
  pycheck               코드-이행형 — 약속 = 검사 스크립트(test.py: solution 임포트·검증·
                        "OK" 출력) · 산출 = solution.py · 검증 = 격리 실행(-I·자원 상한·
                        임시 디렉터리). ⚠️v0 격리 = 프로세스-수준(완전 격리 아님 — 배포
                        시 컨테이너 권고 · [R1_PROGRAM §5] D-12 등재)
                        ⛔★**협조적-이행자 한정(RD-9 정직 강등)**: 산출이 판정 프로세스
                        안에서 실행되므로 적대적 산출이 수용 술어를 위조 가능(임포트 시점
                        "OK"+즉시 종료 — 단일-프로세스 수리 원리 불가). 적대 설정은 pyjudge.
  ★pyjudge              ★평가-이행형([M-105] D-10 — 판정-분리 = 사다리 v2의 실물 · RD-9
                        수리): 약속 = checker.py + 입력 · 산출 = 프로그램(solution.py) ·
                        검증 = ①격리 프로세스에서 산출 실행(stdin=입력·stdout 포획 —
                        신뢰 없음) ②**별도 프로세스**에서 checker가 포획된 바이트만 심사
                        (산출 코드 비실행 · rc 0 ∧ "OK") — 적대적 산출은 자기 출력만 움직임.
                        ⚠️checker(요청자 코드)의 노드-침입·자원 방어는 여전히 컨테이너
                        몫(D-12) — 판정-분리는 위조를 막지 침입을 막지 않는다.

★가격 결박(P-2 — 정책 상수 · D-4와 한 자리 재조정 가능): 상환 노트 액면 ≥ price(job).
  1 AU = 250,000 sha256-반복(N_PER_AU) · pycheck 하한 1 AU(지능 작업의 가격은 시장 몫 —
  하한만 결박).
"""
import base64
import hashlib
import os
import random
import resource
import shutil
import subprocess
import sys
import tempfile


def _rlimits():
    """★D-12 보강 — 검사 프로세스 자원 상한(CPU·주소공간·파일크기·프로세스 수).
    완전 격리는 컨테이너 몫(배포-잔여 D-12) — 이것은 프로세스-수준 상한."""
    resource.setrlimit(resource.RLIMIT_CPU, (PY_TIMEOUT, PY_TIMEOUT + 2))
    try:
        resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
    except (ValueError, OSError):
        pass                                   # 일부 플랫폼(macOS) 미지원 — 등재
    resource.setrlimit(resource.RLIMIT_FSIZE, (5 << 20, 5 << 20))
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
    except (ValueError, OSError):
        pass

KINDS = ("sha256_chain", "sha256_chain_sampled", "pycheck", "pyjudge")
SOL_OUT_MAX = 1 << 20                # pyjudge — 산출 stdout 포획 상한(1MB)
CHK_OUT_MAX = 4096                   # checker/test 판정 출력 상한(수용 토큰만 필요)


def _run_capped(argv, cwd, cap, stdin=b""):
    """★H3 — 자식 stdout을 **파일로** 받아(부모 메모리 무접촉 · RLIMIT_FSIZE=5MB가 자식
    쓰기를 강제 캡) 상한 cap 바이트만 되읽는다. capture_output의 무한 버퍼링(악성 산출이
    수백 MB 뿜어 검증기 OOM) 봉합. 반환 (returncode, stdout[:cap], truncated).
    ★truncated([M-149] SR-7): cap 초과분을 무-표지로 절단하면 「전달된 것과 다른
    바이트열」을 심사하게 된다 — 접두-관대 checker의 절단 오수용이 재현 확정됐다(2MB
    산출 → 1MB 절단본 합격). 호출자는 절단 시 판정이 아니라 **명시 거부**로 간다."""
    op = os.path.join(cwd, ".stdout")
    with open(op, "w+b") as of:
        try:
            r = subprocess.run(argv, cwd=cwd, env={"PATH": ""}, input=stdin,
                               stdout=of, stderr=subprocess.DEVNULL,
                               timeout=PY_TIMEOUT, preexec_fn=_rlimits)
        finally:
            of.seek(0, 2)
            size = of.tell()
            of.seek(0)
            data = of.read(cap)
    return r.returncode, data, size > cap
N_MIN, N_MAX = 1, 5_000_000          # 남용 상한(검증 비용 유계)
N_PER_AU = 250_000                   # ★P-2 — 1 AU당 작업량(정책 상수)
CKPT = 50_000                        # sampled — 체크포인트 간격
SAMPLE_K = 2                         # sampled — 검증 구간 수(검증-시점 무작위)
PY_MAX_B = 65_536                    # pycheck — 파일 크기 상한
PY_TIMEOUT = 10                      # pycheck — 실행 상한(초)


def _accepts(out_bytes):
    """★수용 술어(완결성 점검 low): 마지막 비-공백 줄이 정확히 'OK' — 부분문자열 매치
    (b'OK' in ...)는 'NOT OK'·진단 출력에 OK가 섞이면 오수용했다."""
    lines = [ln.strip() for ln in out_bytes.splitlines() if ln.strip()]
    return bool(lines) and lines[-1] == b"OK"


def _chain_from(start_bytes, steps):
    h = start_bytes
    for _ in range(int(steps)):
        h = hashlib.sha256(h).digest()
    return h


def compute(kind, seed_hex, n):
    """이행자-측 계산(sha256 계열 — pycheck는 이행자의 지능 몫)."""
    if kind == "sha256_chain":
        return _chain_from(bytes.fromhex(seed_hex), n).hex()
    if kind == "sha256_chain_sampled":
        h = bytes.fromhex(seed_hex)
        ckpts = []
        for i in range(0, int(n), CKPT):
            steps = min(CKPT, n - i)
            h = _chain_from(h, steps)
            ckpts.append(h.hex())
        return {"final": h.hex(), "ckpts": ckpts}
    raise ValueError(f"compute 미지원 클래스 {kind}")


def price(job):
    """★P-2 — 최소 액면(작업량-비례 · 하한 1)."""
    if job["kind"] in ("sha256_chain", "sha256_chain_sampled"):
        return max(1, -(-job["n"] // N_PER_AU))
    return 1                          # pycheck — 하한 1(시장 가격은 수락으로)


def validate_spec(job):
    if not isinstance(job, dict):
        raise ValueError("작업 명세는 객체")
    kind = job.get("kind")
    if kind not in KINDS:
        raise ValueError("작업 클래스 밖")
    if kind in ("sha256_chain", "sha256_chain_sampled"):
        seed = job.get("seed", "")
        if not (isinstance(seed, str) and 2 <= len(seed) <= 128):
            raise ValueError("seed는 2~128자 hex")
        bytes.fromhex(seed)
        n = job.get("n")
        if not (isinstance(n, int) and N_MIN <= n <= N_MAX):
            raise ValueError(f"n ∈ [{N_MIN}, {N_MAX}]")
        spec = {"kind": kind, "seed": seed.lower(), "n": n}
        if kind == "sha256_chain_sampled" and "k" in job:
            k = job["k"]                 # ★[M-162] 잡별 검증-깊이(매수자-선택 ·
            if not (isinstance(k, int) and 2 <= k <= 16):   # H2가 깊이를 결박)
                raise ValueError("k ∈ [2, 16]")
            spec["k"] = k
        return spec
    def _b64_field(name, allow_empty=False):
        v = job.get(name, "")
        if not isinstance(v, str) or len(v) > PY_MAX_B * 2 or \
                (not v and not allow_empty):
            raise ValueError(f"{name} 크기 밖")
        try:
            raw = base64.b64decode(v, validate=True)
        except Exception:
            raise ValueError(f"{name} 비정형")
        if len(raw) > PY_MAX_B:
            raise ValueError(f"{name} 크기 상한")
        return v

    if kind == "pycheck":            # 약속 = 검사 스크립트(b64 · 크기 유계)
        return {"kind": "pycheck", "test_b64": _b64_field("test_b64")}
    # ★pyjudge — 약속 = 판정 스크립트 + 입력(둘 다 REDEEM 결박)
    spec = {"kind": "pyjudge", "checker_b64": _b64_field("checker_b64")}
    if job.get("input_b64"):
        spec["input_b64"] = _b64_field("input_b64", allow_empty=True)
    return spec


def _verify_sampled(job, output):
    if not (isinstance(output, dict) and "final" in output and "ckpts" in output):
        return False, {"why": "산출 형식"}
    n = job["n"]
    want = -(-n // CKPT)
    ck = output["ckpts"]
    if not (isinstance(ck, list) and len(ck) == want
            and ck[-1] == output["final"]):
        return False, {"why": "체크포인트 형식"}
    # ★hex 유효성 선검증(완결성 점검 low): 비정형 원소가 표본 인덱스에 따라 비결정적으로
    # uncaught ValueError를 던지던 것 봉합 — 형식 불량은 결정론적 거부.
    if not all(isinstance(x, str) and len(x) == 64 for x in ck):
        return False, {"why": "체크포인트 형식(hex 64)"}
    try:
        for x in ck:
            bytes.fromhex(x)
    except ValueError:
        return False, {"why": "체크포인트 비-hex"}
    # ★검증-시점 무작위 표본(이행자는 제출 전에 알 수 없다) — 구간 재계산
    k_eff = job.get("k", SAMPLE_K)       # ★잡별-깊이(무지정 = 현행 상수 2)
    idxs = sorted(random.SystemRandom().sample(range(want),
                                               min(k_eff, want)))
    for i in idxs:
        start = (bytes.fromhex(job["seed"]) if i == 0
                 else bytes.fromhex(ck[i - 1]))
        steps = min(CKPT, n - i * CKPT)
        if _chain_from(start, steps).hex() != ck[i]:
            return False, {"why": f"구간 {i} 불일치", "checked": idxs}
    return True, {"checked": idxs, "coverage": round(len(idxs) / want, 4)}


def _verify_pycheck(job, output):
    if not isinstance(output, str) or len(output) > PY_MAX_B * 2:
        return False, {"why": "산출 형식"}
    try:
        sol = base64.b64decode(output, validate=True)
    except Exception:
        return False, {"why": "solution_b64 비정형"}
    if len(sol) > PY_MAX_B:
        return False, {"why": "산출 크기 상한"}
    d = tempfile.mkdtemp(prefix="pycheck-")
    try:
        open(os.path.join(d, "solution.py"), "wb").write(sol)
        open(os.path.join(d, "test.py"), "wb").write(
            base64.b64decode(job["test_b64"]))
        # -I(고립)는 cwd를 sys.path에서 빼므로 러너가 경로만 주입(격리 유지)
        open(os.path.join(d, "_runner.py"), "w").write(
            "import sys, os\nsys.path.insert(0, os.getcwd())\n"
            "exec(compile(open('test.py', 'rb').read(), 'test.py', 'exec'),"
            " {'__name__': '__main__'})\n")
        # ⚠️v0 격리 = 프로세스-수준(-I 고립·빈 env·임시 cwd·시간 상한) — D-12 등재
        rc, out, tr = _run_capped([sys.executable, "-I", "_runner.py"], d,
                                  CHK_OUT_MAX)      # ★H3 — 파일-포획·상한 읽기
        if tr:                                     # ★SR-7 — 절단본 심사 금지
            return False, {"why": f"판정 출력 상한 초과({CHK_OUT_MAX}B)", "rc": rc}
        ok = rc == 0 and _accepts(out)             # ★수용 = 마지막 줄 == OK(부분매치 금지)
        return ok, {"rc": rc, "out": out.decode(errors="replace")[-200:]}
    except subprocess.TimeoutExpired:
        return False, {"why": "시간 상한"}
    except Exception as e:
        return False, {"why": f"{type(e).__name__}"}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _verify_pyjudge(job, output):
    """★판정-분리([M-105] RD-9 수리): ①산출을 자기 프로세스에서 실행(stdout 포획 —
    무신뢰) ②checker를 **별도 프로세스**에서 실행(포획 바이트만 심사 · 산출 코드 비실행).
    적대적 산출은 자기 출력 바이트만 움직일 수 있다 — 수용 술어는 checker 프로세스 소유."""
    if not isinstance(output, str) or len(output) > PY_MAX_B * 2:
        return False, {"why": "산출 형식"}
    try:
        sol = base64.b64decode(output, validate=True)
    except Exception:
        return False, {"why": "solution_b64 비정형"}
    if len(sol) > PY_MAX_B:
        return False, {"why": "산출 크기 상한"}
    stdin_b = base64.b64decode(job.get("input_b64", "") or "")
    d1 = tempfile.mkdtemp(prefix="pyjudge-sol-")
    d2 = tempfile.mkdtemp(prefix="pyjudge-chk-")
    try:
        open(os.path.join(d1, "solution.py"), "wb").write(sol)
        try:    # ── ①산출 실행(무신뢰 — rc·출력은 참고일 뿐 판정 아님 · ★H3 파일-포획) ──
            sol_rc, out_b, tr_sol = _run_capped(
                [sys.executable, "-I", "solution.py"], d1,
                SOL_OUT_MAX, stdin=stdin_b)
        except subprocess.TimeoutExpired:
            return False, {"why": "산출 실행 시간 상한"}
        if tr_sol:      # ★SR-7 — 절단 1MB를 심사하면 오수용/불투명-거부(재현 확정)
            return False, {"why": f"산출 stdout 상한 초과({SOL_OUT_MAX}B — "
                                  "절단본 심사 거부)", "sol_rc": sol_rc}
        # ── ②판정(별도 프로세스 — checker는 output.txt/input.txt 바이트만 본다) ──
        open(os.path.join(d2, "checker.py"), "wb").write(
            base64.b64decode(job["checker_b64"]))
        open(os.path.join(d2, "output.txt"), "wb").write(out_b)
        open(os.path.join(d2, "input.txt"), "wb").write(stdin_b)
        try:
            chk_rc, chk_out, tr_chk = _run_capped(
                [sys.executable, "-I", "checker.py"], d2, CHK_OUT_MAX)
        except subprocess.TimeoutExpired:
            return False, {"why": "판정 시간 상한"}
        if tr_chk:                                 # ★SR-7 — fail-closed를 명시 사유로
            return False, {"why": f"판정 출력 상한 초과({CHK_OUT_MAX}B)"}
        ok = chk_rc == 0 and _accepts(chk_out)     # ★수용 = 마지막 줄 == OK
        return ok, {"sol_rc": sol_rc, "checker_rc": chk_rc,
                    "out_bytes": len(out_b),
                    "checker_out": chk_out.decode(errors="replace")[-200:]}
    except Exception as e:
        return False, {"why": f"{type(e).__name__}"}
    finally:
        shutil.rmtree(d1, ignore_errors=True)
        shutil.rmtree(d2, ignore_errors=True)


def verify_output(job, output):
    """약속-일치 판정 — (ok, detail)."""
    k = job["kind"]
    if k == "sha256_chain":
        ok = (isinstance(output, str)
              and compute(k, job["seed"], job["n"]) == output.lower())
        return ok, {}
    if k == "sha256_chain_sampled":
        return _verify_sampled(job, output)
    if k == "pyjudge":
        return _verify_pyjudge(job, output)
    return _verify_pycheck(job, output)
