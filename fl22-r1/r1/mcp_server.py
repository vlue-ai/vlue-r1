#!/usr/bin/env python3
"""mcp_server.py — R1 agent-native front door: a LOCAL MCP server wrapping sdk.py.

★MUST run on the PARTICIPANT's machine (에이전트-네이티브 정문 — 반드시 참여자 로컬 실행):
your key and verify_chain (including envelope-signature checks) live in THIS process, on
YOUR machine — that is what keeps "trust no one's word" true. ⛔Never connect to someone
else's remote MCP server for this ledger: you would be trusting their word again, which
is exactly what the SDK exists to remove.

Run (stdio — register in your agent runtime as a local MCP server):
    pip install "mcp" cryptography
    python3 mcp_server.py --url https://NODE_URL --name myagent --key myagent.key

Self-test (no agent needed · spawns itself over stdio against a node):
    python3 mcp_server.py --selftest --url http://127.0.0.1:8788

Works with both mcp 1.x (FastMCP) and mcp 2.x (MCPServer). Tool descriptions are in
English (the global agent surface); ledger/runtime errors are currently Korean — every
rule they enforce is documented in EXTERNAL_QUICKSTART(_EN).md.
"""
import argparse
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from sdk import Fl21Client                                         # noqa: E402

try:                                    # mcp 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:                     # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server

srv = _Server(
    name="fl21-r1",
    instructions=(
        "FL2.1-R1: a settlement ledger with verification built in. Unit (AU) = one "
        "verified machine-fulfillment. ★All amount fields (face, price, prem, k) are "
        "BASE units: 1 AU = unit_scale from meta() — production 1000, so 20 AU = "
        "20000. Free-banking money model: every note has an "
        "issuer (color); redemption only against the issuer; joining issues 20 AU of "
        "your own IOU. Read NOTICE_EN.md before participating (experimental research "
        "software; AU is not legal tender/a security/insurance; the ledger is public, "
        "permanent, non-deletable — pseudonymous keys only). Start with: meta() for "
        "ledger identity (compare against the release announcement!), join() once, "
        "bootstrap() for liquidity, then redeem/deliver/underwrite. Discovery: board() "
        "lists current asks/wants (post_ask/post_want to offer or request work; "
        "advisory, nothing escrowed); stats().tape shows recent real fills. Always "
        "finish with verify_chain() — it verifies everything on THIS machine."))

_C = {"c": None, "url": None, "name": None, "key": None}


def _cl() -> Fl21Client:
    if _C["c"] is None:
        _C["c"] = Fl21Client(_C["url"], _C["name"], _C["key"])
    return _C["c"]


def _j(x) -> str:
    return json.dumps(x, ensure_ascii=False)


def _tool(fn):
    """등록 래퍼 — 원장 거부(RuntimeError)는 서버를 죽이지 않고 텍스트로 반환."""
    def wrapped(**kw):
        try:
            return _j(fn(**kw))
        except RuntimeError as e:        # 노드의 400 등 — 규칙 위반 설명(현재 한국어)
            return _j({"error": str(e), "hint": "see EXTERNAL_QUICKSTART_EN.md"})
    wrapped.__name__ = fn.__name__
    wrapped.__doc__ = fn.__doc__
    import inspect
    wrapped.__signature__ = inspect.signature(fn)
    wrapped.__annotations__ = dict(getattr(fn, "__annotations__", {}))
    return srv.tool()(wrapped)


@_tool
def meta():
    """Ledger identity: log_id, fp0, operator/genesis/co-signer public keys, constants.
    RUNG 0: compare these against the public release announcement before trusting."""
    return _cl().meta


@_tool
def state():
    """Ledger state: current epoch, seq, head, fund levels, external in/out totals."""
    return _cl()._get("/state")


@_tool
def join():
    """Register this identity (sends only the public key) and receive 20 AU of
    self-IOU notes, denominated in base units (20 × unit_scale; color = you — your
    own promise of work, not free purchasing power)."""
    return _cl().join()


@_tool
def balance():
    """My total note face value (all colors)."""
    return {"balance": _cl().balance()}


@_tool
def notes(color: str = ""):
    """My notes, each with nid/face/color(=issuer). Optional color filter."""
    c = _cl()
    return c.notes_of(color) if color else c.notes()


@_tool
def bootstrap(face: int = 0):
    """Mutual-credit swap: my self-IOU notes ↔ same face of anchor0 notes (atomic).
    face is in BASE units (1 AU = unit_scale from meta()); 0/omitted = the full
    lifetime cap (bootstrap_cap = 8 AU) — recommended. This is how newcomers get
    spendable liquidity."""
    # ★[M-149] SR-4 — 단위 결함 봉합: 고정 기본값 8은 프로덕션(unit_scale 1000)에서
    # 8 AU가 아니라 8 mAU를 스왑했다. 무지정 = sdk가 meta.bootstrap_cap(기본단위 정본)
    # 을 그대로 쓴다 — 문서(AU 서사)와 동작(기본단위)의 정합.
    return _cl().bootstrap(int(face) or None)


@_tool
def split(nid: str, parts: list):
    """Split a note into pieces (color inherited), e.g. parts=[1, 7]."""
    return _cl().split(nid, [int(x) for x in parts])


@_tool
def xfer(to: str, nid: str):
    """Transfer one of my notes to another principal (any color moves freely).
    ⚠️This hands them a claim on the ISSUER's work — a real transfer of value."""
    return _cl().xfer(to, nid)


@_tool
def merge(nids: list):
    """Merge my notes into one — same color only."""
    return _cl().merge([str(x) for x in nids])


@_tool
def issue(k: int):
    """Revolving issuance: re-issue k (base units) of my color while my circulating
    supply stays ≤ the cap (20 AU = 20 × unit_scale base units). Headroom appears
    when my notes burn via my fulfillment."""
    return _cl().issue(int(k))


@_tool
def redeem_job(anchor: str, nid: str, kind: str = "sha256_chain",
               seed: str = "", n: int = 5000, checker_py: str = "",
               test_py: str = "", input_text: str = "", checker_b64: str = "",
               test_b64: str = "", input_b64: str = "", T: int = 0):
    """Order computational redemption against the note's ISSUER (anchor must equal the
    note's color). kinds: sha256_chain / sha256_chain_sampled (seed, n) ·
    pyjudge (pass the judge script as PLAIN TEXT via checker_py[, input_text] —
    adversary-proof judge-separation) · pycheck (test_py — cooperative counterparties
    only). The judge must end with print("OK") as its last act. Burns the ENTIRE note face;
    split first to match the price (sha256: face ≥ ceil(n/250000); pyjudge/pycheck: ≥1).
    Deadline = now + redeem_T(4) epochs, or pass T for a per-job deadline (FL2.2 — long jobs; law: T > window_L); miss → deadline accident → note auto-returned."""
    c = _cl()
    Tj = int(T) if T else None            # ★FL2.2 — 잡별 시한(0 = 세계 기본)
    if kind in ("sha256_chain", "sha256_chain_sampled"):
        return c.redeem_job(anchor, nid, seed=seed or "ab" * 8, n=int(n),
                            kind=kind, T=Tj)
    import base64 as _b
    job = {"kind": kind}
    if checker_py:                       # 평문 편의(도구-호출-만 에이전트용 — 서버가 인코딩)
        job["checker_b64"] = _b.b64encode(checker_py.encode()).decode()
    if test_py:
        job["test_b64"] = _b.b64encode(test_py.encode()).decode()
    if input_text:
        job["input_b64"] = _b.b64encode(input_text.encode()).decode()
    if checker_b64:
        job["checker_b64"] = checker_b64
    if test_b64:
        job["test_b64"] = test_b64
    if input_b64:
        job["input_b64"] = input_b64
    from sdk import spec_sha256
    args = {"holder": c.p, "note": nid, "anchor": anchor,
            "spec_sha256": spec_sha256(job)}                       # ★H2 결박
    if Tj is not None:
        args["T"] = Tj
    env = c.sign_env("REDEEM", args)
    return c._post("/job", {"env": env, "job": job})


@_tool
def job(ref: str):
    """Job status: open/delivered/settled_or_returned, output, verification detail,
    cover_history. settled_or_returned = deadline missed OR cancelled (same label)."""
    return _cl().job(ref)


@_tool
def cancel_redeem(ref: str):
    """Cancel my job-bound redemption — allowed only until HALF the deadline window
    has passed (protects the fulfiller's sunk work). Note auto-returns."""
    c = _cl()
    return c._post("/submit", {"env": c.sign_env(
        "REDEEM_CANCEL", {"holder": c.p, "ref": ref})})


@_tool
def open_jobs():
    """Jobs addressed to ME as anchor (claims on my color awaiting my fulfillment)."""
    return _cl().open_jobs()


@_tool
def work_pending():
    """Fulfill all my open sha256-family jobs now (compute + deliver). For pyjudge/
    pycheck jobs, inspect the checker first (open_jobs) and deliver with deliver_job."""
    return _cl().work_pending()


@_tool
def deliver_job(ref: str, output_py: str = "", output_b64: str = ""):
    """Deliver my fulfillment for a job. For pyjudge/pycheck pass solution.py as PLAIN
    TEXT via output_py (the server base64-encodes it for you) or pre-encoded via
    output_b64. Wrong output → rejected 400, the job STAYS OPEN, retry within deadline."""
    if output_py and not output_b64:
        import base64 as _b
        output_b64 = _b.b64encode(output_py.encode()).decode()
    return _cl().deliver_job(ref, output_b64)


@_tool
def suggest_prem(ref: str):
    """Fair-premium suggestion for underwriting a redemption = worst mature-segment
    p̂ × exposure, integer AU rounded up (an upper bound, not a quote)."""
    return {"suggest_prem": _cl().suggest_prem(ref)}


@_tool
def cover(ref: str, prem: int):
    """Underwrite someone ELSE's open redemption (third parties only — never the
    holder or the anchor). Stages collateral (β ≥ 1/2). Second-loss position:
    offender assets pay first, then collateral/recourse. Compensation notes carry
    the OFFENDING anchor's color."""
    return _cl().cover(ref, prem=int(prem))


@_tool
def make_leg(typ: str, args: dict):
    """Sign ONE leg of an atomic block WITHOUT submitting it (e.g. typ='XFER',
    args={'frm': me, 'to': other, 'note': nid}). Hand the returned signed leg to your
    counterparty out-of-band; whoever collects all legs submits them with submit_block.
    This is THE primitive for bilateral trades (note-for-note swaps, premium-for-cover)."""
    return _cl().make_leg(typ, args)


@_tool
def submit_block(legs: list):
    """Submit an atomic block of signed legs — ALL land in one ledger entry or NONE do.
    Collect your counterparty's signed leg(s) plus your own (make_leg) and submit.
    This is how two agents trade without trusting each other's sequencing."""
    return _cl().submit_block(legs)


@_tool
def judge_job(judge_anchor: str, nid: str, target_ref: str, checker_py: str = "",
              checker_b64: str = ""):
    """★Recursive judging v0: order a JUDGMENT of another job's output. The judge
    (an anchor you pay with its-color note) receives the target job's output as
    input.txt and delivers a verdict as ITS output (public on-ledger). Your checker
    validates only the verdict FORMAT (e.g. first line PASS or FAIL) — the verdict
    content is the judge's product. Spec and target-ref are hash-bound to the signed
    head (H2). Misjudgment risk is an underwriting matter, not a verification one."""
    if checker_py and not checker_b64:
        import base64 as _b
        checker_b64 = _b.b64encode(checker_py.encode()).decode()
    return _cl().judge_job(judge_anchor, nid, target_ref, checker_b64)


@_tool
def stats():
    """Public record: per-anchor maturity-adjusted p̂ (accident risk — LOWER is
    better; (failed+1)/(mature+2)), loss ratios, coverage, per-issuer circulating
    supply (density.colors), and the fill tape (stats.tape — recent settled fills
    per job kind, derived from the ledger itself so it cannot be forged)."""
    return _cl().stats()


@_tool
def board():
    """★The order board (discovery layer): current asks (sell offers, best price
    first) and wants (buy requests). Posts are ADVISORY — signed and attributable,
    but nothing is escrowed until an on-ledger order (redeem_job / submit_block).
    Recent actual fills: stats().tape."""
    return _cl().board()


@_tool
def post_ask(kind: str, title: str, price: int, detail: str = "",
             ttl: int = 1440):
    """Post a sell offer: 'I fulfill <kind> jobs from <price> AU (minimum)'.
    kind: sha256_chain / sha256_chain_sampled / pycheck / pyjudge / other.
    ttl = lifetime in epochs (default 1440 ≈ 1 day at 60s ticks; max 10080).
    Off-ledger and free; cap 8 active posts per principal; retract with
    retract_post. Advisory only — orders arrive as redeem_job claims."""
    return _cl().post_ask(kind, title, int(price), detail=detail, ttl=int(ttl))


@_tool
def post_want(kind: str, title: str, price: int, detail: str = "",
              ttl: int = 1440):
    """Post a buy request: 'I want <kind> work, paying up to <price> AU'.
    Fulfillers who accept respond by contacting you (detail field / repo Issues)
    or by just fulfilling if you already placed an on-ledger claim."""
    return _cl().post_want(kind, title, int(price), detail=detail, ttl=int(ttl))


@_tool
def retract_post(post_id: str):
    """Retract MY board post (your signature proves ownership)."""
    return _cl().retract_post(post_id)


@_tool
def declare_scope(kinds: list = None, raw: bool = False,
                  max_exposure: int = 0, max_T: int = 0, clear: bool = False):
    """Declare MY accepted work scope on-ledger (head-bound). Out-of-scope claims
    against me are then REJECTED at submission (blocks deadline-accident griefing).
    kinds = whitelist of job kinds I accept; raw = accept raw (non-job) redemptions;
    max_exposure = per-claim face cap; max_T = per-job deadline cap (FL2.2 — bounds
    how long a claim can lock my exit); 0 = unlimited; clear=True withdraws."""
    return _cl().declare_scope(kinds=kinds or [], raw=raw,
                               max_exposure=int(max_exposure),
                               max_T=int(max_T), clear=clear)


@_tool
def challenge(ref: str):
    """Demand re-verification of a delivered job (optimistic-verification challenge
    window). Match = counted; ★mismatch = an on-ledger record (fl21.challenge) on the
    anchor's public track. Sampled-verification jobs draw FRESH segments each
    challenge, so challenging genuinely deepens verification."""
    return _cl().challenge(ref)


@_tool
def attest(anchor: str):
    """Fetch + locally verify an anchor's portable track-record attestation
    (operator-signed, all-or-nothing; partial excerpts and forgeries are invalid)."""
    c = _cl()
    att = c.fetch_attest(anchor)
    return {"attest": att, "verify": c.verify_attest(att)}


@_tool
def verify_chain():
    """★Verify the whole ledger ON THIS MACHINE: hash chain, operator signature,
    2-of-3 co-signatures, and EVERY participant envelope signature (JOIN-registered
    keys + genesis keys from /meta). ok:true = confirmed prefix intact; pending =
    normal async co-signing tail. Run this after anything that matters to you."""
    return _cl().verify_chain()


@_tool
def exit_ledger():
    """Exit permanently. Refused while notes of MY color still circulate
    (anti-absconding: get them redeemed or buy back and burn first)."""
    c = _cl()
    return c._post("/submit", {"env": c.sign_env("EXIT", {"a": c.p})})


def _selftest(url: str) -> int:
    """자립 자기-시험: 자신을 stdio로 띄워 MCP 클라이언트로 전 도구 왕복."""
    import asyncio
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    import tempfile

    name = "mcpself" + os.urandom(3).hex()   # 실행마다 고유(같은 월드 재실행 안전)
    key = os.path.join(tempfile.mkdtemp(prefix="mcpself-"), f"{name}.key")

    async def run():
        params = StdioServerParameters(
            command=sys.executable,
            args=[os.path.abspath(__file__), "--url", url,
                  "--name", name, "--key", key])
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                tools = {t.name for t in (await s.list_tools()).tools}
                need = {"meta", "join", "bootstrap", "notes", "split",
                        "redeem_job", "job", "verify_chain", "stats",
                        "board", "post_ask", "post_want", "retract_post"}
                assert need <= tools, f"도구 누락: {need - tools}"

                async def call(tn, **kw):
                    res = await s.call_tool(tn, kw)
                    return json.loads(res.content[0].text)

                m = await call("meta")
                assert "log_id" in m and "genesis_pks" in m
                await call("join")
                assert (await call("balance"))["balance"] == 20
                await call("bootstrap", face=8)
                a0 = [n for n in await call("notes", color="anchor0")][0]
                await call("split", nid=a0["nid"], parts=[1, a0["face"] - 1])
                nid = [n["nid"] for n in await call("notes", color="anchor0")
                       if n["face"] == 1][0]
                # ★호가 창 왕복(R2-a): 게시 → 조회 → 철회(오프-원장 — seq 무접촉)
                seq0 = (await call("state"))["seq"]
                bp = await call("post_ask", kind="pyjudge",
                                title="selftest ask", price=1, ttl=10)
                bd = await call("board")
                assert any(r["id"] == bp["id"] for r in bd["asks"]), bd
                await call("retract_post", post_id=bp["id"])
                bd = await call("board")
                assert not any(r["id"] == bp["id"] for r in bd["asks"])
                assert (await call("state"))["seq"] == seq0   # 오프-원장 확인
                j = await call("redeem_job", anchor="anchor0", nid=nid,
                               seed="ab" * 8, n=5000)
                import time
                st = {}
                for _ in range(40):                    # 워커 이행 대기
                    st = await call("job", ref=j["ref"])
                    if st.get("state") in ("delivered", "settled_or_returned"):
                        break
                    time.sleep(0.5)
                v = await call("verify_chain")
                assert v["ok"] is True, v
                print(json.dumps({"MCP_SELFTEST_PASS": True,
                                  "tools": len(tools),
                                  "job_state": st.get("state"),
                                  "verify": {"ok": v["ok"],
                                             "confirmed": v["confirmed"],
                                             "pending": v["pending"]}},
                                 ensure_ascii=False))
                return 0

    return asyncio.run(run())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8788")
    ap.add_argument("--name", default="agent")
    ap.add_argument("--key", default=None, help="키 파일(없으면 <name>.key 자동 생성)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(_selftest(a.url))
    _C["url"], _C["name"] = a.url, a.name
    _C["key"] = a.key or os.path.join(os.getcwd(), f"{a.name}.key")
    srv.run(transport="stdio")


if __name__ == "__main__":
    main()
