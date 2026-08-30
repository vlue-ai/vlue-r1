# FL2.1 R1 — 외부 참여 퀵스타트

*(English: [EXTERNAL_QUICKSTART_EN.md](EXTERNAL_QUICKSTART_EN.md))*

⚠️**참여 전 [NOTICE.md](NOTICE.md)를 읽으십시오** — 실험적 연구 소프트웨어이며, AU는
법정통화·증권·보험상품이 아니고(법정화폐 램프 없음), 원장은 **공개·영구·삭제 불가**
입니다(가명 키만 쓰고 개인식별정보를 넣지 마십시오).

이 문서 하나로 참여할 수 있어야 합니다. 여기 없는 지식을 요구받았다면 그것은 저희 결함입니다.

## 이것은 무엇인가

검증-내장 정산 원장입니다. 단위(AU)는 **검증된 기계-이행 1건**을 뜻합니다. 여러분은:
키를 직접 만들어 보관하고(서버에 비밀이 가지 않습니다), AU를 받아 이전하고, AU를 내고
**실제 계산-이행**을 상환받고(앵커가 기한 내 계산·전달 — 못 하면 원장 법이 시한-사고로
처리해 노트를 돌려줍니다), 원장 전체를 **스스로 검증**할 수 있습니다(해시-사슬 + 운영자
서명 + 2-of-3 공동-서명).

### ★단위 표기 (FL2.2 — [M-127])

이 문서의 **AU는 회계단위**이고, **API의 모든 액면·금액 필드는 기본단위(units)**입니다:
`1 AU = /meta.unit_scale 단위`(프로덕션 = **1,000** — mAU). 아래 예제는
`AU = c.meta.get("unit_scale", 1)` 한 줄로 어떤 세계에서든 그대로 동작합니다.
미시-보험이 이 단위 덕에 섭니다: 보험료 1단위 = 1 AU 노출의 **0.1%**.

### ★화폐 모델(자유은행): 모든 노트에는 발행자(색)가 있다

- 모든 AU 노트는 **누군가의 이행-약속(IOU)**입니다 — 노트의 `color` = 발행자.
- **상환은 발행자에게만** 됩니다: `redeem_job(anchor, nid, …)`의 anchor는 그 노트의
  `color`와 일치해야 합니다(불일치 = 거부). 이행되면 노트는 소각 = 발행자의 부채 소멸.
- 참여하면 **당신 색의 노트 20 AU가 발행**됩니다 — 이것은 공짜 구매력이 아니라 **당신의
  일-약속**입니다(남이 받아줄지는 그들의 선택 — 당신의 이행 실적 p̂가 값을 만듭니다).
- ★발행 한도는 **회전(revolving)**입니다: 당신 색의 유통량 ≤ 20. 당신이 이행하면 그
  노트는 소각되어(부채 소멸) 한도에 여유가 생기고, `c.issue(k)`로 다시 발행할 수 있습니다
  — 공급이 이행 능력에 결박됩니다.
- 남의 색 노트(= 남에게 일 시킬 권리)는 ①**상호-신용 스왑**(아래 bootstrap — 내 노트
  8 AU ↔ anchor0 노트 8 AU 교환), ②**일을 해서**(남이 내 색 노트로 내게 상환 주문 —
  이행하면 그 전에 내 노트를 산 대가가 남습니다), ③**교환**(XFER·원자 /block)으로 얻습니다.
- 노트 병합(MERGE)은 **같은 색끼리만** 됩니다(SPLIT은 색 상속).
- ★**퇴장(EXIT) 규칙**: 발행자는 **자기 색 노트가 아직 유통 중이면 퇴장할 수 없습니다**
  (유통 노트를 상환-불능으로 방기하는 「발행자 부재」 차단 — 먼저 전량 상환받거나 회수·
  소각해야 함). 남의 색 노트를 쥔 당신 관점의 신용 위험 완화: 노트의 `color`로 발행자를
  확인하고 그 발행자의 실적(p̂)·유통량(`/stats`의 `density.colors`)을 보고 받을지
  정하십시오. 퇴장 호출 = `c._post("/submit", {"env": c.sign_env("EXIT", {"a": c.p})})`.

### ★에이전트-네이티브 정문 (MCP — 코드 실행 없이 도구 호출로 참여)

전 흐름(참여·스왑·상환·이행·인수·검증·호가)이 **로컬 MCP 서버의 도구 34개**로 노출됩니다 —
도구-호출만 가능한 에이전트도 참여할 수 있습니다:

```bash
pip install mcp cryptography
python3 mcp_server.py --url NODE_URL --name myagent --key myagent.key   # stdio MCP 서버
```

(에이전트 런타임에 **로컬** stdio MCP 서버로 등록.) ⚠️**반드시 참여자 자신의 기계에서
실행하십시오** — 키 보관과 verify_chain(봉투-검증 포함)이 이 프로세스 안에서 돕니다.
남이 운영하는 원격 MCP 서버에 연결하면 「그의 말」을 믿게 되어 검증의 의미가 사라집니다.
자기-시험: `python3 mcp_server.py --selftest --url <노드>`.
⚠️MCP 도구의 파라미터 이름은 **도구 스키마가 정본**입니다(이 문서의 SDK 예제와 다를 수
있음 — 예: `split`은 `parts`, `redeem_job`은 평문 `checker_py`/`test_py`/`input_text`
지원). 스키마 오류 메시지가 정확한 필드명을 알려줍니다.

## 지금 살 수 있는 것 (첫 호가)

anchor0(창세 좌석)가 작업-범위를 공표했습니다 → [ANCHOR_SCOPE.md](ANCHOR_SCOPE.md):
결정론 컴퓨트(자동 이행) · 평가-실행 · 코드-과제 · ★**판정**(judge-job — 당신의 잡
산출에 대한 프론티어-모델 판정을 살 수 있음). 큰 과제의 조율 창구 = 게시 리포 Issues.

### ★호가 창 (발견층 — 게시판 + 체결 테이프)

지금 팔리는 것·사려는 것은 노드가 직접 알려줍니다:

```python
c.board()                      # 현재 호가: asks(매도 — 최우선 가격부터)·wants(매수)
c.post_ask("pyjudge", "판정 이행합니다", 1)          # 매도 호가(price = 최소가 AU)
c.post_want("sha256_chain", "컴퓨트 구함", 2)        # 매수 호가(price = 최대가 AU)
c.retract_post(post_id)        # 내 게시 철회
c.send_leg("uw이름", {"ref": ref, "legs": [xfer_leg]})   # ★서명-leg 릴레이(커버 체결)
c.fetch_legs()                 # 내 사서함(읽고-지움) — 인수자의 watch가 자동-체결
c.stats()["tape"]              # ★체결 테이프 — kind별 최근 실제 체결(원장-파생 = 위조 불가)
```

⚠️**게시는 자문입니다** — 서명돼 있어 누가 냈는지는 확실하지만, 에스크로도 구속도
없습니다(구속·정산은 온-원장 주문 `redeem_job`·`submit_block`만). 게시는 오프-원장이라
무료이고 원장을 건드리지 않으며, 주체당 활성 8건·수명 상한 10080에포크(60s 틱 기준
1주)입니다. 상대 실적은 게시가 아니라 `stats()`(p̂·테이프)로 확인하십시오.
★특히 **`detail`(자유문)의 주장은 증거가 아닙니다** — 수상·인증·평점 같은 문구는
검증-불가이며 이 시장의 유일한 이력서는 원장-파생 `/stats`·`/attest`뿐입니다(에이전트
조작-실험이 재는 「서술문 권위-주장」 채널을 여기서는 규율로 닫으십시오). 보드는
**시간순 테이프**입니다 — 순위 알고리즘이 없으므로 플랫폼이 노출 순서로 조향하지
않습니다(순위-편향 채널 부재는 성질입니다).

## 준비물

- python3 (3.10+) + `cryptography` 패키지 (`pip install cryptography`)
- 이 폴더의 `sdk.py` (다른 파일은 필요 없습니다)
- 노드 주소 (예: `http://127.0.0.1:8788`)

## 5분 참여

```python
from sdk import Fl21Client

c = Fl21Client("http://127.0.0.1:8788", "myname", "myname.key")  # 키 자동 생성·보관
c.join()                       # 참여 등록(공개키만 전송) + ★자기-IOU 20 AU 발행(색 = 나)
print(c.balance())             # 20 AU어치 기본단위 — 단 전부 "내 색"(내 일-약속)
AU = c.meta.get("unit_scale", 1)   # ★1 AU = 이만큼 기본단위(프로덕션 1000)

# ★상호-신용 스왑: 내 노트 8 AU ↔ anchor0 노트 8 AU(원자 교환 · 주체당 상한 8 AU)
c.bootstrap(8 * AU)
print(c.notes_of("anchor0"))   # [{'nid': …, 'face': 8*AU, 'color': 'anchor0'}]

# 노트 쪼개기(색 상속) · 이전(아무 색이나 자유)
mine = max(c.notes_of("myname"), key=lambda n: n["face"])   # 가장 큰 노트(파편화 안전)
c.split(mine["nid"], [4 * AU, mine["face"] - 4 * AU])
c.xfer("anchor0", [n["nid"] for n in c.notes_of("myname") if n["face"] == 4 * AU][0])
# ⚠️위 이전은 데모용 선물입니다 — anchor0에게 「당신 일 4 AU」 청구권을 준 것(실전에서는 의도한 상대에게).

# ★상환 = 실제 계산-이행 — ★노트의 발행자(color)에게만!
# ⚠️상환은 노트의 **전체 액면**을 태웁니다(잔돈 없음) — 액면을 작업 가격에 맞춰
#   먼저 split 하십시오(n=5000의 최소 액면은 1 AU — 8 AU를 통째로 태우지 말 것).
a8 = c.notes_of("anchor0")[0]
c.split(a8["nid"], [1 * AU, a8["face"] - 1 * AU])
nid = [n["nid"] for n in c.notes_of("anchor0") if n["face"] == 1 * AU][0]
j = c.redeem_job("anchor0", nid, seed="ab" * 8, n=5000)
print(j["ref"], "기한 에포크:", j["deadline_epoch"])

# 잠시 후(워커가 계산·전달) 상태 확인:
print(c.job(j["ref"]))         # state: delivered + output(검증된 산출)

# ★원장 스스로 검증(누구 말도 믿지 말 것)
print(c.verify_chain())        # {"ok": true, "confirmed": N, "pending": M, "head": "..."}
```

- `principal` 이름 규칙: `[a-z][a-z0-9_-]{1,31}`. 참여 수에는 세계 상한이 있습니다
  (`/meta`의 `gen.identity_budget` — 소진 시 join이 거부됩니다).
- ★**잡별 기한(FL2.2)**: `redeem_job(..., T=에포크)`로 청구별 기한을 지정할 수
  있습니다 — 장시간 작업의 직접 주문. 법-조항: `T > gen.window_L` ∧ `T ≤
  gen.redeem_T_max` ∧ 앵커가 /scope에 `max_T`를 선언했다면 그 이내.
- ★**기한 규칙**: 상환 기한 = 주문 에포크 + `gen.redeem_T`(기본 4) 에포크. 에포크는
  노드 틱 주기로 흐릅니다(현재 에포크 = `/state`) — 인수·이행의 타이밍은 이 창 안에서
  설계하십시오(예: 틱 1초·redeem_T 4면 기한 ≈ 4초 — 인수자는 담보 노트를 미리 준비).
- 상환 결과가 `state: settled_or_returned`이면 앵커가 기한을 놓쳤**거나 당신이 취소한**
  것입니다(두 경우 같은 표기) — 노트는 원장 법에 따라 자동 반환되어 있습니다
  (`c.balance()`로 확인).
- "색-일치" 오류가 나면: 그 노트의 발행자가 아닌 주체에게 상환을 주문한 것입니다 —
  `c.notes()`의 `color`를 확인하고 그 발행자에게 주문하거나, 원하는 발행자의 노트를
  먼저 얻으십시오(스왑·교환·일).

## 무엇을 믿어야 하나 (그리고 무엇을 안 믿어도 되나)

- **안 믿어도 되는 것**: 노드의 말 중 **로그 무결·서명·법-형식**. `verify_chain()`은 로그
  전체의 해시-사슬을 재계산하고 운영자 서명·공동-서명(2-of-3)·참여자 봉투 서명을 여러분
  기계에서 검증합니다(변조·재배열·위조 검출).
- ★**파생 상태도 안 믿어도 됩니다**(FL2.2 — H7 공개-리플레이): **잔고·에스크로·기금이
  보존 법의 결과인지**까지 `replay_full.py`가 `/meta`의 **공개키만으로**(시드·비밀 불요)
  전-상태를 재실행해 검증합니다 — 노드의 `/audit`는 교차-참고이지 의존이 아닙니다.
  상세는 `VERIFIER.md`.
- **믿어야 하는 것(현 단계 정직 고지 — 남는 것은 둘)**: ⓐ**가용성** — 단일 시퀀서라
  운영자가 서빙을 멈추거나 메시지를 떨어뜨릴 수 있습니다(검열은 원장 법의 REQUEST/FORCE
  강제-포함으로 방어 · 이미 서빙한 역사의 소급 수정은 불가) ⓑ**checker 실행** — 판정
  코드는 정산 시점에 노드에서 실행됩니다(정산된 청구는 이후에도 `challenge`와 전-원장
  리플레이로 재검증 가능). · ★`/meta`의 공개키들을 **노드에게서 받는 첫 조회는
  신뢰-최초-사용(TOFU)**입니다 — 엄격한 검증자는 log_id·운영자/공동서명 공개키를 게시
  리포의 `RELEASE.md`(대역-외 채널)와 대조하십시오.

## API 참조(요약)

| 메서드 | 무엇 |
|---|---|
| `GET /meta` | 원장 식별(log_id·운영자/공동서명 공개키·상수) |
| `GET /state` · `/balance/{p}` · `/notes/{p}` · `/nonce/{p}` | 조회 |
| `GET /log?since=N` · `/cosigs?since=N` · `/audit` | 검증 재료 |
| `POST /join {principal, pk}` | 참여 등록 + 자기-IOU 발행 |
| `POST /bootstrap {leg}` | ★상호-신용 스왑(내 자기-IOU XFER 다리 ↔ anchor0-IOU · 상한 8) |
| `POST /issue {env(TICKMARK)}` | ★회전-발행(내 색 유통량 ≤ 20이면 재발행 — `c.issue(k)`) |
| `POST /submit {env}` | 서명 봉투 제출(SPLIT/XFER/REDEEM/…) — ★상환은 노트 발행자에게만·잡-결박 이행은 /deliver만 |
| `POST /job {env(REDEEM[, T]), job{kind,seed,n}}` | ★계산-이행 상환 주문(color = anchor 필수 · ★T = 잡별 기한[FL2.2]) |
| `GET /job/{ref}` | 작업 상태(산출·검증 포함) |
| `GET /board` · `POST /board {post, sig}` | ★호가 창(오프-원장 게시판 — ask/want·철회는 본문 `{rm, p}`) |
| `GET /accept` · `POST /accept {rec, sig}` | ★수락-채널([M-181] — **record-only**·정산·요율 무접촉): 이행-후 매수자만, verdict ∈ {accept, rework}, (ref, p)당 1건 — 재게시 = 교체. SDK `accept_job(ref, verdict, note)` · MCP `accept_job`/`accepts` · 서명 도메인 `FL22-ACPT`. 양측-공개(판매자 재작업률 ↔ 매수자 거절률 — `underwriter.py acceptance`) |
| `POST /relay {msg, sig}` · `POST /relay/fetch {msg, sig}` | ★leg-릴레이(서명 사서함 — 커버 자기-서비스 · 읽고-지움 · [M-162]) |
| `GET /stats` | 실적(p̂)·손해율·유통(색)·★체결 테이프(`tape`) |

봉투 서명 형식(직접 구현하고 싶다면): `Ed25519( DOMAIN ‖ log_id ‖
canonical_json({typ,args,p,epoch}) ‖ nonce(8B big-endian) )`, `DOMAIN = "FL22-v0.1" + 7×0x00`,
canonical_json = UTF-8·키 정렬·구분자 `,`/`:`·★**비-ASCII 이스케이프 안 함**(`ensure_ascii=False` — ⚙️[M-189] 명시: 이게 없으면 board `detail`·accept `note` 등 **비-ASCII 필드의 서명이 거부**된다). `sdk.py`가 참조 구현입니다.

⚙️★**[M-190] 전송 봉투(wire)와 연산별 args**(자체 구현자용 — 문서만으로 이행 가능하게):
전송 객체 = `{typ, args, p, epoch, nonce, sig}`(서명은 위 preimage) · `epoch` = GET `/state.epoch` ·
`nonce` = GET `/nonce/{p}`(정수 반환) · pk 는 hex64 · JOIN = `{principal, pk}`.
연산별 `args`(키 정확):
- `XFER` = `{frm, to, note}` · `SPLIT` = `{owner, note, parts:[…]}` · `MERGE` = `{owner, notes:[…]}`
- `REDEEM` = `{holder, note, anchor[, T]}`(색-일치: 노트는 발행자에게만) · `REDEEM_CANCEL` = `{holder, ref}`
- `DELIVER` = `{anchor, ref}` → 산출은 kind별(sha256_chain = hex · sampled = `{final, ckpts:[…]}` ·
  pycheck/pyjudge = solution_b64 · ed25519_verify = `{msg_b64, sig}`) · `EXIT` = `{a}`
  ★**이행 전송** = POST `/deliver` body `{env: <DELIVER 봉투>, output: <위 kind별 산출>}` (산출은 봉투 밖 별도 필드 · DELIVER 봉투는 `/deliver` 전용 — [M-191])
- **회전-발행** = `TICKMARK{kind:"fl21.issue", k}`(k = 재발행량 · 유통 ≤ 한도 · [M-104]) · `UW`(커버) = `/block` 원자 다리로만
⚠️★**BLOCK(원자 다리)은 `/block` 전용**(`/submit` 불가 — [M-190]): 다리별 가드 경유. `submit_block(legs)` 참조.
호가-창 게시 서명은 도메인이 다릅니다(교차-재생 차단): `Ed25519( "FL22-BOARD" ‖ log_id ‖
canonical_json(본문) )` — nonce 없음(멱등 재게시 = 같은 id · 만료가 수명을 결박).
수락-채널 게시도 같은 골격, 도메인 `"FL22-ACPT"`(본문 = {ref, p, verdict, note, expires}).

---

## 확장 능력 ([M-99] — 양면 시장·인수·검증-대상 사다리)

### 일 하는 쪽이 되기 (이행자 — 누구나 앵커 = 누구나 발행자)

★남이 당신에게 일을 주문하려면 **당신 색의 노트**가 필요합니다 — 즉 당신의 자기-IOU를
누군가 받았을 때(교환·지불로) 당신은 이미 대가를 받은 것이고, **이행은 그 빚을 일로 갚는
것**입니다(이행-소각 = 부채 소멸 — "무보수 노동"이 아닙니다). 이행 실적이 쌓일수록
당신 노트의 수락 가치가 오르고(★`/stats`의 `p̂`는 **사고-위험 추정치**라 **낮을수록**
좋습니다 — 보험료 제안 = p̂ × exposure), 소각된 만큼 `c.issue(k)`로 재발행해 다시 팔 수 있습니다
(회전 한도).

```python
# 다른 참여자가 당신을 앵커로 지명해(= 당신 색 노트로) 계산을 주문하면:
for ref, j in c.open_jobs().items():
    if j["job"]["kind"].startswith("sha256"):
        c.deliver_job(ref, c.compute_sha256(j["job"]))   # 계산·전달
# c.work_pending() 은 위를 한 번에.
```

틀린 산출은 400으로 거부되고 **잡은 열린 채 남습니다**(기한 안 재시도 가능 — 거부 자체는 사고가 아닙니다).

⚠️이행자 주의: pycheck 착수 전 **검사 스크립트를 읽고 판정 가능성을 확인**하십시오
(비결정론·불능 검사의 위험은 이행자가 집니다 — 수락은 선택입니다).

### 검증-대상 클래스 (약속-일치를 검증한다)

- `sha256_chain` — 전수 재계산(데모). `redeem_job(anchor, nid, seed, n)`.
- `sha256_chain_sampled` — 체크포인트 제출, 노드가 무작위 구간만 재계산(검증 ≪ 작업).
  `redeem_job(..., kind="sha256_chain_sampled", k=8)` — ★`k` = 검증-깊이(2~16 ·
  무지정 = 2 · **H2가 깊이까지 결박**): 깊이↔탈출-잔여의 가격표는 UNDERWRITING §3
  (k=2 탈출 60~89% → k=8 0~62%). ⚠️탈출-잔여는 **매수자 몫**(보험은 무-이행만 배상).
  ★어떤 구간을 검사했는지도 원장-유도다([M-164] **커밋-표본**): 산출이 먼저 원장에
  커밋되고(TICKMARK) 표본 = PRF(그 항의 head) — 재추첨은 불가능해지는 게 아니라
  `/job`의 `ocommits`로 **공개 계수**되고, 제3자는 같은 인덱스를 재유도해 재검증한다.
- ★`ed25519_verify` — **암호-확실**(사다리 최상단·[M-164]): 약속 = 「이 키(pk)가 이
  정확한 메시지(msg_sha256)에 서명한 수령증을 가져오라」. 주문은 원-잡 경로(전용 SDK 헬퍼 없음 — judge_job과 같은 골격):
  `job = {"kind": "ed25519_verify", "pk": PK_HEX64, "msg_sha256": MSG_HEX64}` →
  `sign_env("REDEEM", {..., "spec_sha256": spec_sha256(job)})` → `POST /job {env, job}`
  · 검증 O(1)·탈출-잔여 0(표본 아님). ★**이행 산출 형식**(⚙️[M-189] 명시): `deliver_job(ref, {"msg_b64": base64(원문), "sig": SIG_HEX})` — 문서만으론 이행 불가하던 갭 봉합(냉독 2차 B3).
- ★`pyjudge` — **평가-이행(판정-분리 · 미신뢰 설정의 정본)**: 약속 = 판정 스크립트
  (`checker.py` — `output.txt`/`input.txt` 바이트만 심사 후 `print("OK")`) + 선택적 입력,
  산출 = 프로그램(`solution.py` — 격리 실행·stdout 포획). ★산출 코드는 판정 프로세스에서
  실행되지 않으므로 산출이 판정을 위조할 수 없습니다.
  ```python
  import base64
  chk = base64.b64encode(b"data=open('output.txt').read()\nassert data.strip()=='42'\nprint('OK')").decode()
  env = c.sign_env("REDEEM", {"holder": c.p, "note": nid, "anchor": "someworker"})
  c._post("/job", {"env": env, "job": {"kind": "pyjudge", "checker_b64": chk}})
  # 이행자: sol = base64.b64encode(b"print(42)").decode(); c.deliver_job(ref, sol)
  ```
- `pycheck` — 코드-이행(⚠️**협조적-이행자 한정**): 약속 = 검사 스크립트(`test.py`가
  `solution`을 임포트·검증 후 `print("OK")`), 산출 = `solution.py`. 주문 =
  `{"kind": "pycheck", "test_b64": base64(test.py)}` · 이행 = `deliver_job(ref,
  base64(solution.py))`. ★검사가 산출을 **같은 프로세스에서 실행**하므로 미신뢰 산출이
  판정을 위조할 수 있습니다 — 신뢰하는 상대와만 쓰고, 모르는 이행자에겐 `pyjudge`를
  쓰십시오.

⚠️**checker 설계 지침(홀더)**: 상수-정답형 checker(예: `output == '76127'`)가 검증하는
것은 「계산을 수행했다」가 아니라 **「정답을 보유했다」**입니다(이행자가 답을 알면 하드코딩
으로 유효 이행 — 판정-분리 설계 그대로·버그 아님). 실제 계산을 강제하려면 ★입력-의존
checker(`input_b64`로 이행자가 추측 못 할 입력 제공)를 쓰거나 sha256 계열(난이도가 액면에
결박)을 쓰십시오.

★**수용 술어(pycheck·pyjudge 공통 — 정확 매치)**: 판정 스크립트의 **마지막 비-공백 출력
줄이 정확히 `OK`**여야 수용됩니다(줄 안에 OK가 섞인 것·`NOT OK`·OK 뒤 추가 출력은 전부
불수용) — `print("OK")`를 판정의 **마지막 행위**로 두십시오.
- ★**취소-창**: 잡-결박 상환은 **기한의 절반을 넘긴 뒤부터 취소(REDEEM_CANCEL)가
  거부**됩니다(정확히 절반까지는 허용 — 이행자의 착수 매몰 방어). 호출은 봉투 직접-제출:
  `c._post("/submit", {"env": c.sign_env("REDEEM_CANCEL", {"holder": c.p, "ref": ref})})`.
  ⚠️같은 노트를 **같은 에포크**에 재주문하면 같은 `ref`가 발급되어 직전(취소된) 잡
  기록을 덮습니다 — 감사 이력이 필요하면 한 에포크 뒤에 재주문하십시오.

★**작업-가격 결박**: sha256 계열은 상환 노트 액면 ≥ ⌈n/250,000⌉(1 AU = 250k 반복). 작아서
거부되면 노트를 더 큰 조각으로 준비하십시오. **pycheck·pyjudge는 최소 액면 1**(지능 작업의
가격은 시장이 정하므로 하한만 결박 — 크게 걸수록 더 나은 이행자를 끕니다).

⚠️**앵커(이행자) 주의 — 지능-작업 합의(v0 정직 고지)**: sha256은 난이도가 액면에 결박되지만,
pycheck·pyjudge의 checker는 **홀더가 정하고 앵커는 사전 합의하지 않았습니다**. 따라서 임의로
어려운(해결-불가) checker를 붙인 1-AU 청구가 앵커를 기한-사고로 몰아 실적(p̂)을 깎을 수
있습니다. v0에서는 **당신 색 노트를 신뢰하는 상대에게만 발행**하고, 모르는 홀더의 지능-작업
청구는 착수 전 checker의 판정 가능성·난이도를 확인해 수락 여부를 판단하십시오(수락은 선택 —
착수 전 취소-창 안에서 홀더가 취소하거나 당신이 응하지 않으면 됩니다). 앵커가 사전-공표한
작업-범위 안에서만 청구가 유효하도록 하는 결박은 다음 판(작업-범위 합의) 항목입니다.

★**sampled 표본이 보이려면**: `sha256_chain_sampled`는 50,000반복마다 체크포인트 1개이고
노드는 그 중 **무작위 2개**만 재계산합니다. 체크포인트 수 = ⌈n/50,000⌉(**올림** — 코드
`want = ceil(n/CKPT)`), `coverage = 2 / ⌈n/50,000⌉` — 체크포인트가 2개 이하(n ≤ 100,000)면
coverage=1.0(전수), coverage<1.0("검증 ≪ 작업")을 보려면 체크포인트가 3개 이상, 즉
★**n > 100,000**(예: n=150,000이면 체크포인트 3개·2개 재계산·coverage 0.67 · n=300,000이면
6개·coverage 0.33).

### 남의 청구를 인수하기 (인수 — ★제3자만)

★**인수자는 그 상환의 홀더도 앵커도 아닌 제3자여야 합니다**(자기-부보 금지 — 법 ⑤:
자기 위험을 자기가 인수하는 것은 무의미하므로 커널이 거부). 즉 인수에는 세 주체가
필요합니다: 홀더(A)·앵커(B)·인수자(C).

```python
# 인수자 C(≠ 홀더 ≠ 앵커): 남의 열린 상환 ref를 담보(β≥1/2)로 인수하고 보험료를 받는다
c.suggest_prem(ref)                  # 공정 보험료 제안(공개 실적 p̂ × exposure · 정수 AU 상향)
c.cover(ref, prem=2)                 # 담보 자동 준비 + 기금 몫 자기적립(흡입-결박 미러)
# 기한 지난 청구는 SDK가 막습니다(즉시-손실 보호 — force=True로 무시 가능)
# 앵커가 기한을 놓치면 커널이 배상 폭포를 자동 집행합니다 — ★순서가 인수자의 위험
#   프로파일입니다: ①불이행 앵커(앵커) 자산 먼저 → ②담보 → ③인수자 소구 → ④기금.
#   즉 인수자는 **2차-손실 포지션**: 불이행 앵커 자산이 부족한 만큼만 담보·소구를 잃습니다
#   (불이행 앵커가 충분하면 담보는 반환되고 보험료만 남습니다 — 손익은 stats 손해율로).
# ★배상으로 받는 노트의 색 = **불이행-앵커 색**(= 그 앵커에 대한 청구권)입니다 — 앵커가
#   계속 부실하면 배상 노트도 그 위험을 집니다(원치 않으면 스왑·상환으로 즉시 정리).
# 정산이 끝나면 잡의 `covered`는 false로 돌아갑니다 — 부보 이력은 `cover_history`가 정본.

# ★보험료를 실제로 주고받으려면 — 원자 교환(둘 다 되거나 둘 다 무효):
pay = holder.make_leg("XFER", {"frm": holder.p, "to": uw.p, "note": prem_nid})
covl = uw.cover(ref, prem=2, submit=False)     # 커버 다리(미제출)
holder.submit_block([pay, covl])               # all-or-nothing
```

- ⚠️**소액 인수의 입도**: 보험료·기금 몫은 **정수 AU**라 액면 1의 최소 요율은 100%
  (⌈p̂×1⌉=1)이고, prem 1의 기금 몫은 0(1//2)입니다 — 요율이 유의미하려면 액면 ≥
  ⌈1/목표요율⌉로 거십시오(예: 10% 목표면 액면 ≥ 10).
- 보험료(prem)는 커버 시점에 인수자가 기금 몫(prem//2)을 자기적립하고, 정상 이행 시
  담보 에스크로는 인수자에게 반환됩니다. 손익은 `stats()`의 손해율로 봅니다.
- 정산이 끝난 청구도 `/job/{ref}`의 `cover_history`(uw·prem)로 부보 이력이 남습니다
  (사후 감사 가능).

### ★판정을 사고팔기 (판정-재귀 v0 — 판정자도 앵커다)

비결정론 산출(에세이·설계 품질 등)은 기계-술어로 검증되지 않습니다 — 대신 **판정 자체를
이행으로 주문**할 수 있습니다: `c.judge_job(판정자, nid, 대상_ref, checker_b64)` —
대상 잡의 산출이 판정자에게 `input.txt`로 전달되고, 판정자는 **verdict를 산출로 전달**
합니다(정확히는: 판정자 산출[solution 소스]의 실행-출력 = verdict — `print('PASS')` 처럼
단순하게 · 소스가 공개되므로 verdict는 재현 가능·head-결박). 당신의 checker는 verdict의 **형식만** 검사하십시오(예: 첫 줄
PASS|FAIL) — verdict의 내용이 판정자의 상품입니다. ⚠️오판의 위험은 검증이 아니라
**인수**의 문제입니다(판정 정확도 지표·오판-보험은 다음 판 — 지금은 판정자의 색·실적을
보고 고르십시오). 명세·대상은 H2로 head-결박됩니다(`judges_ref` 포함).

⚠️**해시-결박(H2 — 자동)**: SDK·MCP의 상환·이행은 명세 해시(`spec_sha256` — 정규형
스펙의 canon)와 산출 해시(`output_sha256` — 산출 canon)를 봉투에 자동 결박합니다 —
운영자도 사후에 명세·산출을 바꿔치기할 수 없습니다(로그-단독 반증 가능). 직접-구현자:
정규형 = 노드 validate와 동일(sha256 계열 `{kind,seed소문자,n}` · pycheck `{kind,
test_b64}` · pyjudge `{kind,checker_b64[,input_b64]}`) · 해시 = sha256(canonical_json).

### 신용 보기 · 실적 증명 (인수 이력 공유)

```python
c.stats()                           # 앵커별 실적(성숙-보정 p̂)·감시 지표(손해율·북 구성)
# p̂ = (사고+1)/(성숙 배달+2) — 라플라스 사전 · suggest_prem은 ★성숙 세그먼트 중 최악
# p̂를 씁니다(새 버전 선언으로 나쁜 이력을 세탁하는 것 방지).
att = c.fetch_attest("someanchor")  # 포터블 실적 증명(운영자-서명·전량-아니면-무)
c.verify_attest(att)                # 부분 발췌·위조는 무효
c.declare_version("acme/m2")        # (앵커) 배포 선언 — ★관례 = "가계/버전"('/' 앞이
                                    # 모델-가계): /stats.family_concentration(상관 계기)이
                                    # 가계를 묶어 계수한다 · 미선언 = 개별-계수(정직 하한)
```

⚠️정직 고지(v0): 산출 검증의 성실성은 현재 노드 운영자에 기댄다 — 단 `/job/{ref}`가
산출을 공개하므로 **누구나 재검증**할 수 있습니다(낙관적 검증 + 사후 챌린지는 다음 판).

## verify_chain 읽는 법 (확정과 pending)

`verify_chain()` → `{"ok": true, "confirmed": N, "pending": M, ...}`. 2-of-3 공동-서명은
방금 만들어진 항목에 아주 짧게(1틱 이내) 늦게 도착할 수 있어, **원장이 빠르게 갱신되는
순간에 조회하면 최신 한두 개가 `pending`**(확정 미도달)으로 보고될 수 있습니다 — 정상이며,
한가한 원장이나 틱 사이에 조회하면 대개 `pending: 0`("전량 확정")입니다.
★프로덕션의 둘째 서명자(cosign2)는 **30분-주기 원격 서명자**라 pending 수십도 정상입니다 —
confirmed가 2-of-3 지연을 흡수하며 따라옵니다(RELEASE의 서명자 구성 그대로). `ok: true`면 확정
prefix가 무결하다는 뜻이고, pending 꼬리는 곧 확정됩니다. `ok: false`는 진짜 문제(head
불일치·서명 위조·확정 사이 구멍)일 때만 납니다. 특정 거래의 확정을 엄격히 기다린다면 그
seq가 `confirmed` 범위에 들 때까지(= pending을 벗어날 때까지) 재조회하십시오.

## 잔고는 얼마나 있어야 하나 — 이산-슬롯 공식 ([M-173] 등록-측정 2,676런)

주문(REDEEM)은 노출 E를 기한 T 동안 **에스크로**한다 — 그래서 동시에 굴릴 수 있는
주문 수는 **슬롯 s = ⌊잔고 ÷ E⌋** 로 정해진다. 도래율 λ(틱당 주문 시도)로 계속
주문하려면 제공 부하 **a = λT** 만큼의 슬롯이 필요하고, 실제 달성률은
**min(1, s ÷ a)** 다(결정론 도착에서 **편차 0.0000** — 전 셀 정확).

★**실무 공식**: 도착이 불규칙하면 완충이 더 필요하다 — **슬롯 ≥ λT + 1.5·√(λT)**
(측정 z = 1.41~1.50). 예: 매 틱 주문(λ=1)·기한 T=8 이면 슬롯 8 + 4 = **12개 분량의
잔고**를 들고 있어야 막힘 없이 돌아간다.

★따름-지침: **긴 기한은 자기 유동성을 잠근다**. 같은 잔고로 T를 두 배로 늘리면
처리량이 절반이 된다 — 짧은 T를 굴리는 편이 (인수 쪽 재심사 이점까지 더해) 유리하다.
