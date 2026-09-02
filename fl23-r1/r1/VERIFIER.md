# 독립 검증자 안내 — 누구 말도 믿지 않는 법

*(English: [VERIFIER_EN.md](VERIFIER_EN.md))*

이 번들만으로 원장의 모든 주장(잔고·이행·사고·통계)을 **여러분 기계에서** 재검증할 수
있습니다. 신뢰 사다리의 네 단(0~3단) — 위로 갈수록 신뢰가 줄어듭니다.

> ★[M-209] 0단 대조 항목 **확장**: `log_id`·`operator_pk0`·`cosigners` 에 더해 **`genesis_head`**(창세 **내용**을 고정하는 유일 값 — `/meta.genesis_head` = `/log?since=0` 첫 항 head = RELEASE 값) · `snapshot_hash` · `fp0` · `anchor0_pk` · `bridge_ref` 를 RELEASE 표와 대조하라. `verify_chain(expect_genesis_head=…)` · `replay_full.py --genesis-head …` 가 그 대조를 도구로 강제한다(같은 키·같은 log_id 로 다른 창세를 돌리는 운영자를 잡는 유일한 방법).

## 0단 — 대역-외 대조 (TOFU 제거 · 시작 전 필수)

`GET /meta`의 `log_id`·`operator_pk`·`cosigners` 공개키 **와 `genesis_head`**(수입 창세면 `snapshot_hash` 도)를 **공개 발표문**(이 번들의
`r1/RELEASE.md` — 게시 후에는 공개 발표 채널의 사본과 대조)의
값과 대조하십시오. 노드가 주는 첫 키를 그냥 믿으면(신뢰-최초-사용) 악의 노드가 자기-정합
가짜 원장을 줄 수 있습니다 — 발표문 대조가 그 문을 닫습니다.
★**불일치가 나면**: 그 노드는 발표된 원장이 아니라 **다른 세계**입니다(테스트 인스턴스일
수도, 사칭일 수도) — 그 노드의 이력은 발표 원장에 대해 아무것도 증명하지 않습니다.

## 1단 — 라이트 검증 (SDK만 · 초 단위)

```python
from sdk import Fl21Client
c = Fl21Client(NODE_URL, "verifier", "verifier.key")
print(c.verify_chain())    # head 사슬 재계산 + 운영자 서명 + 공동-서명 2-of-3
# ★[M-213] 결과 읽기: `ok` 만 보지 말고 **`confirmed`**(2-of-3 확정 항 수 · 0 이면 `warning`) · `genesis_pin`("release"|"flag"|null) ·
#   `release_identity`("match" = 발표 원장 · "mismatch" = 다른 배포 · "conflict" = RELEASE 파일↔내장 핀 충돌 → sdk.py 갱신) · `pin_note` 를 읽는다.
# ★[M-210] 기본 핀: 노드가 이 번들 RELEASE 의 log_id 를 주장하면 genesis_head 를 RELEASE.md 와 자동 대조한다.
#   다른 배포를 검증하려면 expect_genesis_head=... 를 직접 넘긴다.
```

`ok:true` = 확정 prefix의 무결(변조·누락·구멍 검출). `pending` = 아직 공동-서명이 도착
안 한 최신 꼬리(정상 — 서명자가 분리 프로세스라 비동기).

## 2단 — 봉투 서명·법-형식 검증 (커널 공개본 · 부분 독립)

**도달 범위(정직)**: 이 단(라이트 검증)만으로는 **로그 무결·서명·법-형식**까지 독립
검증됩니다 — "파생 상태(잔고·에스크로)가 보존 법의 결과인가"(state_root의 법-준수)는
이 단의 밖입니다: 악의 노드가 보존 법을 깨는 state_root를 만들어 서명해도 라이트 검증
(해시-사슬+서명)은 통과합니다. ★그 간극은 아래 **H7 전-상태 공개 재검증**이 닫습니다
(FL2.2부터 — `/meta`의 **공개키만으로** 법 자체를 재실행 · master_seed 등 비밀 불요 · FL2.3은 REJECT 항·REKEY 키-일정까지 재유도). 즉
전-상태까지 확인하려면 라이트 검증에 더해 H7 리플레이를 실행하십시오.

외부에서 **독립 검증되는 것**(1단 verify_chain이 수행):
- 해시-사슬 무결(head_i = sha256(prev ‖ canon({env,fp,w_epoch,state_root}[+_force]))).
- 운영자 head 서명(모든 항목) + 공동-서명 2-of-3.
- ★**참여자 봉투 서명** — JOIN 항목이 각 주체의 공개키를 로그에 싣으므로, 모든
  XFER/REDEEM/UW/… 봉투의 서명을 그 공개키로 독립 검증 가능(누가 무엇을 서명했는가).
- 색(발행자) 재구성 — 규칙이 결정론·로그-파생이라 독립 재현 가능.
- 창세 지문 `fp0`를 발표문(RELEASE)의 값과 대조(0단).

(로그 어휘: `TICK` = 에포크 정산 사건 · `TICKMARK` = 서명 표지 · `EXT_IN` = 운영자-서명
유입 · `fp` = 상태 지문 · `w_epoch` = 세계 에포크 · `BLOCK` = 원자 다발[다리 각자 서명].)

커널·게이트를 스스로 실행해 "이 코드가 그 캐논"임을 확인하십시오:

(이 명령들은 `results/*.json`에 판정 기록을 씁니다 — 자기 사본에서 실행하십시오.)

```bash
python3 fin_lean/lang23/kernel23_selftest.py     # 셀프테스트 전량(승계 20 + FL2.3 신설 10 — 차등 폭풍 포함)
python3 fin_lean/lang23/frontier_vectors.py      # 골든 벡터(결정론 재현)
python3 fin_lean/lang23/golden_compare.py        # ★FL2.2 벡터와 정산-배분 멀티셋 동일 = 법 승계의 기계-증명
python3 r1/test_r1.py                            # 서비스층 수용 게이트 전량
# 아카이브(FL2.2 원장)는 동봉된 fin_lean/lang22/ 로 재검증한다 — replay_full.py 가 /meta.domain 으로 세대를 고른다
```

**★왜 판정이 0~100 점수가 아닌가(설계 근거 — [M-157])**: 에이전트-신뢰 표준들
(예: 온체인 Validation Registry 계열)은 검증을 **지목-검증자의 0~100 스칼라 응답**으로
기록하고 증거 URI는 선택이다. 이 원장은 그 형식을 **채택하지 않는다** — ⓐ스칼라는
판정 **근거를 세탁**한다(87점의 의미가 계약에 없음) ⓑ증거가 선택이면 신뢰뿌리가
검증자-평판으로 되돌아간다. 여기의 판정은 **통과/실패 + 증거 결박**(H2)이고, 그 판정
자체를 누구나 재실행으로 반증할 수 있다(H7·challenge) — 점수가 필요하면 원장-파생
실적(p̂·테이프)에서 **스스로 계산**하라(계산식이 당신 소유가 된다).
그럼에도 그 생태와의 **다리는 제공한다** — `erc8004_adapter.py`(★[M-159]): VLUE 노드를
ERC-8004 지목-검증자 뒤에 앉혀 이행-정산 → 100 · 시한-사고 → 0 · 미성숙 → 거부로
사상하고, responseURI 문서에 판정 근거 전문(attest·H7 포인터)을 **항상-첨부**한다
(keccak·ABI = 순수-stdlib 자기검증 · 온체인 송신은 운영자 몫).

## 남는 신뢰 가정 (정직 고지 — v0)

| 가정 | 내용 | 완화 |
|---|---|---|
| 단일 시퀀서 | 노드가 기입 순서를 정한다(검열은 커널 REQUEST/FORCE 강제-포함이 법엔 있으나 ⚠️r1 표면엔 아직 미배선 — 등재) | 로그 공개·서명 결박(재배열은 검출됨) |
| ★**포크(equivocation)** | 악의 노드가 같은 seq에 **서로 다른 두 갈래**를 만들어 검증자 A·B에게 각각 보이면, 각 갈래는 내부적으로 무결(해시·서명 정합)이라 **단일 검증자의 verify_chain은 이를 못 잡는다**. ⚠️공동-서명자(cosigner)는 head를 **재계산하지 않고 받은 head에 서명**하므로 두 갈래 모두에 서명한다 — 2-of-3이 보증하는 것은 「법 준수」가 아니라 **「그 head 바이트열에 대한 키들의 합의」**다 | ★**검증자 간 head 대조**(같은 seq의 head가 다르면 포크 확정 — 서명이 곧 증거) · 자기 head를 공개 게시(제3자 목격) · 근본 완화 = 다중 시퀀서·앵커 합의(R3 등재) |
| ★**상태-법 준수** | ✅**[FL2.2~] H7로 해소** — 시드-독립 전-상태 리플레이가 성립(`replay_full.py` — `/meta` 공개 재료만·비밀 불요 · 아래 H7 절). ⚠️남는 정직 한정어: **라이트 검증만 쓰는** 검증자에게는 여전히 밖이다(악의 노드의 법-위반 발행을 해시-사슬+서명만으로는 못 잡음) — 전-상태 확인은 신뢰 가정이 아니라 **실행할 일**이 됐다 | ★H7 리플레이 실행(수 초~수 분) · 노드 `/audit`는 교차-참고 |
| 산출 검증의 성실성 | 잡-경로 이행 판정은 노드가 수행. ✅**[M-121] H2 결박 실장**: 신규 항목부터 REDEEM에 `spec_sha256`(정규형 명세)·DELIVER에 `output_sha256`(산출 canon)이 **서명 head에 결박** — 운영자의 사후 명세·산출 위조가 로그-단독으로 반증 가능(⚠️결박-이전 구항목은 v0 시맨틱) | ★산출이 `/job/{ref}`로 공개 — 누구나 재검증 + 해시를 REDEEM/DELIVER의 head-결박 값과 대조(불일치 = 위조 증명) · ★[M-164] 표본-검증의 **무작위성 자체도 재검증 대상**이 됐다: 표본 = PRF(산출-커밋 항의 head ‖ ref) — 어떤 구간이 검사됐어야 하는지 로그만으로 재유도되고, 재추첨 시도는 `ocommits`로 공개 계수된다(무-흔적 재추첨 경로 봉쇄) | ★[M-208] 표본-검증(`sha256_chain_sampled`)의 **재추첨은 누적**된다 — 실패-이행 뒤 새 ocommit 은 검사 인덱스를 **더할 뿐**이라 재추첨으로 탈출 확률이 오르지 않는다(구판은 최신 표본만 검사 · 냉독 4 R4-3 수리 · 재추첨 수 = `/job.ocommits` 공개 계수). 유도식(공개 · `replay_full.py` 출력 `sample_union`): ref 의 모든 `fl21.ocommit` head h 에 대해 idx = sha256(h‖ref‖ctr) mod want 를 k개씩 뽑아 **합집합** — 검사된 `checked` 는 이 값이어야 한다.
| 공동-서명 2-of-3 | 서명자 키 분리는 운영 형상(cosigner 데몬 분리 배포 여부) | 발표문이 형상 명시 |


## ★FL2.3 에서 검증자가 더 보는 것 (J-7 · J-4 · J-11)

- **REJECT 항**(`kind: "REJECT"`): 서명·nonce 유효한 봉투의 법-거부 기록. head 는 `{env, fp, w_epoch, state_root, kind}` 결박 ·
  `state_root` 는 그 봉투가 **아무것도 바꾸지 않았음**(nonce 소비 제외)을 뜻한다 · `reason` 은 head 밖 정보 필드. 리플레이는 같은
  봉투를 커널에 넣어 **같은 거부가 재유도되는지**를 확인한다(수용되면 원장 위조). 운영자 좌석의 실패는 기록되지 않는다.
- **키-일정**: 운영자 head_sig 검증의 시작점은 `/meta.operator_pk0`(창세 키 · 불변). `REKEY` 항(p = operator)을 만나면 **그 항까지는
  구-키, 다음 항부터 신-키**. 참여자 봉투도 같다(JOIN·GENESIS_IMPORT 로 등록 → REKEY 로 교체). `sdk.verify_chain`·`replay_full.py`·
  `kernel23.replay_verify` 전부 이 규칙.
- ★[M-210] **약한 키**: 저-위수 Ed25519 점(항등점 등 — pyca 가 만능서명을 받아들이는 토션 점)을 등록하는 JOIN·REKEY·GENESIS_IMPORT 는
  노드가 거부하고, 서빙된 로그에 하나라도 나타나면 `sdk.verify_chain`·`replay_full.py` 는 fail-closed(`kernel23.replay_verify` 는 이 검사를
  하지 않는다 — 노드/검증기 층의 규칙).
- **GENESIS_IMPORT**(첫 엔트리): 승계 스냅샷(`principals·notes·F·F_uw·exited`) — `snapshot_hash` 가 args 에 결박되고 `ext_in =
  Σface + F + F_uw` 로 보존식이 선다. 노트의 `issuer` 는 색 시드(커널은 해석하지 않는다).
  ★레시피(J-11): `snapshot_hash = sha256(canonical_json({principals, notes, F, F_uw, exited}))` — `sort_keys=True` ·
  `separators=(",", ":")` · `ensure_ascii=False`. FL2.3 값 `acf1f24e…` 는 FL2.2 아카이브 최종 상태(anchor0 40,000 · F 0 · F_uw 0 · exited [])에서 재유도된다.
  ★[M-213] **검증 절차**(다음 세대부터 규범): ① 아카이브에 동봉된 `snapshot.json` 을 해시해 새 원장 seq 0 의 `snapshot_hash` 와 대조 ② 전임 원장을
  전-상태 리플레이해 **보존식 대조** — 소유자별 Σface · `F` · `F_uw` · `exited` · 레지스트리(창세 좌석 밖 주체 = `principals`, pk = 현행 키)가 스냅샷과
  같아야 한다 ③ `notes` 는 nid 오름차순 · `principals` 는 p 사전순(정렬이 다르면 다른 해시) · `issuer` = 전임 노드의 색 엔진이 기록한 색(아카이브 README 가
  색 파일을 동봉) · 소유자별 노트 > 512 이면 전임 세대에서 사전 MERGE(수입 민트는 J-6 상한을 따른다).
- **아카이브**: FL2.2 원장(`archive/fl22/`)은 `fin_lean/lang22/kernel22.py` 로 전-상태 리플레이 · FL2.1(`archive/fl21/`)은 head-사슬·서명 검증까지(kernel21 은 시드-무관 리플레이 API 가 없다 — 마지막 2-of-3 확정 seq 3,164 · 꼬리 60 TICK) — 세대는 `/meta.domain`(또는
  아카이브 meta)의 접두(`FL22-`/`FL23-`)로 고른다.

## ★전-상태 공개 재검증 (H7 — FL2.2부터 · 최상단 신뢰 단)

라이트 검증 위: 창세-시드 없이 **법 자체를 재실행**합니다 — /meta의 공개 재료(운영자·
창세 공개키·GEN·label·bridge_ref)만으로 검증-전용 세계를 만들고 로그 전량을 리플레이해
모든 상태 전이·정산 폭포·head 결박·운영자 서명을 재검증합니다(fp0·log_id 재유도 =
창세-무결 검사 겸):

```bash
python3 r1/replay_full.py --url https://NODE_URL          # ★[M-210] 노드가 RELEASE 의 log_id 를 주장하면 genesis_head 자동 핀
# 기대: {"H7_FULL_REPLAY": true, "identity_rederived": true, "genesis_pin": "release", ...} · 다른 배포: --genesis-head <값>
```
