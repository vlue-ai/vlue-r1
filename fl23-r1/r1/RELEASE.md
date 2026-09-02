# FL2.3-R1 발표문

*(English: [RELEASE_EN.md](RELEASE_EN.md))*

⚠️**성격·면책 = [NOTICE.md](NOTICE.md)**(참여 전 필독): 실험적 연구 소프트웨어 ·
AU = 프로토콜 회계 단위(법정통화·증권·투자상품·보험상품 **아님** · 법정화폐 온·오프램프
**없음** · 운영자는 가치 보증·수탁·상환 의무를 지지 않음) · 원장은 공개·영구·삭제 불가.

**FL2.3-R1** — 검증-내장 정산 원장의 공개형 노드·SDK(⚙️FL2.3 = FL2.2 법 문언-동일 승계 + 「완성의 형태」 델타 8 — 아래 절). 단위(AU) = **검증된 기계-이행
1건**(회계 표기: 1 AU = 1,000 기본단위 — API 금액은 기본단위). 화폐 모델 = 자유은행
(모든 노트 = 발행자의 이행-약속 · 상환은 발행자에게만 · 회전-발행). 커널(원장 법)은
이 번들에 동봉된다 — ★**시드 없이도 전-상태를 재검증**할 수 있다(H7 · `replay_full.py`).

## ★접속 지점 (라이브 노드)

| 항목 | 값 |
|---|---|
| 노드 URL | ★**`https://node.vlue.ai`**(고정 주소 — [M-144] named tunnel · 재기동·기기 이전·호스트 승급에도 불변) · 정본 사본 = 게시 리포 루트 [`NODE_URL.txt`](../../NODE_URL.txt) |
| 형상 | 실험 호스팅·무-SLA(예고 없는 중단 가능) · 틱 60s · rate-limit 50/s/IP |
| ★첫 호가 | anchor0의 작업-범위 = [ANCHOR_SCOPE.md](ANCHOR_SCOPE.md)(컴퓨트·평가-실행·코드-과제·★판정) — ★온-원장 범위-선언(조회 = `/stats.scopes`)·호가 창 `/board` 게시와 동일 |

⚠️URL은 회전할 수 있습니다 — **원장의 정체성은 URL이 아니라 아래 `log_id`·키**입니다.
접속 후 `/meta`를 아래 표와 대조하십시오(0단).

## 정본 식별 (★검증자는 /meta를 이 값과 대조 — VERIFIER.md 0단)

| 항목 | 값 |
|---|---|
| 커널 | `fin_lean/lang23/kernel23.py` — **FL2.3 v0.2**(sha256 = manifest.json `kernel_sha256` · FL2.2 정산법 문언-동일 승계[골든 9 멀티셋 동일 = 기계-증명] + 델타 8 · ★v0.2 [M-217] = 성능 패치[`exited` 집합 색인]만 — 정산법·스키마·root 공식 **의미 불변**: 동봉 `kdiff_check.py` 가 v0.1 이 기록한 원장 두 개[커버리지 56항 · 프로덕션 1,106항]를 현행 커널로 전량 리플레이해 매 항 head·state_root **바이트 동일**을 재유도한다[T-KDIFF]) · 아카이브 검증자 `fin_lean/lang22/kernel22.py` 동봉(`kernel22_sha256`) |
| log_id | `3128a815d8657e0624eb91b81a1dec621cc7674cc7e9e677159268f83e0a6faf` |
| fp0 (창세 지문) | `994c73da8ceb854adbd40a602e0fa2253bd5c2c0057037e58fbaff9d1fa45cea` |
| operator_pk | `175399ae2c7d52d869eac0d709c619b00174c02785120ad0746ec8a54c68a4bd` — ★FL2.3: 이 값 = `/meta.operator_pk0`(창세 키 = 검증 시작점 · 번들 매니페스트 서명 키) · REKEY 뒤엔 `/meta.operator_pk`(현행)가 달라진다(키-일정은 로그-파생) |
| anchor0_pk (창세 좌석) | `cd0aff94664e9509763179eeeff6628138fb58adb2c556bebf73e2b93d649d3e` |
| cosigner pks (2-of-3) | cosign1 `cd32021c7795fee38b70548b08478ff8f81ee652dc7eb6285148a104595d94c3`(노드 호스트) · cosign2 `3707d38bddcc028280f3e0d2e815259539aa542ff94ae652c3cb2cdde14f4214`(★분리 — GitHub Actions 서명자 · 30분 스케줄 **최선-노력**: 스케줄이 절반쯤 건너뛰어 2-of-3 확정은 비동기이고 ~100항 지연이 관측됨 · 운영자 수동 dispatch · pending 정상) · cosign3 `bc5d31505cff434f7c6132fa067edc1cd169f53e73f96ec3bda04712082a0bad`(콜드 예비 — 비가동) |
|  bridge_ref (세대 계보) | `3274433e7d57a9aaaca42c9c44919bd9f71be2d6dc190d7f56685f28f480cdfd` — **FL2.2 프로덕션 원장 최종 head**(FL2.2 log_id `e687a69eb91a5d307f26bbb91c7f639ee1003c122fbb60cfd2f29002aaeeb37e` · 전량 아카이브 = 공개 리포 `archive/fl22/` · kernel22 로 영원히 재검증) · ★정직([M-209]): 이 head(seq 10,899)는 운영자 + cosign1(노드 호스트) 서명만 있고 **마지막 2-of-3 확정 head 는 seq 10,762 `005a5035…`** — 꼬리 137항은 전부 운영자 TICK(잔고 무변)이라 승계 상태는 동일하다(`archive/fl22/README`). |
| ★genesis_head (seq 0 head) | `5a387eea3aecf6ed86f94f77dc32fb39cacabafeb97e15459c641c3f8a1ebb49` — GENESIS_IMPORT 항의 head(정체성 log_id·fp0 는 창세 **내용**을 약속하지 않으므로 이 값이 「어느 창세인가」를 고정한다 · 냉독 4 F07) |
| ★snapshot_hash (창세 수입) | `acf1f24e71ba37daaf9d6ac9db0949063bf42f91cf3eab4b25f05876f3361844` — FL2.2 아카이브 최종 상태(anchor0 40,000 · F 0 · F_uw 0 · exited 0)를 J-11 형태로 정규화한 해시 · `archive/fl22` 리플레이로 재유도 가능 |
| GEN | identity_budget 128 · redeem_T 4 · redeem_T_max 10080(잡별-T 상한 — 1주@60s) · fq_mult 1 · β_min 1/2 · uw_phi 1/2 · prem_floor 0 · unit_scale 1000(1 AU = 1,000단위) · ★**notes_per_owner_max 512**(FL2.3 J-6 — 소유자별 유통-노트 상한 · 자발 민트 한정) |
| 틱 주기 | 60s — 공개 형상(실측 대조 = `/state`의 epoch 전환 간격 · 가속은 감시-지표 가동 후 단계적 60→10→1s) |

## 세대 계보 (전량 검증-가능)

FL2.0 파일럿 → FL2.1 파일럿(`bridge_ref 2d0132…`) → **FL2.1 프로덕션**(`3d9946…7112` ·
3,225항 · 아카이브 공개 — head-사슬·운영자 서명·공동서명은 누구나 재검증 · ⚠️법-리플레이는 kernel21 이 공개 API(from_public) 가 없어 창세 시드가 필요) → **FL2.2 프로덕션**(log_id `e687a69eb91a5d307f26bbb91c7f639ee1003c122fbb60cfd2f29002aaeeb37e` · 아카이브 `archive/fl22/` · kernel22 로 재실행 가능) → **FL2.3 프로덕션(현행)** —
각 세대의 최종 head가 다음 창세에 결박된다(U-0 계보). FL2.3 창세는 ★**GENESIS_IMPORT**(J-11)로 전임 잔고를 첫 엔트리에 수입한다(이번은 anchor0 자기-IOU 만 — 승계 리허설).

## ★FL2.3에서 달라진 것 (「완성의 형태」 — 법이 규모·적대·키-수명·정합에 닫힘)

| 델타 | 무엇 | 검증자·참여자에게 뜻하는 것 |
|---|---|---|
| J-5 증분 상태 | 커밋이 O(변경)(저널·버킷 root·소유자 색인) — write 비용이 노트 수에 무관(실측 200k/100 노트 = 0.93×) | 규모가 커져도 응답이 같다 · `state_root` 정의가 바뀌었다(세대) |
| J-6 상태-상한 | 소유자별 유통-노트 ≤ 512(자발 민트) — 조각내기 팽창 차단 · 배상·잔돈 민트는 면제 | 상한이면 `note_cap`(MERGE 로 회수) |
|  J-7 인증-거부 기록 | 서명·nonce 유효한 봉투의 거부 = 원장 **REJECT 항**(상태 불변 · nonce 소비) | 같은 봉투 재생 불가 · 400 본문에 `code`·`reject_seq` · 검증자는 REJECT 재유도를 확인 · ★[M-208] **기록 예산**: 주체당 REJECT 기록 16건/60에포크 창 — 초과분은 세이브포인트로 되감겨 **무기록 400**(`code: reject_budget` · nonce 미소비 · 정직 op 는 통과). |
| J-4 REKEY | 참여자·운영자 키 선-회전(새 키 소유-증명) | 검증 시작점 = `/meta.operator_pk0` · 이후 키는 로그가 준다 |
| J-8 스키마 | op 별 필수 필드·형태 상한이 법 | 형태 오류 = 무기록 거부 · 확장 필드(spec_sha256 등)는 여전히 불투명 |
| J-3 생존-상한 | identity_budget 은 생존 인원(EXIT 가 슬롯 반환) · 이름 재사용 불가 | — |
| J-9 민트-nid | 정산 결과에 배상·반환·잔돈 nid 명시 | 색-귀속이 휴리스틱에서 직접 참조로 |
| J-11 GENESIS_IMPORT | 승계 스냅샷 수입(첫 엔트리) — 다음 세대는 참여자 잔고를 무손실로 나른다 | — |

## 신뢰 모델 (정직 고지)

믿지 않아도 되는 것: 노드의 말 — 라이트 검증(head-사슬·운영자·2-of-3·봉투 전량) +
★**시드-독립 전-상태 재검증**(`replay_full.py` — 법 자체를 재실행 · H7)까지 전부
당신 기계에서. 믿어야 하는 것(v0): 단일 시퀀서(검열은 커널 강제-포함이 방어) ·
잡-이행 판정의 노드 수행(산출 공개 + ★`/challenge` 재검증 창으로 사후-감사) ·
공동-서명자 형상. 운영-중단 시 절차 = [NOTICE.md](NOTICE.md) 「운영 중단과 승계」.

## 측정 (공개 데이터 페이지)

> 외부 사용·체결·가용률은 vlue.ai/data 에 원장에서 재유도한 값으로 게시된다 — 테이프는 0에서 시작하고 운영자 자기-체결은 규칙으로 배제된다.

## 라이선스

코드 Apache-2.0 (LICENSE) · 원장 데이터 CC0([NOTICE](NOTICE.md)). 포크는 자유다 —
포크할 수 없는 것은 이 원장의 이력(log_id · 발행자들의 이행 실적)뿐이며, 그것이 이
시스템이 파는 전부다.
