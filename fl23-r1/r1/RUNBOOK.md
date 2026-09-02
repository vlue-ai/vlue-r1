# R1 운영 런북 (D-7 · [M-101~106])

## ★프로덕션 창세 의식 (D-3 — 한 번뿐 · GEN은 영구 불변)

```bash
python3 r1/node.py --data /var/fl21 --port 8788 \
  --bridge-ref 3274433e7d57a9aaaca42c9c44919bd9f71be2d6dc190d7f56685f28f480cdfd  # ★[M-209] 정본 = RELEASE bridge_ref(전임 세대 최종 head) — 예시는 FL2.2→FL2.3 값 \
  --auto-tick 60 --rate-limit 50
```

- `--bridge-ref` = FL2.1 파일럿 원장 최종 head(U-0 세대-계보 — RELEASE.md 정본).
- GEN(소스 상수 — [M-105] D-3): identity_budget **128** · fq_mult **1**(실측 n≤128→1) ·
  redeem_T 4. ⚠️창세 후 불변 — 규모-전이는 세대-전이.
- 첫 기동이 전 키 생성(운영자·앵커·공동서명 3 + cosign_pubs.json 고정) — 직후
  `/meta`의 log_id·fp0·공개키를 **RELEASE.md에 기입**(검증자 대역-외 대조점 = RV-4 닫기).

## ★공동-서명 분리 (D-2 — 공개 전 필수 · 동거 = 연극)

```bash
# 창세 의식 후: cosign2.key·cosign3.key를 별도 호스트로 **이동**(원본 삭제) → 노드 재기동
# ★공개 노드 = rate-limit 필수(D-6) · ★[M-188] H-1 재검증 유계화(verify-slots·challenge-budget) —
#   ⚠️한 명령이다(줄-연결 백슬래시 · 냉독 4 R4-6: 주석이 줄 끝에 있으면 복붙 시 아래 플래그가 떨어져 H-1 이 꺼진 채 뜬다)
python3 r1/node.py --data /var/fl21 --port 8788 --cosign-local cosign1 \
  --auto-tick 60 --rate-limit 50 --trust-forwarded \
  --verify-slots 2 --verify-wait 1 --challenge-budget 20 --challenge-window 60 \
  --notes-per-owner-max 512

⚠️★**플래그 둘은 「있으면 좋은 것」이 아니라 가드의 전제다**(⚙️[M-188] 적대 배터리 A-4·A-6이 실측으로 노출):
- **`--auto-tick`이 없으면 외부 `/tick`이 열린다**(SEC-1 가드는 `own_clock = auto_tick > 0`
  조건부 — 자기 시계가 없는 노드는 누군가 밀어야 하므로 **설계된 동작**이다). 공개 노드는
  반드시 켠다.
- **`--trust-forwarded`는 「유일 경로 = 신뢰 프록시」가 전제다** — 그 전제가 깨진 형상
  (직접 노출)에서 켜면 `X-Forwarded-For` 스푸핑이 유량 버킷을 무한 분할한다.
  프록시/터널 뒤가 아니면 **끈다**(배터리 대조군: 끄면 스푸핑 무효).
- ⟹ 단독 `docker run` 대신 **compose 형상**을 쓴다(플래그 누락 부류 예방).
# 각 서명자 호스트에서(★URL = TLS 프록시의 공개 주소 — 노드 기본 바인드는 127.0.0.1):
python3 r1/cosigner.py --url https://DOMAIN --name cosign2 --key cosign2.key --poll 5
python3 r1/cosigner.py --url https://DOMAIN --name cosign3 --key cosign3.key --poll 5
```

⚠️`--trust-forwarded`는 **TLS 프록시(D-5) 뒤 + 기본 바인드 127.0.0.1일 때만** — 노드에
직접 닿는 배치에서 켜면 X-Forwarded-For 위조로 rate-limit이 통째로 우회된다(프록시 없이
노출하는 데모·테스트는 이 플래그를 빼라).

비동기 서명은 verify_chain의 confirmation-depth(pending 꼬리)가 흡수 — 데몬이 죽어도
원장은 전진하고, 확정만 늦는다(외부 검증자는 pending으로 본다 · 데몬 재기동 시 자동 소급).

## ★틱 주기 = 밀도 사다리 (D-8 — 서킷브레이커 다이얼)

| 단 | --auto-tick | 실기한 | 위기 시계(60ep) | 개방 조건 |
|---|---|---|---|---|
| 공개 | **60** | 4분 | 1시간 | 즉시 |
| 2단 | 10 | 40s | 10분 | 밀도 추세 창(Δ거절률·Δ손해율) 가동 |
| 3단 | 1 | 4s | 1분 | R-DENSITY-ⓑ(틱-가속 붕괴 재현·경보 검증) 통과 |

통계는 에포크-네이티브 — 가속해도 기록 불변(실시간 해석만 변함).

## 기동·정지 (데모·개발)

```bash
python3 r1/node.py --data DIR --port 8788 --auto-tick 2
python3 r1/worker.py --url http://127.0.0.1:8788 --key DIR/anchor0.key
```

- `--bind 0.0.0.0`은 반드시 TLS 종단 프록시(nginx 등) 뒤에서만(D-5). 기본은 127.0.0.1.
- `--rate-limit N` = 초당/IP 상한(D-6 — 공개 시 필수 · 테스트는 0).
- `--auto-tick` = 에포크 주기(초) — ★상환 기한의 실시간 의미 = redeem_T(4) × 주기(D-8 ·
  사용자 결정 — ⚠️틱 = 배치-경매 구조가 서킷브레이커 역할이므로 과소 주기 금물
  [FREEBANK_ANALOGY §3]).
- `--join-issue N`(기본 20) = join당 자기-IOU 발행량 · `--genesis-issue N`(기본 40) =
  창세 앵커 자기-IOU(첫 기동 1회). ★[M-103] 화폐 모델: 색·발행자-상환·상호-신용 스왑
  (한도 BOOT_CAP=8 — 소스 상수). 색은 로그-파생이라 백업 대상 아님(리플레이가 재구성).
- 정지: SIGTERM/SIGKILL 모두 안전(A-3 — 기동 시 전체 리플레이·audit·색 재구성 · ⚙️FL2.3: REJECT 항 재유도 포함).
- ⚙️★**FL2.3 다이얼**: `--notes-per-owner-max N`(소유자별 유통-노트 상한 · 기본 GEN 512 · 0 = 끔 — 자발 민트 한정) ·
  `--genesis-import PATH`(첫 기동에서만 · 첫 엔트리 GENESIS_IMPORT = 승계 스냅샷 — 창세 자기-IOU 를 **대체**한다 · 절차 =
  `deploy/FL23_GENESIS.md`).
- ⚙️★**운영자 키 선-회전**(FL2.3 J-4): 노드 프로세스 안에서 `Node.rekey_operator()`(전역 락 · REKEY 제출 → 서명 키 교체 →
  `operator.key` 원자 기록) — 절차·한계 = `deploy/KEY_ROTATION.md §6′`. 재기동 시 `operator.key` 가 있으면 그 키로 서명한다
  (`node_secret` 은 창세 시드 — 불변). 검증자는 `/meta.operator_pk0` 에서 시작해 로그의 REKEY 로 키를 따라온다.
- ⚙️**400 본문**: `{error(한국어 법 문언), code(영문 안정 코드), reject_seq?}` — `reject_seq` 는 원장의 REJECT 항(인증-거부 기록).

## 비밀·키 (D-1 — 전부 data_dir · 0600 · 첫 기동 시 자동 생성)

| 파일 | 무엇 | 유출 시 |
|---|---|---|
| `node_secret` | 세계 마스터 시드(256b — 운영자·창세 키 파생) | ★치명 — 세계 재창설 필요 |
| `cosign{1,2,3}.key` | 공동-서명 독립 키(★D-2 — 2·3은 서명자 호스트로 이동) | 2개 유출 = k-of-n 붕괴 |
| `cosign_pubs.json` | 공동서명 공개키 전량(분리 후에도 노드가 검증용 보유) | (공개 정보) |
| `anchor0.key` | 워커 좌석 키 | 워커 사칭 |

★백업(둘 다 필요):
- **노드 호스트**: `entries.jsonl`·`cosigs.jsonl`·`jobs.json` + `node_secret`·`cosign1.key`·
  `cosign_pubs.json`·`anchor0.key`(node 정지 중 복사 권장 — ack=내구는 fsync가 보장하나
  백업은 정지-중 사본이 안전).
- ★**각 서명자 호스트**: `cosignN.key`와 그 `cosignN.key.state`(커서)를 **독립 백업** —
  ⚠️이 둘이 유실되면 2-of-3 확정이 영구 불능(신규 항목이 pending에 머문다 = 세계 사실상
  동결). D-2 분리의 SPOF다.

복구 = 각 호스트에서 사본 복원 후 기동(노드 자동 리플레이·audit · 서명자 데몬은 커서로
소급). ⚠️**재-창세/부분 복원 시 데몬 커서(.state)가 로그보다 앞서면** 신규 항목을 영구
건너뛴다 — 로그가 커서보다 짧으면 `.state`를 삭제(0부터 재-서명)하라.

## 장애 대응

- 기동 실패 "대장 리플레이 불일치/audit 실패" = 대장 손상 — 백업 복원(부분 손상 시 마지막
  정합 prefix까지 잘라도 리플레이는 서나 ⚠️그 뒤 거래는 유실 — 즉시 공지).
- 공동-서명 **유실**(크래시로 대장 뒤 서명이 안 써진 반쪽-영속) = ★재기동 시 자동 치유
  (노드가 결정론 재서명 — RD-1). 별도 조치 불요.
- `verify_chain` 외부 보고가 `ok:false`(구멍)이 **재기동 후에도** 남으면 = 공동-서명이
  유실이 아니라 **변조**(head 불일치 서명 — 치유 대상 아님) — cosigs 백업 대조·조사.
- pycheck 폭주 = rlimits(D-12 프로세스-수준)가 1차 방어 — 공개 전 컨테이너 격리 권고.

## 공개 전 체크리스트 ([R1_PROGRAM §5] · [M-106] 집행 후)

✅D-4(자유은행 (i)) · ✅D-3(GEN 128/fq1·bridge_ref — 위 창세 의식) · ✅D-2(서명 분리 —
위 절차·게이트 T-SPLITSIGN) · ✅D-8(60s 사다리) · ✅D-10(pyjudge 판정-분리·취소-창 —
pycheck는 협조적-이행자 한정) · ✅D-9 패키징(`package.py` — 번들 자립 자기-시험·manifest).
⛔공개 실행 = 사용자 재가: 창세 의식 → RELEASE.md 확정값 기입 → 번들 게시 → K5′ 개시
(3개월 AND-0 시계 — D-11). 운영 잔여 = D-5(TLS 프록시·도메인) · D-12(컨테이너 — pyjudge
후에도 침입-방어 몫).
