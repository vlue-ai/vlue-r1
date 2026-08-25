# r1/ — FL2.1 공개형 제품층 (완성-국면 · [M-95~96])

**지위**: ★캐논 무접촉 — FROZEN 커널(`fin_lean/lang21/kernel21.py` v0.3)을 읽기-전용
임포트하는 서비스층(법 재구현 0 — 이원-기판 규율의 제품판). 헌장·수용 게이트 기록은
개발 저장소(비공개)의 R1_PROGRAM 문서이며, 게이트의 실측 판정은 `results/r1_gates.json`
과 `test_r1.py`(누구나 재실행 가능)가 정본이다.
★**화폐 모델 = 자유은행 v0**([M-103] — D-4 확정): 모든 노트에 발행자(색) · join =
자기-IOU 발행 · 상환 = 발행자에게만(색-일치) · 유입 = 상호-신용 스왑(/bootstrap) ·
배상 노트 = 가해-앵커 색. 유비 근거 = 자유은행 사료 연구(개발 저장소 — 비공개 ·
요지는 RELEASE·QUICKSTART의 화폐-모델 절에 자기완결로 서술).

| 파일 | 무엇 | 게이트 |
|---|---|---|
| `node.py` | HTTP 노드(제출·조회·audit·잡·틱·★호가 창 /board) · append-only 대장 + 기동 전체-리플레이 · 경계 예외-격리 · k-of-n 공동-서명 사이드카 | A-3·A-4·A-6 |
| `mcp_server.py` | ★에이전트-네이티브 정문 — 로컬 MCP 서버(도구 29·sdk 래퍼·--selftest — ★원격 실행 금지 = 신뢰 재유입) | A-2 |
| `sdk.py` | ★외부 주체용 클라이언트(커널 무임포트 — 서명·헤드 독립 재구현·골든 결박) · 키 자율 보관 · 라이트 검증 | A-2·A-6 |
| `worker.py` | 앵커 워커 — ★실제 계산-이행(죽으면 커널 시한-사고 실발동) | A-1 |
| `cosigner.py` | ★D-2 분리 공동-서명자 데몬(비동기 /cosig 회신 — 키 물리 분산) | A-6 |
| `jobs.py` | 검증-대상 사다리: sha256-체인·표본검증·pycheck(협조 한정)·★pyjudge(판정-분리 = v2) | A-1 |
| `package.py` | ★D-9 공개 번들 조립 + 자립성 자기-시험(manifest) | — |
| `test_r1.py` | ★수용 게이트 스위트 18종(골든서명·실물페릴·복구·퍼즈·소크·암호실물·서명치유·★화폐모델·★원자성·★판정분리·★서명분리·가격결박·표본검증·코드이행·인수개방·★해시결박·통계증명·★호가창) | 전체 |
| `EXTERNAL_QUICKSTART.md` | ★외부 참여 문서(맥락-0 실증의 유일 입력) · `VERIFIER.md` 검증자 안내 · `RELEASE.md` 발표문 초안 | A-2 |

## 실행

```bash
python3 r1/test_r1.py                     # 수용 게이트 전량(R1_GATES_PASS)
python3 r1/node.py --data DIR --port 8788 --auto-tick 2       # 노드
python3 r1/worker.py --url http://127.0.0.1:8788 --key DIR/anchor0.key  # 앵커 워커
```

판정 기록 = `results/r1_gates.json`(재실행 = 위 명령).
