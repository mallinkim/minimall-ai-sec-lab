# MiniMall AI 보안 실습 — 8강 스타터 (수업용 가상 예시)

AI 활용 소프트웨어 공학 8강 "AI 보안과 안전한 활용" 미니 프로젝트용 프로젝트입니다. Node.js 20 이상이면 되고 설치할 패키지는 없습니다(`npm install` 불필요). 외부 서비스 · 실제 AI · 키가 필요 없습니다.

## 빠른 시작
```bash
node --version                                   # v20 이상
npm run eval:ai                                  # AI 가 만든 산출물(ai_sec/)의 점수 — Mission 0 에서 측정
npm run eval                                     # 우리 팀 산출물의 점수 (공개 시나리오)
node scripts/demo.js "ORD-1002 상태 알려줘" --baseline   # 방어 없는 도우미를 직접 공격해 보기
node scripts/demo.js "ORD-1002 상태 알려줘"              # 우리 팀 방어를 통과시켜 보기
npm test                                         # 공격 회귀 테스트 (redteam/attacks.json)
npm run playbook   # npm run incidents   # npm run docs   # 형식 점검
npm run sec-ci                                   # 보안 CI 게이트 (Mission 5 에서 완성)
```

## 폴더
| 경로 | 설명 | 수정 |
|---|---|---|
| `docs/SEC_CONTRACT.md` | **기준 문서** — 규칙 · 인터페이스 · 점수 방식 | × |
| `docs/MOCK_LLM.md` | 모의 LLM(순진한 모델)의 동작 규칙 | × |
| `redteam/attacks.json` | 우리 팀의 공격 케이스 (Mission 1) | ○ |
| `app/shop_api.js` | AI 가 만든 API 초안 — 취약점 7가지 (Mission 2) | ○ |
| `scanner/` | 시크릿 · 의존성 · SBOM 도구 (Mission 2) | ○ |
| `guard/` `src/assistant/systemPrompt.js` | 가드레일 · 시스템 프롬프트 (Mission 3) | ○ |
| `secops/` | 탐지 · 한도 · 킬스위치 · 대응 절차 (Mission 4) | ○ |
| `incidents/INC-S1~S3` | 사고 분석용 번들 (로그 · 변경 · 경보) | × |
| `ai_sec/` | AI 가 만들었다고 가정한 산출물 (리뷰 대상) | × |
| `sim/` `src/assistant/{assistant,tools}.js` `config/` | 시뮬레이터 · 파이프라인 · 설정 | × |
| `scripts/` | 평가 · 점검 도구 (`sec-ci.js` 만 수정) | sec-ci.js |
| `tests/` | 공격 회귀 테스트 (추가 가능) | ○ |
| `docs/` 나머지 | 위협 모델 · 요구사항 · 리뷰 · 보고 양식 | ○ |

문제지(Word)의 미션 순서대로 진행하세요.

> 모든 데이터 · 키 · 주소 · 인물은 **가상**입니다. 이 프로젝트의 공격 기법은 허가된 시뮬레이터 안에서만 연습합니다.
