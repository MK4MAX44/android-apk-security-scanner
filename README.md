# apkscan 🔍

> 안드로이드 APK 정적 보안 분석기

APK 파일을 열어 **위험 권한 · 잘못된 매니페스트 설정 · 하드코딩된 비밀키 ·
위험 API 호출**을 자동으로 탐지하고, 심각도 기반 위험 점수를 매겨
텍스트 / JSON / 마크다운 / **HTML 대시보드** 4종 리포트로 출력한다.

![Python](https://img.shields.io/badge/python-3.9+-blue)
![androguard](https://img.shields.io/badge/engine-androguard%204.x-green)
![tests](https://img.shields.io/badge/tests-13%20passing-brightgreen)
![license](https://img.shields.io/badge/license-educational-lightgrey)

---

## ✨ 주요 기능

- **매니페스트 분석** — 위험 권한, `debuggable`, `allowBackup`, 평문 HTTP, exported 컴포넌트
- **위험 API 탐지** — DEX 호출 그래프(xref)를 분석해 *실제로 호출되는* 위험 API만 탐지
  (명령 실행 · 동적 코드 로딩 · SMS 발송 · 식별자 접근 · 리플렉션)
- **서명 인증서 분석** — 디버그 키 서명, 약한 알고리즘(SHA-1) 탐지
- **하드코딩 시크릿 탐지** — AWS/Google API 키, JWT, Private Key, Slack 토큰 등
- **오탐 감소** — androidx 등 프레임워크 컴포넌트를 공격면 집계에서 자동 분리
- **OWASP Mobile Top 10 매핑** — 각 탐지 결과를 표준 항목에 연결
- **위험 점수(0~100)** — 심각도 가중합으로 우선순위 제공
- **4종 리포트** — 터미널 · JSON · 마크다운 · 자체 완결형 HTML 대시보드(다크모드 대응)

---

## 🚀 빠른 시작

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 분석 (딥 모드: 코드까지)
.venv/bin/python -m apkscan samples/app.apk

# HTML 대시보드로 저장 후 브라우저에서 열기
.venv/bin/python -m apkscan samples/app.apk --html -o reports/app.html
open reports/app.html
```

---

## 📊 예시 출력

의도적으로 취약하게 만든 앱 **InsecureBankv2** 분석 결과 (`위험 점수 85/100`):

| # | 심각도 | 룰 | 발견 | OWASP |
|---|--------|-----|------|-------|
| 1 | HIGH | `MANIFEST-001` | 디버그 모드 활성화 | M8 |
| 2 | HIGH | `API-001` | 위험 API 4종 (Runtime.exec·DexClassLoader·SmsManager·리플렉션) | M4 |
| 3 | MEDIUM | `PERM-001` | 위험 권한 5개 (SMS·통화기록·연락처 등) | M3 |
| 4 | LOW | `MANIFEST-002` | 백업 허용 | M9 |
| 5 | LOW | `SDK-001` | 낮은 targetSdk (22) | M8 |

### 정상 vs 취약 앱 비교 ([평가 상세](docs/10-정확도-평가.md))

| 앱 | 위험 점수 | 발견 | 성격 |
|---|:---:|:---:|---|
| InsecureBankv2 | **85** | 5 | 의도적 취약 앱 |
| F-Droid Basic | 65 | 4 | 정상 앱스토어 |

---

## 🧱 아키텍처

관심사 분리 — 4단계 파이프라인. 룰 추가 시 추출·출력 코드를 건드리지 않는다.

```
APK ─▶ [추출]      사실만 수집       → ApkFacts
       [룰]        위험 판단         → [Finding, ...]
       [분석]      점수 계산         → AnalysisResult
       [리포트]    text/json/md/html
```

| 파일 | 역할 |
|---|---|
| `apkscan/extractors.py` | APK에서 사실 추출 (매니페스트·인증서·문자열·API) |
| `apkscan/rules.py` | 룰 엔진 (11종 룰 + OWASP 매핑) |
| `apkscan/analyzer.py` | 오케스트레이션 + 위험 점수 |
| `apkscan/report.py` | 4종 리포트 출력 |
| `apkscan/cli.py` | 명령줄 인터페이스 |

---

## 🧪 개발

```bash
.venv/bin/python tests/test_rules.py                 # 유닛 테스트 13개
.venv/bin/python scripts/batch_scan.py samples/ --csv reports/out.csv   # 일괄 스캔
```

---

## 🗺️ 로드맵

- [x] 코어 분석기 + 11종 탐지 룰
- [x] 위험 API 탐지 (DEX xref)
- [x] 4종 리포트 (HTML 대시보드 포함)
- [x] 유닛 테스트 · 일괄 스캔
- [x] 정상/취약 앱 비교 평가
- [ ] 표본 확대(각 10개+)로 오탐·미탐율 수치화
- [ ] (선택) ML 악성 분류 · Flask 웹앱 · 동적 분석(Frida)

전체 기획·일정·예산은 [`docs/`](docs/) 폴더 참고 → 시작: [`docs/00-프로젝트-계획서.md`](docs/00-프로젝트-계획서.md)

---

## ⚠️ 고지

보안 연구·진단 목적의 **정적 분석** 도구다. 앱을 실행하지 않으므로 악성 샘플도 안전하게 다룰 수 있다.
위험 점수는 자동 판정이 아니라 **사람이 검토할 우선순위**로 쓸 것.
