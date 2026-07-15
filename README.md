# apkscan 🔍

안드로이드 APK 정적 보안 분석기 (교육용 프로젝트).

APK 파일을 열어 **위험 권한 · 잘못된 매니페스트 설정 · 하드코딩된 비밀키**를
자동으로 탐지하고 심각도 기반 위험 점수를 매긴다.

## 빠른 시작

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m apkscan samples/app.apk
```

## 📋 프로젝트 문서 (옵시디언)

기획·일정·예산·원리 등 모든 문서는 **`docs/` 폴더**에 있다.
옵시디언에서 **이 폴더(`apkscan/`)를 볼트로 열면** 문서끼리 링크로 이어진다.

시작 문서 → **`docs/00-프로젝트-계획서.md`**

- `01` 왜 이 프로젝트인가 (동기·진로 도움)
- `02` 목표와 범위 (선택 이유 포함)
- `03` 일정 로드맵 (걸리는 시간)
- `04` 예산과 리소스 (돈·시간)
- `05` 아키텍처 · `06` 사용법 · `07` 탐지 룰 · `08` 확장 · `09` 용어사전

## 구조

```
apkscan/
├── apkscan/          # 소스 코드
│   ├── extractors.py #  사실 추출
│   ├── rules.py      #  위험 판단
│   ├── analyzer.py   #  오케스트레이션
│   ├── report.py     #  리포트 출력
│   └── cli.py        #  명령줄
├── docs/             # 옵시디언 프로젝트 문서
├── samples/          # 분석용 APK
├── reports/          # 생성된 리포트
└── tests/            # 테스트
```
