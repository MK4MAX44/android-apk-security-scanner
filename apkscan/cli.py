"""명령줄 인터페이스.

사용 예:
    python -m apkscan app.apk
    python -m apkscan app.apk --json -o reports/app.json
    python -m apkscan app.apk --markdown -o reports/app.md
    python -m apkscan app.apk --fast     # 코드 분석 생략(빠름)
"""
from __future__ import annotations

import argparse
import sys

from .analyzer import analyze
from . import report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="apkscan",
        description="안드로이드 APK 정적 보안 분석기 (교육용)",
    )
    p.add_argument("apk", help="분석할 .apk 파일 경로")
    p.add_argument("--fast", action="store_true",
                   help="DEX 코드 분석을 생략하고 매니페스트·인증서만 분석")
    p.add_argument("--json", action="store_true", help="JSON으로 출력")
    p.add_argument("--markdown", "--md", action="store_true", help="마크다운으로 출력")
    p.add_argument("--html", action="store_true", help="HTML 대시보드로 출력 (브라우저에서 열기)")
    p.add_argument("-o", "--output", help="결과를 파일로 저장 (미지정 시 표준출력)")
    p.add_argument("--no-color", action="store_true", help="터미널 색상 끄기")
    args = p.parse_args(argv)

    try:
        print(f"[*] 분석 중: {args.apk}", file=sys.stderr)
        result = analyze(args.apk, deep=not args.fast)
    except FileNotFoundError:
        print(f"[!] 파일을 찾을 수 없음: {args.apk}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[!] 분석 실패: {e}", file=sys.stderr)
        return 1

    if args.json:
        out = report.to_json(result)
    elif args.markdown:
        out = report.to_markdown(result)
    elif args.html:
        out = report.to_html(result)
    else:
        out = report.to_text(result, color=not args.no_color and not args.output)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"[+] 저장됨: {args.output}", file=sys.stderr)
    else:
        print(out)

    # 위험 점수가 높으면 non-zero 종료코드 (CI 연동 대비)
    return 0 if result.risk_score < 50 else 3


if __name__ == "__main__":
    raise SystemExit(main())
