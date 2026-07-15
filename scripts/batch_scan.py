"""여러 APK를 한 번에 스캔해 요약 표를 출력한다.

사용:
    .venv/bin/python scripts/batch_scan.py samples/            # 폴더 안의 모든 apk
    .venv/bin/python scripts/batch_scan.py a.apk b.apk --fast  # 개별 파일
    .venv/bin/python scripts/batch_scan.py samples/ --csv out.csv
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apkscan.analyzer import analyze


def collect_apks(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            out.extend(sorted(path.glob("*.apk")))
        elif path.suffix == ".apk":
            out.append(path)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="여러 APK 일괄 스캔")
    ap.add_argument("paths", nargs="+", help="APK 파일 또는 폴더")
    ap.add_argument("--fast", action="store_true", help="빠른 스캔")
    ap.add_argument("--csv", help="결과를 CSV로 저장")
    args = ap.parse_args(argv)

    apks = collect_apks(args.paths)
    if not apks:
        print("스캔할 .apk 파일이 없습니다.", file=sys.stderr)
        return 1

    rows = []
    print(f"{'APK':40}  {'점수':>4}  {'발견':>4}  최고 심각도")
    print("-" * 72)
    for apk in apks:
        try:
            result = analyze(str(apk), deep=not args.fast)
            top = result.findings[0].severity.label if result.findings else "-"
            n = len(result.findings)
            score = result.risk_score
        except Exception as e:
            top, n, score = f"ERROR: {e}", 0, -1
        name = apk.name[:40]
        print(f"{name:40}  {score:>4}  {n:>4}  {top}")
        rows.append({"apk": apk.name, "score": score, "findings": n, "top_severity": top})

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["apk", "score", "findings", "top_severity"])
            w.writeheader()
            w.writerows(rows)
        print(f"\n[+] CSV 저장: {args.csv}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
