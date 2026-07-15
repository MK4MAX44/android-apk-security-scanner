"""분석 결과를 사람이 읽는 텍스트 / JSON / 마크다운으로 출력."""
from __future__ import annotations

import json
from dataclasses import asdict

from .analyzer import AnalysisResult
from .rules import Severity

# 터미널 색상 (심각도별)
_COLOR = {
    Severity.CRITICAL: "\033[95m",
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[94m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"


def to_text(result: AnalysisResult, color: bool = True) -> str:
    f = result.facts
    lines = []
    lines.append("=" * 64)
    lines.append(f"  APK 분석 리포트: {f.app_name or f.package or f.path}")
    lines.append("=" * 64)
    lines.append(f"  패키지    : {f.package}")
    lines.append(f"  버전      : {f.version_name} ({f.version_code})")
    lines.append(f"  SDK       : min={f.min_sdk}  target={f.target_sdk}")
    lines.append(f"  서명       : {f.cert_subject}")
    lines.append(f"  위험 점수  : {result.risk_score}/100")
    lines.append("-" * 64)

    if not result.findings:
        lines.append("  ✅ 발견된 위험 신호 없음")
    else:
        lines.append(f"  발견 {len(result.findings)}건:\n")
        for i, fnd in enumerate(result.findings, 1):
            c = _COLOR.get(fnd.severity, "") if color else ""
            r = _RESET if color else ""
            lines.append(f"  [{i}] {c}[{fnd.severity.label}]{r} {fnd.title}  ({fnd.rule_id})")
            for dl in fnd.detail.splitlines():
                lines.append(f"      {dl}")
            if fnd.recommendation:
                lines.append(f"      → 권고: {fnd.recommendation}")
            if fnd.owasp:
                lines.append(f"      → OWASP: {fnd.owasp}")
            lines.append("")

    if f.urls:
        lines.append("-" * 64)
        lines.append(f"  코드 내 URL {len(f.urls)}개 (상위 15개):")
        for u in f.urls[:15]:
            lines.append(f"    - {u}")
    if f.notes:
        lines.append("-" * 64)
        lines.append("  분석 메모:")
        for n in f.notes:
            lines.append(f"    ! {n}")
    lines.append("=" * 64)
    return "\n".join(lines)


def to_json(result: AnalysisResult) -> str:
    payload = {
        "facts": asdict(result.facts),
        "risk_score": result.risk_score,
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.label,
                "detail": f.detail,
                "recommendation": f.recommendation,
                "owasp": f.owasp,
            }
            for f in result.findings
        ],
    }
    # 문자열 전체는 JSON에 넣으면 너무 크므로 개수만 남긴다
    payload["facts"]["strings"] = f"<{len(result.facts.strings)}개 생략>"
    return json.dumps(payload, ensure_ascii=False, indent=2)


def to_markdown(result: AnalysisResult) -> str:
    """옵시디언에서 보기 좋은 마크다운 리포트."""
    f = result.facts
    md = []
    md.append(f"# APK 분석 리포트: {f.app_name or f.package}")
    md.append("")
    md.append(f"- **패키지**: `{f.package}`")
    md.append(f"- **버전**: {f.version_name} ({f.version_code})")
    md.append(f"- **SDK**: min={f.min_sdk}, target={f.target_sdk}")
    md.append(f"- **서명 주체**: {f.cert_subject}")
    md.append(f"- **위험 점수**: **{result.risk_score}/100**")
    md.append("")
    md.append("## 발견 사항")
    md.append("")
    if not result.findings:
        md.append("발견된 위험 신호 없음 ✅")
    else:
        md.append("| # | 심각도 | 룰 | 제목 |")
        md.append("|---|--------|-----|------|")
        for i, fnd in enumerate(result.findings, 1):
            md.append(f"| {i} | {fnd.severity.label} | `{fnd.rule_id}` | {fnd.title} |")
        md.append("")
        for i, fnd in enumerate(result.findings, 1):
            md.append(f"### {i}. [{fnd.severity.label}] {fnd.title}")
            md.append("")
            md.append(f"> 룰 ID: `{fnd.rule_id}`")
            md.append("")
            md.append("```")
            md.append(fnd.detail)
            md.append("```")
            if fnd.recommendation:
                md.append(f"**권고:** {fnd.recommendation}")
            if fnd.owasp:
                md.append(f"**OWASP:** {fnd.owasp}")
            md.append("")
    if f.urls:
        md.append("## 코드 내 URL")
        md.append("")
        for u in f.urls[:30]:
            md.append(f"- `{u}`")
        md.append("")
    return "\n".join(md)
