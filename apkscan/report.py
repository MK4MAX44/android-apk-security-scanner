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


# ── HTML 리포트 ──────────────────────────────────────────────────
# 심각도별 색상 (라이트/다크 공통으로 무난한 값)
_SEV_HEX = {
    Severity.CRITICAL: "#a21caf",
    Severity.HIGH: "#dc2626",
    Severity.MEDIUM: "#d97706",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#6b7280",
}


def _esc(s) -> str:
    """HTML 특수문자 이스케이프 (XSS·깨짐 방지)."""
    return (
        str(s).replace("&", "&amp;").replace("<", "&lt;")
        .replace(">", "&gt;").replace('"', "&quot;")
    )


def to_html(result: AnalysisResult) -> str:
    """서버 없이 브라우저에서 바로 열리는 자체 완결형 HTML 리포트."""
    f = result.facts
    score = result.risk_score
    # 점수에 따른 색상
    if score >= 70:
        gauge = "#dc2626"
    elif score >= 40:
        gauge = "#d97706"
    else:
        gauge = "#16a34a"

    # 심각도 요약 (개수)
    counts: dict[str, int] = {}
    for fnd in result.findings:
        counts[fnd.severity.label] = counts.get(fnd.severity.label, 0) + 1
    chips = "".join(
        f'<span class="chip" style="--c:{_SEV_HEX[Severity[k]]}">{k} {v}</span>'
        for k, v in counts.items()
    ) or '<span class="chip" style="--c:#16a34a">발견 없음</span>'

    cards = []
    for i, fnd in enumerate(result.findings, 1):
        hexc = _SEV_HEX[fnd.severity]
        rec = f'<p class="rec">→ 권고: {_esc(fnd.recommendation)}</p>' if fnd.recommendation else ""
        ows = f'<span class="owasp">{_esc(fnd.owasp)}</span>' if fnd.owasp else ""
        cards.append(f"""
      <div class="card" style="--c:{hexc}">
        <div class="card-head">
          <span class="sev" style="background:{hexc}">{fnd.severity.label}</span>
          <span class="title">{i}. {_esc(fnd.title)}</span>
          <span class="rid">{_esc(fnd.rule_id)}</span>
        </div>
        <pre class="detail">{_esc(fnd.detail)}</pre>
        {rec}
        {ows}
      </div>""")
    cards_html = "\n".join(cards) or '<p class="ok">✅ 발견된 위험 신호 없음</p>'

    urls_html = ""
    if f.urls:
        items = "".join(f"<li><code>{_esc(u)}</code></li>" for u in f.urls[:30])
        urls_html = f'<h2>코드 내 URL <small>({len(f.urls)}개 중 상위 30)</small></h2><ul class="urls">{items}</ul>'

    title = _esc(f.app_name or f.package or "APK")
    return f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>apkscan · {title}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    margin: 0; padding: 2rem 1rem; background: #f6f7f9; color: #111827;
    line-height: 1.5; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #0f1115; color: #e5e7eb; }}
    .card, .head, .urls {{ background: #1a1d24 !important; }}
    pre.detail {{ background: #0f1115 !important; }}
  }}
  .wrap {{ max-width: 860px; margin: 0 auto; }}
  .head {{ background: #fff; border-radius: 16px; padding: 1.5rem 1.75rem;
    box-shadow: 0 1px 3px rgba(0,0,0,.08); margin-bottom: 1.5rem;
    display: grid; grid-template-columns: 1fr auto; gap: 1rem; align-items: center; }}
  h1 {{ margin: 0 0 .3rem; font-size: 1.5rem; }}
  .meta {{ font-size: .85rem; color: #6b7280; }}
  .meta code {{ color: inherit; }}
  .gauge {{ text-align: center; }}
  .gauge .num {{ font-size: 2.6rem; font-weight: 800; color: {gauge}; line-height: 1; }}
  .gauge .lbl {{ font-size: .75rem; color: #6b7280; }}
  .chips {{ margin: .75rem 0 0; }}
  .chip {{ display: inline-block; font-size: .75rem; font-weight: 700; color: #fff;
    background: var(--c); border-radius: 999px; padding: .2rem .6rem; margin: 0 .35rem .35rem 0; }}
  h2 {{ font-size: 1.05rem; margin: 1.5rem .25rem .75rem; }}
  h2 small {{ color: #6b7280; font-weight: 400; }}
  .card {{ background: #fff; border-left: 5px solid var(--c); border-radius: 10px;
    padding: 1rem 1.25rem; margin-bottom: .9rem; box-shadow: 0 1px 2px rgba(0,0,0,.05); }}
  .card-head {{ display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; }}
  .sev {{ color: #fff; font-size: .7rem; font-weight: 700; padding: .15rem .5rem;
    border-radius: 6px; }}
  .title {{ font-weight: 700; }}
  .rid {{ margin-left: auto; font-size: .72rem; color: #6b7280; font-family: monospace; }}
  pre.detail {{ background: #f3f4f6; border-radius: 8px; padding: .75rem;
    font-size: .82rem; overflow-x: auto; white-space: pre-wrap; margin: .7rem 0 .4rem; }}
  .rec {{ margin: .3rem 0; font-size: .85rem; }}
  .owasp {{ display: inline-block; font-size: .72rem; background: #eef2ff; color: #4338ca;
    border-radius: 6px; padding: .15rem .5rem; }}
  @media (prefers-color-scheme: dark) {{ .owasp {{ background: #312e81; color: #c7d2fe; }} }}
  .urls {{ background: #fff; border-radius: 10px; padding: 1rem 1.25rem 1rem 2rem;
    font-size: .82rem; }}
  .ok {{ font-size: 1.1rem; }}
  footer {{ text-align: center; color: #9ca3af; font-size: .75rem; margin-top: 2rem; }}
</style></head>
<body><div class="wrap">
  <div class="head">
    <div>
      <h1>{title}</h1>
      <div class="meta">
        <code>{_esc(f.package)}</code> · v{_esc(f.version_name)} ·
        SDK min {_esc(f.min_sdk)}/target {_esc(f.target_sdk)}<br>
        서명: {_esc(f.cert_subject)}
      </div>
      <div class="chips">{chips}</div>
    </div>
    <div class="gauge">
      <div class="num">{score}</div>
      <div class="lbl">위험 점수 / 100</div>
    </div>
  </div>
  <h2>발견 사항 <small>({len(result.findings)}건)</small></h2>
  {cards_html}
  {urls_html}
  <footer>apkscan · 안드로이드 APK 정적 분석기 · 정적 분석 결과는 참고용입니다</footer>
</div></body></html>"""
