"""분석 오케스트레이터.

APK 경로를 받아 → androguard로 로드 → 추출 → 룰 실행 → 결과 반환.
CLI와 리포트는 이 함수만 호출하면 된다.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import extractors, rules
from .extractors import ApkFacts
from .rules import Finding


@dataclass
class AnalysisResult:
    facts: ApkFacts
    findings: list[Finding]

    @property
    def risk_score(self) -> int:
        """심각도 가중합으로 간단한 위험 점수를 낸다 (0~100 clamp)."""
        weights = {0: 0, 1: 5, 2: 15, 3: 30, 4: 50}
        score = sum(weights[int(f.severity)] for f in self.findings)
        return min(score, 100)


def analyze(apk_path: str, deep: bool = True) -> AnalysisResult:
    """APK 하나를 분석한다.

    deep=True 면 DEX 코드까지 로드해 문자열/시크릿을 분석한다 (느림).
    deep=False 면 매니페스트·인증서만 본다 (빠름).
    """
    facts = ApkFacts(path=apk_path)

    if deep:
        # AnalyzeAPK: (APK, [DalvikVMFormat], Analysis) 튜플 반환
        from androguard.misc import AnalyzeAPK
        apk, dex_list, dx = AnalyzeAPK(apk_path)
        extractors.extract_manifest(apk, facts)
        extractors.extract_certificate(apk, facts)
        extractors.extract_strings(dex_list, facts)
        extractors.extract_api_usage(dx, facts)
    else:
        from androguard.core.apk import APK
        apk = APK(apk_path)
        extractors.extract_manifest(apk, facts)
        extractors.extract_certificate(apk, facts)

    findings = rules.run_all(facts)
    return AnalysisResult(facts=facts, findings=findings)
