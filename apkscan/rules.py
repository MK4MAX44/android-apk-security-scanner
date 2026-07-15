"""탐지 룰 엔진.

extractors가 모은 '사실(ApkFacts)'을 입력받아, 위험 신호(Finding)를 만든다.
룰은 데이터로 표현했다 → 새 룰 추가가 쉽고, 문서화도 자동으로 된다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum

from .extractors import ApkFacts


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    detail: str
    recommendation: str = ""
    owasp: str = ""  # 관련 OWASP Mobile Top 10 (2024) 항목


# 안드로이드/구글/androidx 프레임워크가 자동으로 넣는 컴포넌트 접두사.
# 앱이 직접 만든 게 아니라 오탐이 되기 쉬우므로 '공격면' 집계에서 구분한다.
FRAMEWORK_PREFIXES = (
    "androidx.",
    "android.",
    "com.google.android.gms.",
    "com.google.firebase.",
    "com.android.",
)


def _is_framework(name: str) -> bool:
    return name.startswith(FRAMEWORK_PREFIXES)


# ── 위험 권한 목록 (구글이 'dangerous' 로 분류한 대표 권한) ──────────
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "SMS 읽기 (인증번호 탈취 위험)",
    "android.permission.SEND_SMS": "SMS 발송 (유료 결제/스팸 위험)",
    "android.permission.RECEIVE_SMS": "SMS 수신 가로채기",
    "android.permission.READ_CONTACTS": "연락처 읽기",
    "android.permission.ACCESS_FINE_LOCATION": "정밀 위치 추적",
    "android.permission.RECORD_AUDIO": "마이크 녹음",
    "android.permission.CAMERA": "카메라 접근",
    "android.permission.READ_CALL_LOG": "통화 기록 열람",
    "android.permission.READ_PHONE_STATE": "단말/통신 상태·식별자 접근",
    "android.permission.SYSTEM_ALERT_WINDOW": "다른 앱 위에 창 띄우기 (오버레이 공격)",
    "android.permission.REQUEST_INSTALL_PACKAGES": "외부 APK 설치 (드로퍼 악성코드)",
    "android.permission.WRITE_EXTERNAL_STORAGE": "외부 저장소 쓰기",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "접근성 서비스 (화면 탈취/자동조작 남용)",
}

# ── 코드 문자열에서 찾는 하드코딩 시크릿 패턴 ──────────────────────
SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Private Key 블록", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("JWT 토큰", re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    ("Firebase URL", re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com")),
]


def check_permissions(facts: ApkFacts) -> list[Finding]:
    out = []
    hits = [(p, DANGEROUS_PERMISSIONS[p]) for p in facts.permissions if p in DANGEROUS_PERMISSIONS]
    if hits:
        lines = "\n".join(f"  - {p} → {desc}" for p, desc in hits)
        # 특히 위험한 조합은 심각도를 올린다
        names = {p for p, _ in hits}
        sev = Severity.MEDIUM
        if "android.permission.BIND_ACCESSIBILITY_SERVICE" in names or \
           "android.permission.REQUEST_INSTALL_PACKAGES" in names:
            sev = Severity.HIGH
        out.append(Finding(
            rule_id="PERM-001",
            title=f"위험 권한 {len(hits)}개 사용",
            severity=sev,
            detail=f"다음 위험 권한을 요청함:\n{lines}",
            recommendation="앱 기능에 꼭 필요한 권한인지 검토. 특히 SMS/접근성/설치 권한은 악성 앱의 단골 조합.",
            owasp="M3: 안전하지 않은 인증/인가 (과도한 권한)",
        ))
    return out


def check_manifest(facts: ApkFacts) -> list[Finding]:
    out = []
    if facts.debuggable:
        out.append(Finding(
            "MANIFEST-001", "디버그 모드 활성화 (android:debuggable=true)",
            Severity.HIGH,
            "릴리스 빌드에 debuggable=true가 남아있으면 누구나 앱 프로세스에 디버거를 붙여 "
            "메모리·변수를 들여다볼 수 있다.",
            "릴리스 빌드에서는 debuggable을 false(기본값)로 둘 것.",
            owasp="M8: 보안 설정 오류",
        ))
    if facts.allow_backup:
        out.append(Finding(
            "MANIFEST-002", "백업 허용 (android:allowBackup=true)",
            Severity.LOW,
            "adb backup 등으로 앱 데이터가 외부로 유출될 수 있다.",
            "민감 데이터를 다루면 allowBackup=false 설정.",
            owasp="M9: 안전하지 않은 데이터 저장",
        ))
    if facts.uses_cleartext_traffic:
        out.append(Finding(
            "MANIFEST-003", "평문(HTTP) 트래픽 허용",
            Severity.MEDIUM,
            "usesCleartextTraffic=true → 암호화되지 않은 HTTP 통신이 허용되어 중간자 공격에 노출.",
            "HTTPS만 쓰도록 하고 cleartext는 비활성화.",
            owasp="M5: 안전하지 않은 통신",
        ))

    # exported 컴포넌트: 앱이 직접 만든 것과 프레임워크가 넣은 것을 구분(오탐↓)
    app_exported, fw_exported = [], []
    for name in (facts.exported_activities + facts.exported_services + facts.exported_receivers):
        (fw_exported if _is_framework(name) else app_exported).append(name)

    if facts.exported_providers:
        app_providers = [p for p in facts.exported_providers if not _is_framework(p)]
        if app_providers:
            out.append(Finding(
                "MANIFEST-004", f"노출된 ContentProvider {len(app_providers)}개",
                Severity.MEDIUM,
                "exported ContentProvider는 다른 앱이 데이터에 접근할 통로가 될 수 있다:\n  - "
                + "\n  - ".join(app_providers),
                "권한(android:permission)으로 보호하거나 exported=false 설정.",
                owasp="M4: 불충분한 입력/출력 검증",
            ))

    if app_exported:
        out.append(Finding(
            "MANIFEST-005", f"외부 노출 컴포넌트 {len(app_exported)}개 (앱 자체)",
            Severity.INFO,
            f"다른 앱이 호출할 수 있는 앱 컴포넌트(공격면). "
            f"프레임워크 컴포넌트 {len(fw_exported)}개는 제외함. 예:\n  - "
            + "\n  - ".join(app_exported[:10]),
            "각 컴포넌트가 신뢰할 수 없는 입력을 안전하게 처리하는지 점검.",
            owasp="M4: 불충분한 입력/출력 검증",
        ))
    return out


def check_certificate(facts: ApkFacts) -> list[Finding]:
    out = []
    if facts.cert_is_debug:
        out.append(Finding(
            "CERT-001", "디버그 인증서로 서명됨",
            Severity.HIGH,
            f"서명 주체: {facts.cert_subject}\n"
            "디버그 키는 모든 개발자 PC에서 공유되는 공개 키라, 사실상 서명이 없는 것과 같다.",
            "릴리스 전용 keystore로 서명할 것.",
            owasp="M7: 부족한 바이너리 보호",
        ))
    if facts.cert_sig_algo and "sha1" in facts.cert_sig_algo.lower():
        out.append(Finding(
            "CERT-002", f"약한 서명 알고리즘 ({facts.cert_sig_algo})",
            Severity.LOW,
            "SHA-1은 충돌 공격에 취약한 구식 해시.",
            "SHA-256 이상으로 서명.",
            owasp="M10: 부족한 암호화",
        ))
    return out


def check_dangerous_apis(facts: ApkFacts) -> list[Finding]:
    """코드에서 실제로 호출되는 위험 API를 보고한다."""
    out = []
    if facts.api_hits:
        lines = "\n".join(f"  - {label}" for label, _ in facts.api_hits)
        names = {label for label, _ in facts.api_hits}
        # 명령 실행·동적 코드 로딩은 특히 위험
        sev = Severity.MEDIUM
        if any("명령 실행" in n or "동적 코드 로딩" in n for n in names):
            sev = Severity.HIGH
        out.append(Finding(
            "API-001", f"위험 API 호출 {len(facts.api_hits)}종",
            sev,
            f"다음 위험 API를 호출하는 코드가 있음:\n{lines}",
            "명령 실행·동적 코드 로딩·SMS 발송은 정당한 사유가 있는지 확인. 악성 앱의 흔한 행위.",
            owasp="M4: 불충분한 입력/출력 검증",
        ))
    return out


def check_target_sdk(facts: ApkFacts) -> list[Finding]:
    """targetSdk가 너무 낮으면 최신 보안 정책이 적용되지 않는다."""
    out = []
    MIN_RECOMMENDED = 30  # Android 11
    if facts.target_sdk is not None and facts.target_sdk < MIN_RECOMMENDED:
        out.append(Finding(
            "SDK-001", f"낮은 targetSdk ({facts.target_sdk})",
            Severity.LOW,
            f"targetSdk={facts.target_sdk}. 낮으면 구글의 최신 런타임 보안 정책"
            "(scoped storage, 권한 강화 등)이 적용되지 않는다.",
            f"targetSdk를 {MIN_RECOMMENDED} 이상으로 올릴 것.",
            owasp="M8: 보안 설정 오류",
        ))
    return out


def check_secrets(facts: ApkFacts) -> list[Finding]:
    out = []
    for label, pat in SECRET_PATTERNS:
        matched = [s for s in facts.strings if pat.search(s)]
        if matched:
            sample = matched[0]
            if len(sample) > 60:
                sample = sample[:57] + "..."
            out.append(Finding(
                f"SECRET-{label[:4].upper()}", f"하드코딩된 시크릿 의심: {label}",
                Severity.HIGH,
                f"{len(matched)}건 발견. 예: {sample}",
                "키/토큰을 코드에 넣지 말 것. 서버 측으로 옮기거나 안전한 저장소 사용.",
                owasp="M1: 부적절한 자격증명 사용",
            ))
    return out


# 실행할 모든 룰 (여기에 함수만 추가하면 자동 반영)
ALL_CHECKS = [
    check_permissions,
    check_manifest,
    check_certificate,
    check_dangerous_apis,
    check_target_sdk,
    check_secrets,
]


def run_all(facts: ApkFacts) -> list[Finding]:
    """모든 룰을 돌려 심각도 높은 순으로 정렬해 반환."""
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        findings += check(facts)
    findings.sort(key=lambda f: f.severity, reverse=True)
    return findings
