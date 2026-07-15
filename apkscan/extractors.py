"""APK에서 원시 정보를 뽑아내는 추출기 모음.

여기서는 '판단'을 하지 않는다. 오직 사실(fact)만 수집한다.
위험 여부 판단은 rules.py가 담당한다. (관심사 분리)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ── APK 한 개에서 뽑아낸 사실들을 담는 그릇 ──────────────────────────
@dataclass
class ApkFacts:
    path: str
    package: Optional[str] = None
    app_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None

    permissions: list[str] = field(default_factory=list)

    # 매니페스트 설정 플래그
    debuggable: bool = False
    allow_backup: bool = True          # 기본값이 true라 명시 안 하면 true
    uses_cleartext_traffic: Optional[bool] = None
    network_security_config: bool = False

    # 컴포넌트 (name, exported) 튜플
    exported_activities: list[str] = field(default_factory=list)
    exported_services: list[str] = field(default_factory=list)
    exported_receivers: list[str] = field(default_factory=list)
    exported_providers: list[str] = field(default_factory=list)

    # 서명 인증서
    cert_issuer: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_sig_algo: Optional[str] = None
    cert_is_debug: bool = False

    # 코드 분석
    strings: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    api_hits: list[tuple[str, str]] = field(default_factory=list)  # (라벨, API)

    # 에러 메모 (부분 실패해도 죽지 않게)
    notes: list[str] = field(default_factory=list)


# URL / IP 를 문자열에서 찾는 정규식
URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)


def _is_exported(node) -> bool:
    """매니페스트 XML 노드가 외부에 노출(exported)되는지 판단."""
    exported = node.get(
        "{http://schemas.android.com/apk/res/android}exported"
    )
    if exported is not None:
        return exported.lower() == "true"
    # exported 미지정 시: intent-filter가 있으면 (구버전 기준) 노출로 간주
    return len(node.findall("intent-filter")) > 0


def extract_manifest(apk, facts: ApkFacts) -> None:
    """androguard APK 객체에서 매니페스트 관련 사실을 채운다."""
    facts.package = apk.get_package()
    facts.app_name = apk.get_app_name()
    facts.version_name = apk.get_androidversion_name()
    facts.version_code = apk.get_androidversion_code()
    facts.permissions = sorted(apk.get_permissions() or [])

    try:
        facts.min_sdk = int(apk.get_min_sdk_version()) if apk.get_min_sdk_version() else None
        facts.target_sdk = int(apk.get_target_sdk_version()) if apk.get_target_sdk_version() else None
    except (TypeError, ValueError):
        pass

    # application 태그의 보안 관련 속성
    NS = "{http://schemas.android.com/apk/res/android}"
    try:
        manifest = apk.get_android_manifest_xml()
        app = manifest.find("application")
        if app is not None:
            facts.debuggable = app.get(f"{NS}debuggable", "false").lower() == "true"
            facts.allow_backup = app.get(f"{NS}allowBackup", "true").lower() == "true"
            cleartext = app.get(f"{NS}usesCleartextTraffic")
            if cleartext is not None:
                facts.uses_cleartext_traffic = cleartext.lower() == "true"
            facts.network_security_config = app.get(f"{NS}networkSecurityConfig") is not None

            # exported 컴포넌트 수집
            for tag, bucket in (
                ("activity", facts.exported_activities),
                ("service", facts.exported_services),
                ("receiver", facts.exported_receivers),
                ("provider", facts.exported_providers),
            ):
                for node in app.findall(tag):
                    if _is_exported(node):
                        bucket.append(node.get(f"{NS}name", "?"))
    except Exception as e:  # 매니페스트 파싱 실패해도 나머지는 진행
        facts.notes.append(f"매니페스트 상세 파싱 실패: {e}")


def extract_certificate(apk, facts: ApkFacts) -> None:
    """서명 인증서 정보를 뽑는다."""
    try:
        certs = apk.get_certificates()
        if not certs:
            facts.notes.append("서명 인증서를 찾지 못함 (미서명 APK?)")
            return
        cert = certs[0]
        facts.cert_issuer = cert.issuer.human_friendly
        facts.cert_subject = cert.subject.human_friendly
        facts.cert_sig_algo = cert.signature_algo
        # 안드로이드 디버그 서명 키의 표준 CN
        facts.cert_is_debug = "Android Debug" in (facts.cert_subject or "")
    except Exception as e:
        facts.notes.append(f"인증서 파싱 실패: {e}")


def extract_strings(dex_list, facts: ApkFacts, limit: int = 50000) -> None:
    """DEX 코드에 들어있는 문자열을 모으고, 그중 URL을 추린다.

    dex_list: androguard가 준 DalvikVMFormat 객체들의 리스트.
    limit: 문자열이 너무 많으면 성능을 위해 상한을 둔다.
    """
    seen: set[str] = set()
    try:
        for dex in dex_list:
            for s in dex.get_strings():
                if s in seen:
                    continue
                seen.add(s)
                facts.strings.append(s)
                if len(seen) >= limit:
                    facts.notes.append(f"문자열이 {limit}개를 초과해 이후는 생략")
                    break
            if len(seen) >= limit:
                break
    except Exception as e:
        facts.notes.append(f"문자열 추출 실패: {e}")

    # URL 추리기
    urls: set[str] = set()
    for s in facts.strings:
        for m in URL_RE.findall(s):
            urls.add(m.rstrip(".,);"))
    facts.urls = sorted(urls)


# 위험 API: (라벨, 클래스 시그니처, 메서드명)
# 클래스는 DEX 내부 표기(Lpkg/Class;)를 쓴다.
DANGEROUS_APIS = [
    ("명령 실행 (Runtime.exec)", "Ljava/lang/Runtime;", "exec"),
    ("명령 실행 (ProcessBuilder)", "Ljava/lang/ProcessBuilder;", "start"),
    ("동적 코드 로딩 (DexClassLoader)", "Ldalvik/system/DexClassLoader;", "<init>"),
    ("동적 코드 로딩 (PathClassLoader)", "Ldalvik/system/PathClassLoader;", "<init>"),
    ("SMS 발송 (SmsManager)", "Landroid/telephony/SmsManager;", "sendTextMessage"),
    ("기기 식별자 접근 (getDeviceId)", "Landroid/telephony/TelephonyManager;", "getDeviceId"),
    ("가입자 식별자 접근 (getSubscriberId)", "Landroid/telephony/TelephonyManager;", "getSubscriberId"),
    ("리플렉션 호출 (Method.invoke)", "Ljava/lang/reflect/Method;", "invoke"),
]


def extract_api_usage(dx, facts: ApkFacts) -> None:
    """androguard Analysis(dx)로 위험 API가 '호출되는지' 확인한다.

    단순 문자열 매칭이 아니라, 해당 메서드를 호출하는 코드(xref)가
    실제로 존재하는지를 본다 → 오탐이 적다.
    """
    if dx is None:
        return
    try:
        for label, cls, meth in DANGEROUS_APIS:
            for m in dx.find_methods(classname=re.escape(cls), methodname=re.escape(meth)):
                # 이 API를 호출하는 코드가 하나라도 있으면 히트
                if list(m.get_xref_from()):
                    facts.api_hits.append((label, f"{cls}->{meth}"))
                    break
    except Exception as e:
        facts.notes.append(f"API 사용 분석 실패: {e}")
