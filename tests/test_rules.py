"""룰 엔진 유닛 테스트.

실제 APK 없이 ApkFacts를 손으로 만들어 룰만 빠르게 검증한다.
실행: .venv/bin/python -m pytest -q   (또는)  .venv/bin/python tests/test_rules.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apkscan.extractors import ApkFacts
from apkscan import rules
from apkscan.rules import Severity


def _ids(findings):
    return {f.rule_id for f in findings}


def test_clean_apk_has_no_findings():
    """아무 위험 요소 없는 앱은 발견 0건이어야 한다."""
    facts = ApkFacts(path="x", allow_backup=False)
    assert rules.run_all(facts) == []


def test_dangerous_permission_detected():
    facts = ApkFacts(path="x", allow_backup=False,
                     permissions=["android.permission.SEND_SMS"])
    assert "PERM-001" in _ids(rules.run_all(facts))


def test_accessibility_permission_is_high():
    facts = ApkFacts(path="x", allow_backup=False,
                     permissions=["android.permission.BIND_ACCESSIBILITY_SERVICE"])
    perm = [f for f in rules.run_all(facts) if f.rule_id == "PERM-001"][0]
    assert perm.severity == Severity.HIGH


def test_debuggable_flag():
    facts = ApkFacts(path="x", allow_backup=False, debuggable=True)
    assert "MANIFEST-001" in _ids(rules.run_all(facts))


def test_cleartext_traffic():
    facts = ApkFacts(path="x", allow_backup=False, uses_cleartext_traffic=True)
    assert "MANIFEST-003" in _ids(rules.run_all(facts))


def test_framework_components_are_filtered():
    """androidx 등 프레임워크 컴포넌트만 노출되면 MANIFEST-005가 뜨지 않아야 한다."""
    facts = ApkFacts(path="x", allow_backup=False,
                     exported_receivers=["androidx.work.impl.Foo"])
    assert "MANIFEST-005" not in _ids(rules.run_all(facts))


def test_app_component_is_reported():
    facts = ApkFacts(path="x", allow_backup=False,
                     exported_activities=["com.evil.MainActivity"])
    assert "MANIFEST-005" in _ids(rules.run_all(facts))


def test_debug_certificate():
    facts = ApkFacts(path="x", allow_backup=False,
                     cert_subject="Common Name: Android Debug, O: Android")
    facts.cert_is_debug = True
    assert "CERT-001" in _ids(rules.run_all(facts))


def test_dangerous_api_command_exec_is_high():
    facts = ApkFacts(path="x", allow_backup=False,
                     api_hits=[("명령 실행 (Runtime.exec)", "Ljava/lang/Runtime;->exec")])
    api = [f for f in rules.run_all(facts) if f.rule_id == "API-001"][0]
    assert api.severity == Severity.HIGH


def test_low_target_sdk():
    facts = ApkFacts(path="x", allow_backup=False, target_sdk=22)
    assert "SDK-001" in _ids(rules.run_all(facts))


def test_high_target_sdk_ok():
    facts = ApkFacts(path="x", allow_backup=False, target_sdk=34)
    assert "SDK-001" not in _ids(rules.run_all(facts))


def test_hardcoded_secret():
    facts = ApkFacts(path="x", allow_backup=False,
                     strings=["AKIAIOSFODNN7EXAMPLE", "hello"])
    assert any(i.startswith("SECRET-") for i in _ids(rules.run_all(facts)))


def test_findings_sorted_by_severity():
    facts = ApkFacts(path="x", debuggable=True,  # HIGH
                     target_sdk=22)              # LOW
    sevs = [f.severity for f in rules.run_all(facts)]
    assert sevs == sorted(sevs, reverse=True)


if __name__ == "__main__":
    # pytest 없이도 돌아가는 간이 러너
    import inspect
    tests = [v for k, v in globals().items() if k.startswith("test_") and inspect.isfunction(v)]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  ✅ {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  ❌ {t.__name__}  — {e}")
        except Exception as e:
            print(f"  💥 {t.__name__}  — {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(tests)} 통과")
    sys.exit(0 if passed == len(tests) else 1)
