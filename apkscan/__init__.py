"""apkscan - 안드로이드 APK 정적 분석기 (교육용).

APK 파일을 열어 권한, 매니페스트 설정, 인증서, 코드 내 문자열/위험 API를
분석하고, 룰 기반으로 보안 위험 신호를 리포트한다.
"""

__version__ = "0.1.0"

# androguard(4.x)는 loguru로 대량의 DEBUG 로그를 뿜는다. 기본으로 끈다.
# (디버깅이 필요하면 APKSCAN_VERBOSE=1 로 켤 수 있다)
import os as _os

if not _os.environ.get("APKSCAN_VERBOSE"):
    try:
        from loguru import logger as _logger
        _logger.disable("androguard")
    except Exception:
        pass

