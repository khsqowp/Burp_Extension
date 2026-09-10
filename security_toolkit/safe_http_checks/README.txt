Security Toolkit 안전 HTTP 진단 규칙 묶음

이 폴더는 외부 Nuclei, Nikto, Nmap 규칙을 직접 실행하기 위한 폴더가 아니다.
다섯 가지 일반 웹 진단에 필요한 읽기 전용 요청과 판정 서명만 새로 작성해 보관한다.

구성
- error-page-signatures.json: 기본 오류 페이지와 스택 추적 노출 서명
- allowed-methods.json: OPTIONS의 Allow/Public 헤더에 표시된 위험 메서드 분석
- directory-listing.json: 디렉터리 목록 페이지 서명
- server-header-disclosure.json: 제품명 및 상세 버전 헤더 노출
- security-headers.json: 주요 보안 헤더 누락과 약한 CSP 값
- manifest.json: 허용 파일명, 버전 및 SHA-256

안전 계약
- GET, HEAD, OPTIONS만 허용한다.
- 모든 path는 사용자가 지정한 대상 origin 기준 상대경로다.
- 외부 콜백, OAST, 텔레메트리, 웹훅을 사용하지 않는다.
- 자격증명과 쿠키를 자동 전송하지 않는다.
- 리다이렉트를 따라가지 않는다.
- 규칙당 최대 10요청, 초당 최대 2요청, 동시 요청 1개다.
- PUT, DELETE 등 상태 변경 메서드가 OPTIONS에 보여도 실제 재시험하지 않는다.
- 상태 코드 하나만으로 취약점을 확정하지 않는다.
- 자동 업데이트하지 않는다.

검증
- scanner-core/safety/safe_rule_bundle.py의 load_verified_bundle()을 사용한다.
- manifest에 없는 파일, 해시가 바뀐 파일, 위험 메서드 또는 외부 URL이 포함된 파일은 거부한다.
- upstream을 업데이트할 때 이 폴더를 덮어쓰지 말고 별도 검토 후 새 버전을 만든다.
