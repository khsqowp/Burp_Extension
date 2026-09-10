Security Toolkit 오프라인 배포

인터넷이 연결된 준비 PC:
1. security_toolkit 폴더에서 docker compose build scanner-core 실행
2. burp_extension 폴더에서 mvn package 실행 후 루트 burp-history-bridge.jar 교체
3. offline\Export-OfflineBundle.ps1 실행

내부망 PC:
1. Docker Desktop과 Burp Suite를 사전에 설치
2. offline 폴더 전체를 복사
3. offline\Start-Offline.ps1 실행
4. bundle\burp-history-bridge.jar를 Burp Extensions에 등록

실행 중 외부 다운로드나 자동 업데이트는 수행하지 않는다. Docker 이미지에는
실행 파일, Python 패키지, 안전 규칙, 등록된 모듈이 사용하는 최소 wordlist가
포함된다. 진단 트래픽과 도메인 사용 시 내부 DNS 질의만 발생할 수 있다.

번들은 빌드한 이미지의 CPU 아키텍처와 동일한 내부망 PC에서 사용한다.
Export를 다시 실행하면 기존 bundle의 scanner-data는 반출물에 포함하지 않고
security_toolkit\scanner-data\offline-bundle-preserved-* 로 이동해 보존한다.
내부망 실행 결과는 bundle 바깥의 offline\runtime-data에 저장된다.
