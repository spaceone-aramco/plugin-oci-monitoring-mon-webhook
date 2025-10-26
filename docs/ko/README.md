# SpaceONE OCI 모니터링 웹훅 플러그인

## 📋 프로젝트 개요

이 프로젝트는 **Oracle Cloud Infrastructure(OCI) Monitoring**에서 발생하는 알람을 **SpaceONE Alert Manager**로 전달하는 웹훅 플러그인입니다.

### 🎯 주요 기능
- **실시간 알람 수신**: OCI Monitoring 알람 상태 변화 감지
- **자동 이벤트 변환**: OCI 형식 → SpaceONE Event 형식 변환
- **보안 강화**: 메시지 서명 검증 및 HTTPS 통신
- **견고한 처리**: 재시도 메커니즘 및 오류 처리

### 🏗️ 아키텍처
```
OCI Monitoring → Alarm → Notification Topic → Subscription → SpaceONE Webhook → Alert Manager
```

## 🚀 빠른 시작

### 1. 환경 설정
```bash
# 프로젝트 클론
git clone <repository-url>
cd plugin-oci-monitoring-mon-webhook

# 가상환경 생성 및 활성화
python -m venv venv
source venv/bin/activate  # Linux/Mac

# 의존성 설치
pip install -r pkg/pip_requirements.txt
```

### 2. 웹훅 서버 실행
```bash
# 개발 서버 시작
python src/spaceone/monitoring/interface/grpc/webhook.py

# 다른 터미널에서 테스트
grpcurl -plaintext -d '{}' localhost:50051 spaceone.api.monitoring.plugin.Webhook/init
```

### 3. 코드 품질 검사
```bash
# 린트 및 포맷팅
ruff check src/ --fix
ruff format src/

# 테스트 실행
pytest test/ --cov=src
```

## 📚 문서 가이드

### 사용자 문서
- **[사용자 가이드](사용자_가이드.md)**: OCI-SpaceONE 웹훅 연동 설정 방법

### 기술 문서
- **[API 명세서](technical/API_명세서.md)**: gRPC API 상세 명세 및 사용법
- **[Event.parse 응답 데이터 명세서](technical/Event_Parse_응답_데이터_명세서.md)**: Event.parse 메서드 응답 구조 및 필드 상세 설명
- **[REQUEST 로그 명세서](technical/REQUEST_로그_명세서.md)**: JSON 형태 REQUEST 로그 구조 및 분석 방법 상세 가이드
- **[서버 디버그 로그 명세서](technical/서버_디버그_로그_명세서.md)**: 테스트 로그 구조 및 REQUEST 로깅 분석
- **[시스템 아키텍처](technical/시스템_아키텍처_문서.md)**: 전체 시스템 설계 및 구조
- **[소스코드 분석](technical/소스코드_분석_문서.md)**: 프로젝트 소스코드 완전 분석
- **[비즈니스 로직](technical/비즈니스_로직_문서.md)**: 핵심 비즈니스 프로세스 및 규칙
- **[구현 완성도 분석](technical/구현_완성도_분석_보고서.md)**: 문서 vs 소스코드 구현 상태 분석
- **[구현 완료 보고서](technical/구현_완료_보고서.md)**: 기본 기능 중심 구현 완료 결과
- **[기술 명세서](technical/OCI_웹훅_연동_기술_명세서.md)**: 구현 상세 정보 및 예제

### 개발자 문서
- **[개발 환경 가이드](development/개발_환경_가이드.md)**: 개발 환경 설정
- **[코드 품질 가이드](development/코드_품질_가이드.md)**: 코딩 표준 및 품질 관리
- **[로깅 표준 가이드](development/로깅_표준_가이드.md)**: 로깅 정책 및 표준

## 🔧 개발 정보

### 프로젝트 구조
```
src/spaceone/monitoring/
├── service/           # 비즈니스 로직
├── manager/           # 데이터 처리 관리
├── interface/grpc/    # gRPC 인터페이스
├── model/            # 데이터 모델
└── error/            # 에러 정의
```

### 핵심 컴포넌트
- **WebhookService**: 웹훅 초기화 및 검증
- **EventService**: 이벤트 파싱 및 처리
- **EventManager**: OCI → SpaceONE 데이터 변환
- **IncidentOCI**: OCI 알람 데이터 처리

### 지원 OCI 서비스
- **Compute Instance**: CPU, Memory, Disk, Network 메트릭
- **Load Balancer**: 요청 수, 응답 시간, 연결 수
- **Database**: CPU, Memory, 연결 수, 쿼리 성능
- **Object Storage**: 버킷 크기, 요청 수, 오류율

## 🛡️ 보안 및 권한

### 필수 OCI IAM 권한
```
Allow group webhook-users to manage alarms in compartment monitoring
Allow group webhook-users to manage ons-topics in compartment monitoring
Allow group webhook-users to manage ons-subscriptions in compartment monitoring
Allow group webhook-users to read metrics in compartment monitoring
```

### 보안 기능
- **메시지 서명 검증**: X.509 인증서 기반 검증
- **HTTPS 통신**: 모든 통신 암호화
- **IP 화이트리스트**: OCI IP 대역 제한
- **인증 토큰**: 웹훅 인증 강화

## 📊 모니터링 및 운영

### 헬스체크
```bash
curl http://localhost:8080/health
```

### 메트릭 수집
```bash
curl http://localhost:8080/metrics
```

### 로그 레벨 설정
```python
import logging
logging.getLogger('spaceone.monitoring').setLevel(logging.DEBUG)
```

## 🐳 배포

### Docker 실행
```bash
docker build -t oci-webhook .
docker run -p 8080:8080 oci-webhook
```

### Kubernetes 배포
```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

## 🧪 테스트

### 단위 테스트
```bash
pytest test/unit/ -v
```

### 통합 테스트
```bash
pytest test/integration/ -v
```

### 커버리지 리포트
```bash
pytest --cov=src --cov-report=html
open htmlcov/index.html
```

## 🤝 기여하기

### 개발 워크플로우
1. 이슈 생성 또는 기존 이슈 확인
2. 기능 브랜치 생성: `git checkout -b feature/새기능`
3. 코드 작성 및 테스트
4. 코드 품질 검사: `ruff check src/ --fix`
5. Pull Request 생성

### 코딩 표준
- **Python 3.8+** 사용
- **PEP 8** 스타일 가이드 준수
- **타입 힌트** 필수 사용
- **Docstring** 작성 (Google 스타일)

## 📞 지원 및 문의

### 문제 해결
- **이슈 트래커**: GitHub Issues 활용
- **문서 확인**: 기술 명세서 및 사용자 가이드 참조
- **로그 분석**: DEBUG 레벨 로그 확인

### 연락처
- **개발팀**: development@example.com
- **기술지원**: support@example.com

## 📄 라이선스

이 프로젝트는 Apache License 2.0 하에 배포됩니다. 자세한 내용은 [LICENSE](../../LICENSE) 파일을 참조하세요.

---

**마지막 업데이트**: 2024년 1월 28일  
**버전**: 1.0.0  
**상태**: Production Ready ✅