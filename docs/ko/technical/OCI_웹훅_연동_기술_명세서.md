# OCI 웹훅 연동 기술 명세서

## 개요

본 문서는 Oracle Cloud Infrastructure(OCI)와 SpaceONE 간의 웹훅 연동을 위한 완전한 기술 명세서입니다. 실제 구현에 필요한 모든 API, 데이터 형식, 보안 요구사항을 포함합니다.

> 📚 **사용자 가이드**: 설정 방법은 [사용자 가이드](../사용자_가이드.md)를 참조하세요.

*참고: Oracle 공식 문서 [https://docs.oracle.com/en/](https://docs.oracle.com/en/)*

## OCI 서비스 아키텍처

### 핵심 구성 요소

#### 1. OCI Monitoring Service
- **서비스 경로**: `Observability & Management` → `Monitoring`
- **주요 기능**: 메트릭 수집, 알람 생성, 임계값 모니터링
- **API 엔드포인트**: `https://monitoring.{region}.oraclecloud.com`

#### 2. OCI Notification Service (ONS)
- **서비스 경로**: `Observability & Management` → `Notifications`
- **주요 기능**: 토픽 관리, 구독 관리, 메시지 전달
- **API 엔드포인트**: `https://notification.{region}.oraclecloud.com`

#### 3. OCI Identity and Access Management (IAM)
- **서비스 경로**: `Identity & Security` → `Identity`
- **주요 기능**: 권한 관리, 정책 설정, 사용자 인증
- **API 엔드포인트**: `https://identity.{region}.oraclecloud.com`

## OCI Monitoring API 명세

### 알람(Alarm) 관련 API

#### 1. 알람 생성 API
```http
POST /20180401/alarms
Host: monitoring.{region}.oraclecloud.com
Content-Type: application/json
Authorization: Signature keyId="...",algorithm="rsa-sha256",headers="...",signature="..."

{
  "compartmentId": "ocid1.compartment.oc1...",
  "displayName": "High CPU Usage Alert",
  "metricCompartmentId": "ocid1.compartment.oc1...",
  "namespace": "oci_computeagent",
  "query": "CpuUtilization[1m].mean() > 80",
  "severity": "CRITICAL",
  "destinations": ["ocid1.onstopic.oc1..."],
  "isEnabled": true,
  "repeatNotificationDuration": "PT0S"
}
```

#### 2. 알람 상태 조회 API
```http
GET /20180401/alarms/{alarmId}/status
Host: monitoring.{region}.oraclecloud.com
Authorization: Signature keyId="...",algorithm="rsa-sha256",headers="...",signature="..."
```

**응답 예시**:
```json
{
  "status": "FIRING",
  "suppressionState": "UNSUPPRESSED",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### 메트릭 네임스페이스 및 지표

#### 1. Compute Instance 메트릭
```json
{
  "namespace": "oci_computeagent",
  "metrics": [
    {
      "name": "CpuUtilization",
      "unit": "percent",
      "description": "CPU 사용률"
    },
    {
      "name": "MemoryUtilization", 
      "unit": "percent",
      "description": "메모리 사용률"
    },
    {
      "name": "DiskBytesRead",
      "unit": "bytes",
      "description": "디스크 읽기 바이트"
    },
    {
      "name": "NetworksBytesIn",
      "unit": "bytes", 
      "description": "네트워크 수신 바이트"
    }
  ]
}
```

#### 2. Load Balancer 메트릭
```json
{
  "namespace": "oci_lbaas",
  "metrics": [
    {
      "name": "RequestCount",
      "unit": "count",
      "description": "요청 수"
    },
    {
      "name": "ResponseTime",
      "unit": "milliseconds",
      "description": "응답 시간"
    },
    {
      "name": "ActiveConnections",
      "unit": "count",
      "description": "활성 연결 수"
    }
  ]
}
```

## OCI Notification Service API 명세

### 토픽(Topic) 관리 API

#### 1. 토픽 생성 API
```http
POST /20181201/topics
Host: notification.{region}.oraclecloud.com
Content-Type: application/json
Authorization: Signature keyId="...",algorithm="rsa-sha256",headers="...",signature="..."

{
  "compartmentId": "ocid1.compartment.oc1...",
  "name": "SpaceONE-Webhook-Topic",
  "description": "SpaceONE 웹훅 연동을 위한 알림 토픽"
}
```

**응답 예시**:
```json
{
  "topicId": "ocid1.onstopic.oc1.ap-seoul-1.aaaaaaaaa...",
  "name": "SpaceONE-Webhook-Topic",
  "compartmentId": "ocid1.compartment.oc1...",
  "lifecycleState": "ACTIVE",
  "timeCreated": "2024-01-15T10:00:00.000Z",
  "etag": "example-etag"
}
```

### 구독(Subscription) 관리 API

#### 1. 구독 생성 API
```http
POST /20181201/subscriptions
Host: notification.{region}.oraclecloud.com
Content-Type: application/json
Authorization: Signature keyId="...",algorithm="rsa-sha256",headers="...",signature="..."

{
  "topicId": "ocid1.onstopic.oc1.ap-seoul-1.aaaaaaaaa...",
  "compartmentId": "ocid1.compartment.oc1...",
  "protocol": "HTTPS",
  "endpoint": "https://spaceone-webhook.example.com/webhook/oci"
}
```

#### 2. 구독 확인 프로세스
OCI는 HTTPS 구독 생성 시 자동으로 확인 요청을 전송합니다:

```http
POST /webhook/oci
Host: spaceone-webhook.example.com
Content-Type: application/json
User-Agent: Oracle-Notification-Service

{
  "type": "Subscription Confirmation",
  "subscriptionId": "ocid1.subscription.oc1...",
  "topicId": "ocid1.onstopic.oc1...",
  "confirmationUrl": "https://notification.ap-seoul-1.oraclecloud.com/...",
  "message": "Please confirm your subscription by visiting the URL above"
}
```

**SpaceONE 응답 요구사항**:
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "confirmed"
}
```

## 웹훅 메시지 형식

### 알람 발생 시 웹훅 페이로드

#### 1. 기본 구조
```json
{
  "type": "Notification",
  "messageId": "12345678-1234-1234-1234-123456789012",
  "topicId": "ocid1.onstopic.oc1.ap-seoul-1.aaaaaaaaa...",
  "subject": "Alarm: High CPU Usage Alert is in FIRING state",
  "message": "{\"alarmId\":\"ocid1.alarm.oc1...\",\"status\":\"FIRING\"}",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "signature": "example-signature",
  "signingCertURL": "https://notification.ap-seoul-1.oraclecloud.com/..."
}
```

#### 2. 메시지 필드 상세 분석
```json
{
  "message": {
    "alarmId": "ocid1.alarm.oc1.ap-seoul-1.aaaaaaaaa...",
    "displayName": "High CPU Usage Alert",
    "compartmentId": "ocid1.compartment.oc1...",
    "namespace": "oci_computeagent",
    "query": "CpuUtilization[1m].mean() > 80",
    "severity": "CRITICAL",
    "status": "FIRING",
    "timestamp": "2024-01-15T10:30:00.000Z",
    "metricData": [
      {
        "namespace": "oci_computeagent",
        "name": "CpuUtilization",
        "dimensions": {
          "resourceId": "ocid1.instance.oc1.ap-seoul-1.aaaaaaaaa...",
          "resourceDisplayName": "web-server-01"
        },
        "value": 85.5,
        "unit": "percent",
        "timestamp": "2024-01-15T10:30:00.000Z"
      }
    ]
  }
}
```

### 알람 상태별 메시지 유형

#### 1. FIRING (알람 발생)
```json
{
  "status": "FIRING",
  "severity": "CRITICAL",
  "message": "CPU 사용률이 임계값 80%를 초과했습니다 (현재: 85.5%)"
}
```

#### 2. OK (알람 해제)
```json
{
  "status": "OK", 
  "severity": "INFO",
  "message": "CPU 사용률이 정상 범위로 돌아왔습니다 (현재: 65.2%)"
}
```

## SpaceONE 연동 구현 명세

### 1. 웹훅 엔드포인트 구현

#### HTTP 요청 처리
```python
from flask import Flask, request, jsonify
import json
import logging

app = Flask(__name__)
logger = logging.getLogger(__name__)

@app.route('/webhook/oci', methods=['POST'])
def handle_oci_webhook():
    """OCI 웹훅 요청 처리"""
    try:
        # 요청 헤더 검증
        content_type = request.headers.get('Content-Type')
        if content_type != 'application/json':
            return jsonify({'error': 'Invalid content type'}), 400
        
        # 페이로드 파싱
        payload = request.get_json()
        
        # 구독 확인 처리
        if payload.get('type') == 'Subscription Confirmation':
            return handle_subscription_confirmation(payload)
        
        # 알림 메시지 처리
        elif payload.get('type') == 'Notification':
            return handle_notification(payload)
        
        else:
            logger.warning(f"Unknown message type: {payload.get('type')}")
            return jsonify({'error': 'Unknown message type'}), 400
            
    except Exception as e:
        logger.error(f"Webhook processing error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

def handle_subscription_confirmation(payload):
    """구독 확인 처리"""
    logger.info(f"Subscription confirmation received: {payload.get('subscriptionId')}")
    
    # 확인 URL 호출 (선택사항)
    confirmation_url = payload.get('confirmationUrl')
    if confirmation_url:
        # HTTP GET 요청으로 구독 확인
        import requests
        response = requests.get(confirmation_url)
        logger.info(f"Confirmation response: {response.status_code}")
    
    return jsonify({'status': 'confirmed'}), 200

def handle_notification(payload):
    """알림 메시지 처리"""
    try:
        # 메시지 내용 파싱
        message_content = json.loads(payload.get('message', '{}'))
        
        # SpaceONE 이벤트 형식으로 변환
        spaceone_event = convert_to_spaceone_format(payload, message_content)
        
        # SpaceONE으로 이벤트 전송
        send_to_spaceone(spaceone_event)
        
        return jsonify({'status': 'processed'}), 200
        
    except Exception as e:
        logger.error(f"Notification processing error: {str(e)}")
        return jsonify({'error': 'Processing failed'}), 500
```

### 2. 데이터 변환 로직

#### OCI → SpaceONE 이벤트 변환
```python
def convert_to_spaceone_format(oci_payload, message_content):
    """OCI 알림을 SpaceONE 이벤트 형식으로 변환"""
    
    # 기본 이벤트 구조
    spaceone_event = {
        'event_id': generate_event_id(),
        'event_key': message_content.get('alarmId'),
        'event_type': map_event_type(message_content.get('status')),
        'title': create_event_title(message_content),
        'description': message_content.get('displayName', ''),
        'severity': map_severity(message_content.get('severity')),
        'resource': extract_resource_info(message_content),
        'raw_data': oci_payload,
        'additional_info': extract_additional_info(message_content),
        'occurred_at': parse_timestamp(oci_payload.get('timestamp')),
        'provider': 'oci'
    }
    
    return spaceone_event

def map_event_type(oci_status):
    """OCI 알람 상태를 SpaceONE 이벤트 타입으로 매핑"""
    mapping = {
        'FIRING': 'ALERT',
        'OK': 'RECOVERY',
        'INSUFFICIENT_DATA': 'NONE'
    }
    return mapping.get(oci_status, 'NONE')

def map_severity(oci_severity):
    """OCI 심각도를 SpaceONE 심각도로 매핑"""
    mapping = {
        'CRITICAL': 'CRITICAL',
        'ERROR': 'ERROR', 
        'WARNING': 'WARNING',
        'INFO': 'INFO'
    }
    return mapping.get(oci_severity, 'INFO')

def extract_resource_info(message_content):
    """리소스 정보 추출"""
    metric_data = message_content.get('metricData', [])
    if metric_data:
        dimensions = metric_data[0].get('dimensions', {})
        return {
            'resource_id': dimensions.get('resourceId', ''),
            'name': dimensions.get('resourceDisplayName', ''),
            'resource_type': 'inventory.CloudService'
        }
    return {}

def extract_additional_info(message_content):
    """추가 정보 추출"""
    return {
        'compartment_id': message_content.get('compartmentId'),
        'namespace': message_content.get('namespace'),
        'query': message_content.get('query'),
        'alarm_url': f"https://cloud.oracle.com/monitoring/alarms/{message_content.get('alarmId')}"
    }
```

## 보안 및 인증

### 1. OCI API 인증

#### API Key 인증 방식
```python
import oci

# OCI 설정 파일 기반 인증
config = oci.config.from_file("~/.oci/config", "DEFAULT")

# Monitoring 클라이언트 생성
monitoring_client = oci.monitoring.MonitoringClient(config)

# Notification 클라이언트 생성  
notification_client = oci.ons.NotificationControlPlaneClient(config)
```

#### 설정 파일 예시 (`~/.oci/config`)
```ini
[DEFAULT]
user=ocid1.user.oc1..aaaaaaaaa...
fingerprint=12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef
tenancy=ocid1.tenancy.oc1..aaaaaaaaa...
region=ap-seoul-1
key_file=~/.oci/oci_api_key.pem
```

### 2. 웹훅 보안

#### 메시지 서명 검증
```python
import base64
import hashlib
import hmac
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def verify_oci_signature(payload, signature, cert_url):
    """OCI 웹훅 메시지 서명 검증"""
    try:
        # 인증서 다운로드
        import requests
        cert_response = requests.get(cert_url)
        cert_data = cert_response.content
        
        # X.509 인증서 파싱
        certificate = x509.load_pem_x509_certificate(cert_data)
        public_key = certificate.public_key()
        
        # 메시지 해시 생성
        message_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        
        # 서명 검증
        signature_bytes = base64.b64decode(signature)
        public_key.verify(
            signature_bytes,
            message_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        return True
        
    except Exception as e:
        logger.error(f"Signature verification failed: {str(e)}")
        return False
```

## IAM 권한 정책

### 필수 권한 정책

#### 1. Monitoring 서비스 권한
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "monitoring.oraclecloud.com"
      },
      "Action": [
        "ons:Publish"
      ],
      "Resource": "arn:oci:ons:*:*:topic/*"
    }
  ]
}
```

#### 2. 사용자/그룹 권한 정책
```
Allow group WebhookAdmins to manage alarms in compartment MonitoringCompartment
Allow group WebhookAdmins to manage ons-topics in compartment MonitoringCompartment  
Allow group WebhookAdmins to manage ons-subscriptions in compartment MonitoringCompartment
Allow group WebhookAdmins to read metrics in compartment MonitoringCompartment
Allow group WebhookAdmins to read instances in compartment MonitoringCompartment
```

## 모니터링 및 로깅

### 1. OCI 서비스 로깅

#### Audit 로그 활성화
```python
# OCI Audit 서비스를 통한 API 호출 로깅
audit_client = oci.audit.AuditClient(config)

# 감사 이벤트 조회
audit_events = audit_client.list_events(
    compartment_id=compartment_id,
    start_time=start_time,
    end_time=end_time
)
```

#### Service 로그 설정
```json
{
  "logType": "SERVICE",
  "source": {
    "service": "monitoring",
    "resource": "alarms",
    "category": "write"
  },
  "destination": {
    "compartmentId": "ocid1.compartment.oc1...",
    "logGroupId": "ocid1.loggroup.oc1..."
  }
}
```

### 2. 웹훅 모니터링

#### 헬스체크 엔드포인트
```python
@app.route('/health', methods=['GET'])
def health_check():
    """웹훅 서비스 상태 확인"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    }), 200

@app.route('/metrics', methods=['GET'])
def metrics():
    """프로메테우스 메트릭 엔드포인트"""
    return Response(
        generate_prometheus_metrics(),
        mimetype='text/plain'
    )
```

## 오류 처리 및 재시도

### 1. OCI 서비스 오류 처리

#### 일반적인 오류 코드
```python
def handle_oci_errors(func):
    """OCI API 오류 처리 데코레이터"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except oci.exceptions.ServiceError as e:
            if e.status == 429:  # Rate Limiting
                time.sleep(2 ** attempt)  # Exponential backoff
                return func(*args, **kwargs)
            elif e.status == 401:  # Unauthorized
                logger.error("OCI authentication failed")
                raise
            elif e.status == 404:  # Not Found
                logger.warning(f"Resource not found: {e.message}")
                return None
            else:
                logger.error(f"OCI API error: {e.status} - {e.message}")
                raise
    return wrapper
```

### 2. 웹훅 재시도 메커니즘

#### 지수 백오프 재시도
```python
import time
import random

def retry_with_backoff(func, max_retries=3, base_delay=1):
    """지수 백오프를 사용한 재시도"""
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            
            delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
            logger.warning(f"Attempt {attempt + 1} failed, retrying in {delay:.2f}s: {str(e)}")
            time.sleep(delay)
```

## 테스트 및 검증

### 1. 단위 테스트

#### 웹훅 처리 테스트
```python
import unittest
from unittest.mock import patch, MagicMock

class TestOCIWebhook(unittest.TestCase):
    
    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()
    
    def test_subscription_confirmation(self):
        """구독 확인 테스트"""
        payload = {
            "type": "Subscription Confirmation",
            "subscriptionId": "ocid1.subscription.oc1...",
            "confirmationUrl": "https://example.com/confirm"
        }
        
        response = self.client.post('/webhook/oci', 
                                  json=payload,
                                  content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['status'], 'confirmed')
    
    def test_alarm_notification(self):
        """알람 알림 테스트"""
        payload = {
            "type": "Notification",
            "messageId": "12345",
            "message": json.dumps({
                "alarmId": "ocid1.alarm.oc1...",
                "status": "FIRING",
                "severity": "CRITICAL"
            })
        }
        
        with patch('webhook_handler.send_to_spaceone') as mock_send:
            response = self.client.post('/webhook/oci',
                                      json=payload,
                                      content_type='application/json')
            
            self.assertEqual(response.status_code, 200)
            mock_send.assert_called_once()
```

### 2. 통합 테스트

#### OCI 서비스 연동 테스트
```python
def test_oci_integration():
    """OCI 서비스 통합 테스트"""
    # 테스트 알람 생성
    alarm_details = oci.monitoring.models.CreateAlarmDetails(
        display_name="Test Alarm",
        compartment_id=test_compartment_id,
        metric_compartment_id=test_compartment_id,
        namespace="oci_computeagent",
        query="CpuUtilization[1m].mean() > 90",
        severity="CRITICAL",
        destinations=[test_topic_id],
        is_enabled=True
    )
    
    # 알람 생성 API 호출
    response = monitoring_client.create_alarm(alarm_details)
    alarm_id = response.data.id
    
    try:
        # 알람 상태 확인
        status_response = monitoring_client.get_alarm_status(alarm_id)
        assert status_response.data.status in ['OK', 'FIRING']
        
    finally:
        # 테스트 알람 삭제
        monitoring_client.delete_alarm(alarm_id)
```

## 성능 최적화

### 1. 연결 풀링

#### HTTP 클라이언트 최적화
```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 연결 풀 설정
session = requests.Session()
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504]
)
adapter = HTTPAdapter(
    pool_connections=10,
    pool_maxsize=20,
    max_retries=retry_strategy
)
session.mount("https://", adapter)
```

### 2. 비동기 처리

#### 웹훅 비동기 처리
```python
import asyncio
import aiohttp

async def process_webhook_async(payload):
    """비동기 웹훅 처리"""
    async with aiohttp.ClientSession() as session:
        # SpaceONE API 비동기 호출
        async with session.post(
            'https://spaceone-api.example.com/events',
            json=payload,
            headers={'Content-Type': 'application/json'}
        ) as response:
            return await response.json()
```

## 배포 및 운영

### 1. Docker 컨테이너화

#### Dockerfile
```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "4", "app:app"]
```

#### docker-compose.yml
```yaml
version: '3.8'
services:
  oci-webhook:
    build: .
    ports:
      - "8080:8080"
    environment:
      - OCI_CONFIG_FILE=/app/.oci/config
      - SPACEONE_API_URL=https://spaceone-api.example.com
    volumes:
      - ./.oci:/app/.oci:ro
    restart: unless-stopped
    
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
    restart: unless-stopped
```

### 2. Kubernetes 배포

#### deployment.yaml
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oci-webhook
spec:
  replicas: 3
  selector:
    matchLabels:
      app: oci-webhook
  template:
    metadata:
      labels:
        app: oci-webhook
    spec:
      containers:
      - name: oci-webhook
        image: oci-webhook:latest
        ports:
        - containerPort: 8080
        env:
        - name: OCI_CONFIG_FILE
          value: "/app/.oci/config"
        volumeMounts:
        - name: oci-config
          mountPath: /app/.oci
          readOnly: true
      volumes:
      - name: oci-config
        secret:
          secretName: oci-config
```

## 결론

본 기술 명세서는 Oracle 공식 문서를 기반으로 OCI와 SpaceONE 간의 웹훅 연동을 위한 완전한 구현 가이드를 제공합니다. 이 명세를 따라 구현하면 안정적이고 확장 가능한 웹훅 연동 시스템을 구축할 수 있습니다.

### 주요 특징
- **완전한 API 명세**: OCI Monitoring 및 Notification API 상세 문서화
- **보안 강화**: 메시지 서명 검증 및 IAM 권한 관리
- **오류 처리**: 포괄적인 오류 처리 및 재시도 메커니즘
- **성능 최적화**: 연결 풀링 및 비동기 처리
- **운영 준비**: Docker 및 Kubernetes 배포 가이드

*참고 문서: [Oracle Cloud Infrastructure Documentation](https://docs.oracle.com/en/)*
