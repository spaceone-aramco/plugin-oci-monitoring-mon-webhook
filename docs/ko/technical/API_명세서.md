# SpaceONE OCI 모니터링 웹훅 API 명세서

## 📋 개요

본 문서는 SpaceONE OCI 모니터링 웹훅 플러그인의 gRPC API 명세를 정의합니다. 이 API는 SpaceONE 플랫폼과 OCI Monitoring 서비스 간의 웹훅 연동을 위한 인터페이스를 제공합니다.

## 🏗️ API 아키텍처

### 서비스 구조
```
SpaceONE Platform
    ↓ gRPC
┌─────────────────────────────────┐
│  SpaceONE Monitoring Plugin     │
│  ┌─────────────┬─────────────┐  │
│  │   Webhook   │    Event    │  │
│  │   Service   │   Service   │  │
│  └─────────────┴─────────────┘  │
└─────────────────────────────────┘
    ↓ HTTP Webhook
OCI Notification Service
```

### 프로토콜 버퍼 정의
```protobuf
service Webhook {
    rpc init (PluginInitRequest) returns (WebhookPluginInfo);
    rpc verify (PluginVerifyRequest) returns (Empty);
}

service Event {
    rpc parse (ParseEventRequest) returns (EventsInfo);
}
```

## 🔌 Webhook Service API

### 1. init - 플러그인 초기화

#### 요청 (PluginInitRequest)
```json
{
    "options": {
        "webhook_url": "https://webhook.spaceone.dev/monitoring/oci",
        "secret_token": "optional_secret_token",
        "verify_ssl": true
    }
}
```

#### 응답 (WebhookPluginInfo)
```json
{
    "metadata": {
        "supported_resource_type": ["inventory.CloudService"],
        "supported_providers": ["oracle"],
        "webhook_url": "https://webhook.spaceone.dev/monitoring/oci",
        "capabilities": {
            "subscription_confirmation": true,
            "message_verification": true,
            "retry_mechanism": true
        }
    }
}
```

#### 구현 예시
```python
@check_required(['options'])
def init(self, params):
    """웹훅 플러그인 초기화
    
    Args:
        params (dict): {
            'options': {
                'webhook_url': str,
                'secret_token': str (optional),
                'verify_ssl': bool (optional, default: True)
            }
        }
    
    Returns:
        dict: 플러그인 메타데이터
    """
    options = params['options']
    
    # 웹훅 URL 검증
    webhook_url = options.get('webhook_url')
    if not webhook_url or not webhook_url.startswith('https://'):
        raise ERROR_INVALID_WEBHOOK_URL()
    
    return {
        'metadata': {
            'supported_resource_type': ['inventory.CloudService'],
            'supported_providers': ['oracle'],
            'webhook_url': webhook_url,
            'capabilities': {
                'subscription_confirmation': True,
                'message_verification': True,
                'retry_mechanism': True
            }
        }
    }
```

### 2. verify - 웹훅 검증

#### 요청 (PluginVerifyRequest)
```json
{
    "options": {
        "webhook_url": "https://webhook.spaceone.dev/monitoring/oci",
        "secret_token": "test_token"
    }
}
```

#### 응답 (Empty)
```json
{}
```

#### 구현 예시
```python
@transaction
@check_required(['options'])
def verify(self, params):
    """웹훅 연결 검증
    
    Args:
        params (dict): {
            'options': {
                'webhook_url': str,
                'secret_token': str (optional)
            }
        }
    
    Raises:
        ERROR_WEBHOOK_VERIFICATION_FAILED: 검증 실패 시
    """
    options = params['options']
    webhook_url = options.get('webhook_url')
    
    try:
        # 테스트 요청 전송
        test_payload = {
            'type': 'verification',
            'timestamp': datetime.utcnow().isoformat(),
            'test': True
        }
        
        response = requests.post(
            webhook_url,
            json=test_payload,
            timeout=30,
            verify=options.get('verify_ssl', True)
        )
        
        if response.status_code != 200:
            raise ERROR_WEBHOOK_VERIFICATION_FAILED(
                reason=f"HTTP {response.status_code}: {response.text}"
            )
            
    except Exception as e:
        _LOGGER.error(f"Webhook verification failed: {str(e)}")
        raise ERROR_WEBHOOK_VERIFICATION_FAILED(reason=str(e))
```

## 📨 Event Service API

### 1. parse - 이벤트 파싱

#### 요청 (ParseEventRequest)
```json
{
    "options": {
        "provider": "oracle",
        "region": "ap-seoul-1"
    },
    "data": {
        "type": "Notification",
        "messageId": "12345678-1234-1234-1234-123456789012",
        "topicId": "ocid1.onstopic.oc1.ap-seoul-1.aaaaaaaaa...",
        "subject": "Alarm: High CPU Usage Alert is in FIRING state",
        "message": "{\"alarmId\":\"ocid1.alarm.oc1...\",\"status\":\"FIRING\"}",
        "timestamp": "2024-01-15T10:30:00.000Z",
        "signature": "example-signature",
        "signingCertURL": "https://notification.ap-seoul-1.oraclecloud.com/..."
    }
}
```

#### 응답 (EventsInfo)
```json
{
    "results": [
        {
            "event_key": "ocid1.alarm.oc1.ap-seoul-1.aaaaaaaaa...",
            "event_type": "ALERT",
            "title": "High CPU Usage Alert (FIRING)",
            "description": "CPU 사용률이 임계값을 초과했습니다",
            "severity": "CRITICAL",
            "resource": {
                "resource_id": "ocid1.instance.oc1.ap-seoul-1.bbbbbbbbb...",
                "name": "web-server-01",
                "resource_type": "inventory.CloudService"
            },
            "rule": "High CPU Usage Alert",
            "occurred_at": "2024-01-15T10:30:00.000Z",
            "additional_info": {
                "compartment_id": "ocid1.compartment.oc1...",
                "namespace": "oci_computeagent",
                "metric_name": "CpuUtilization",
                "threshold_value": "80",
                "current_value": "85.5",
                "alarm_url": "https://cloud.oracle.com/monitoring/alarms/...",
                "region": "ap-seoul-1"
            }
        }
    ]
}
```

#### 구현 예시
```python
@transaction
@check_required(['options', 'data'])
def parse(self, params):
    """OCI 웹훅 데이터를 SpaceONE 이벤트로 변환
    
    Args:
        params (dict): {
            'options': {
                'provider': str,
                'region': str (optional)
            },
            'data': dict  # OCI Notification 페이로드
        }
    
    Returns:
        list: SpaceONE Event 객체 리스트
    """
    raw_data = params.get('data')
    options = params.get('options', {})
    
    # OCI 메시지 타입 확인
    message_type = raw_data.get('type')
    
    if message_type == 'Subscription Confirmation':
        # 구독 확인 처리
        return self._handle_subscription_confirmation(raw_data)
    
    elif message_type == 'Notification':
        # 알림 메시지 처리
        return self._parse_notification(raw_data, options)
    
    else:
        raise ERROR_UNSUPPORTED_MESSAGE_TYPE(message_type=message_type)

def _parse_notification(self, raw_data, options):
    """알림 메시지를 SpaceONE 이벤트로 변환"""
    try:
        # 메시지 내용 파싱
        message_content = json.loads(raw_data.get('message', '{}'))
        
        # OCI → SpaceONE 이벤트 변환
        event_data = {
            'event_key': message_content.get('alarmId'),
            'event_type': self._map_event_type(message_content.get('status')),
            'title': self._create_title(message_content),
            'description': message_content.get('displayName', ''),
            'severity': self._map_severity(message_content.get('severity')),
            'resource': self._extract_resource(message_content),
            'rule': message_content.get('displayName', ''),
            'occurred_at': self._parse_timestamp(raw_data.get('timestamp')),
            'additional_info': self._extract_additional_info(message_content, options)
        }
        
        # 데이터 검증
        event_model = EventModel(event_data, strict=False)
        event_model.validate()
        
        return [event_model.to_native()]
        
    except Exception as e:
        _LOGGER.error(f"Event parsing failed: {str(e)}")
        raise ERROR_EVENT_PARSING_FAILED(reason=str(e))
```

## 📊 데이터 모델

### EventModel (Schematics 기반)
```python
from schematics.models import Model
from schematics.types import StringType, DateTimeType, ModelType, DictType

class ResourceModel(Model):
    resource_id = StringType(default='')
    name = StringType(default='')
    resource_type = StringType(serialize_when_none=False)

class EventModel(Model):
    event_key = StringType(required=True)
    event_type = StringType(choices=['RECOVERY', 'ALERT'], default='ALERT')
    title = StringType(required=True)
    description = StringType(default='')
    severity = StringType(
        choices=['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'NOT_AVAILABLE', 'NONE'], 
        default='NONE'
    )
    resource = ModelType(ResourceModel)
    rule = StringType(default='')
    occurred_at = DateTimeType()
    additional_info = DictType(StringType(), default={})
    image_url = StringType(default='')
```

### gRPC 메시지 타입 변환
```python
# EventInfo 생성 함수 (실제 구현)
def EventInfo(event_data: EventModel):
    info = {
        'event_key': event_data['event_key'],           # string
        'event_type': event_data['event_type'],         # string (RECOVERY|ALERT)
        'description': event_data.get('description'),   # string
        'title': event_data['title'],                   # string
        'image_url': event_data.get('image_url'),       # string
        'severity': event_data['severity'],             # string (CRITICAL|ERROR|WARNING|INFO|NOT_AVAILABLE|NONE)
        'resource': change_struct_type(event_data['resource']),      # google.protobuf.Struct
        'rule': event_data.get('rule'),                 # string
        'occurred_at': utils.datetime_to_iso8601(event_data.get('occurred_at')), # string (ISO8601)
        'additional_info': change_struct_type(event_data.get('additional_info')) # google.protobuf.Struct
    }
    return event_pb2.EventInfo(**info)

# WebhookPluginInfo 생성 함수 (실제 구현)
def WebhookPluginInfo(result):
    result['metadata'] = change_struct_type(result['metadata'])  # google.protobuf.Struct로 변환
    return webhook_pb2.WebhookPluginInfo(**result)
```

## 🔄 데이터 변환 매핑

### OCI → SpaceONE 상태 매핑
| OCI Status | SpaceONE Event Type | SpaceONE Severity |
|------------|-------------------|------------------|
| FIRING | ALERT | CRITICAL/ERROR/WARNING |
| OK | RECOVERY | INFO |
| INSUFFICIENT_DATA | ALERT | NOT_AVAILABLE |

### OCI 심각도 매핑
| OCI Severity | SpaceONE Severity |
|--------------|------------------|
| CRITICAL | CRITICAL |
| ERROR | ERROR |
| WARNING | WARNING |
| INFO | INFO |

## 🛡️ 보안 및 인증

### 메시지 서명 검증
```python
def verify_oci_signature(payload, signature, cert_url):
    """OCI 메시지 서명 검증
    
    Args:
        payload (dict): 메시지 페이로드
        signature (str): Base64 인코딩된 서명
        cert_url (str): 인증서 URL
    
    Returns:
        bool: 검증 결과
    """
    try:
        # 인증서 다운로드
        cert_response = requests.get(cert_url, timeout=10)
        certificate = x509.load_pem_x509_certificate(cert_response.content)
        public_key = certificate.public_key()
        
        # 메시지 해시 생성
        message_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        signature_bytes = base64.b64decode(signature)
        
        # 서명 검증
        public_key.verify(
            signature_bytes,
            message_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        return True
        
    except Exception as e:
        _LOGGER.error(f"Signature verification failed: {str(e)}")
        return False
```

### HTTPS 통신 요구사항
- 모든 웹훅 URL은 HTTPS 프로토콜 필수
- TLS 1.2 이상 지원
- 유효한 SSL 인증서 필요

## 🔧 오류 처리

### 오류 코드 정의
```python
# 웹훅 관련 오류
ERROR_INVALID_WEBHOOK_URL = 'ERROR_INVALID_WEBHOOK_URL'
ERROR_WEBHOOK_VERIFICATION_FAILED = 'ERROR_WEBHOOK_VERIFICATION_FAILED'

# 이벤트 처리 오류
ERROR_UNSUPPORTED_MESSAGE_TYPE = 'ERROR_UNSUPPORTED_MESSAGE_TYPE'
ERROR_EVENT_PARSING_FAILED = 'ERROR_EVENT_PARSING_FAILED'
ERROR_INVALID_EVENT_DATA = 'ERROR_INVALID_EVENT_DATA'

# 인증 및 보안 오류
ERROR_SIGNATURE_VERIFICATION_FAILED = 'ERROR_SIGNATURE_VERIFICATION_FAILED'
ERROR_CERTIFICATE_DOWNLOAD_FAILED = 'ERROR_CERTIFICATE_DOWNLOAD_FAILED'
```

### 오류 응답 형식
```json
{
    "error": {
        "code": "ERROR_EVENT_PARSING_FAILED",
        "message": "Failed to parse OCI notification message",
        "details": {
            "reason": "Invalid JSON format in message field",
            "message_id": "12345678-1234-1234-1234-123456789012"
        }
    }
}
```

## 🧪 API 테스트

### 단위 테스트 예시
```python
class TestWebhookAPI(TestCase):
    
    def test_init_success(self):
        """웹훅 초기화 성공 테스트"""
        params = {
            'options': {
                'webhook_url': 'https://webhook.example.com/oci',
                'verify_ssl': True
            }
        }
        
        result = self.webhook_service.init(params)
        
        self.assertIn('metadata', result)
        self.assertEqual(
            result['metadata']['supported_providers'], 
            ['oracle']
        )
    
    def test_parse_firing_alarm(self):
        """FIRING 알람 파싱 테스트"""
        params = {
            'options': {'provider': 'oracle'},
            'data': {
                'type': 'Notification',
                'message': json.dumps({
                    'alarmId': 'test-alarm-id',
                    'status': 'FIRING',
                    'severity': 'CRITICAL',
                    'displayName': 'Test Alarm'
                })
            }
        }
        
        result = self.event_service.parse(params)
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['event_type'], 'ALERT')
        self.assertEqual(result[0]['severity'], 'CRITICAL')
```

### 통합 테스트
```bash
# gRPC 클라이언트를 사용한 API 테스트
grpcurl -plaintext -d '{
    "options": {
        "webhook_url": "https://webhook.example.com/oci"
    }
}' localhost:50051 spaceone.api.monitoring.plugin.Webhook/init

# 이벤트 파싱 테스트
grpcurl -plaintext -d '{
    "options": {"provider": "oracle"},
    "data": {
        "type": "Notification",
        "message": "{\"alarmId\":\"test\",\"status\":\"FIRING\"}"
    }
}' localhost:50051 spaceone.api.monitoring.plugin.Event/parse
```

## 📈 성능 고려사항

### 처리량 및 지연시간
- **목표 처리량**: 1,000 events/minute
- **목표 지연시간**: < 100ms per event
- **동시 연결**: 최대 50개 동시 웹훅 처리

### 최적화 방안
- **연결 풀링**: HTTP 클라이언트 연결 재사용
- **비동기 처리**: 무거운 작업의 백그라운드 처리
- **캐싱**: 인증서 및 메타데이터 캐싱

## 📋 상세 데이터 자료형 명세

### 🔍 요청 데이터 자료형 분석

#### 1. ParseEventRequest 구조
```typescript
interface ParseEventRequest {
    options: {
        provider: string;           // 필수, 프로바이더명 (예: "oracle")
        region?: string;            // 선택, 리전 코드 (예: "ap-seoul-1")
    };
    data: OCINotificationPayload;   // 필수, OCI 알림 페이로드
}
```

#### 2. OCI Notification 페이로드 구조 (공식 문서 기반)
```typescript
interface OCINotificationPayload {
    // 기본 메시지 정보 (필수 필드)
    type: "Notification" | "Subscription Confirmation";  // 메시지 타입
    messageId: string;              // UUID 형식 메시지 ID (예: "12345678-1234-1234-1234-123456789012")
    topicId: string;                // OCID 형식 토픽 ID (예: "ocid1.onstopic.oc1.ap-seoul-1.aaaaaaaaa...")
    subject: string;                // 알림 제목 (최대 100자)
    message: string;                // JSON 문자열 형태의 알람 상세 정보 (최대 64KB)
    timestamp: string;              // RFC 3339 형식 타임스탬프 (예: "2024-01-15T10:30:00.000Z")
    
    // 보안 관련 (필수 필드)
    signature: string;              // Base64 인코딩된 SHA256 서명
    signingCertURL: string;         // X.509 인증서 다운로드 URL (HTTPS)
    
    // 선택적 필드 (Subscription Confirmation 시에만 존재)
    subscribeURL?: string;          // 구독 확인용 URL (HTTPS)
    token?: string;                 // 구독 토큰 (UUID 형식)
    
    // 추가 메타데이터 (선택적)
    messageAttributes?: {           // 메시지 속성 (키-값 쌍)
        [key: string]: {
            Type: "String" | "Number" | "Binary";
            Value: string;
        };
    };
}
```

#### 2.1 필드별 상세 명세

| 필드명 | 타입 | 필수 | 제약 조건 | 설명 |
|--------|------|------|-----------|------|
| `type` | `string` | ✅ | `"Notification"` \| `"Subscription Confirmation"` | 메시지 유형 |
| `messageId` | `string` | ✅ | UUID v4 형식 | 메시지 고유 식별자 |
| `topicId` | `string` | ✅ | OCID 형식 | 알림 토픽 식별자 |
| `subject` | `string` | ✅ | 최대 100자 | 알림 제목 |
| `message` | `string` | ✅ | 최대 64KB | JSON 문자열 형태의 페이로드 |
| `timestamp` | `string` | ✅ | RFC 3339 형식 | 메시지 생성 시간 |
| `signature` | `string` | ✅ | Base64 인코딩 | SHA256 디지털 서명 |
| `signingCertURL` | `string` | ✅ | HTTPS URL | X.509 인증서 URL |
| `subscribeURL` | `string` | ❌ | HTTPS URL | 구독 확인 URL |
| `token` | `string` | ❌ | UUID 형식 | 구독 확인 토큰 |

#### 3. OCI 알람 메시지 내용 (message 필드 파싱 결과, 공식 문서 기반)
```typescript
interface OCIAlarmMessage {
    // 알람 기본 정보 (필수 필드)
    alarmId: string;                // OCID 형식 알람 ID (예: "ocid1.alarm.oc1.ap-seoul-1.aaaaaaaaa...")
    displayName: string;            // 알람 표시명 (최대 255자)
    status: "FIRING" | "OK" | "INSUFFICIENT_DATA";  // 알람 상태
    severity: "CRITICAL" | "ERROR" | "WARNING" | "INFO";  // 심각도
    compartmentId: string;          // OCID 형식 구획 ID (필수)
    
    // 메트릭 정보 (필수 필드)
    namespace: string;              // 메트릭 네임스페이스 (예: "oci_computeagent", "oci_lbaas")
    query: string;                  // MQL(Monitoring Query Language) 쿼리 (예: "CpuUtilization[1m].mean() > 80")
    
    // 시간 정보 (필수 필드)
    timestamp: string;              // RFC 3339 형식 타임스탬프
    timestampEpochMillis: number;   // Unix 타임스탬프 (밀리초)
    
    // 리소스 정보 (선택적 필드)
    resourceId?: string;            // OCID 형식 리소스 ID
    resourceDisplayName?: string;   // 리소스 표시명
    resourceGroup?: string;         // 리소스 그룹명
    
    // 메트릭 데이터 (선택적 필드)
    metricData?: Array<{
        namespace: string;          // 메트릭 네임스페이스
        name: string;              // 메트릭명 (예: "CpuUtilization")
        dimensions: {              // 메트릭 차원 (키-값 쌍)
            [key: string]: string;
        };
        value: number;             // 메트릭 값
        unit?: string;             // 단위 (예: "percent", "bytes")
        timestamp: string;         // 메트릭 수집 시간
    }>;
    
    // 알람 설정 정보 (선택적 필드)
    body?: string;                 // 알람 본문 메시지
    alarmUrl?: string;             // OCI 콘솔 알람 상세 페이지 URL
    repeatNotificationDuration?: string;  // 반복 알림 간격 (ISO 8601 duration)
    suppression?: {                // 알람 억제 정보
        description?: string;
        timeSuppressUntil?: string;
    };
    
    // 추가 메타데이터 (선택적 필드)
    freeformTags?: {               // 자유 형식 태그
        [key: string]: string;
    };
    definedTags?: {                // 정의된 태그
        [namespace: string]: {
            [key: string]: string;
        };
    };
}
```

#### 3.1 알람 메시지 필드별 상세 명세

| 필드명 | 타입 | 필수 | 제약 조건 | 설명 |
|--------|------|------|-----------|------|
| `alarmId` | `string` | ✅ | OCID 형식 | 알람 고유 식별자 |
| `displayName` | `string` | ✅ | 최대 255자 | 사용자 정의 알람 이름 |
| `status` | `string` | ✅ | 3가지 상태값 | 현재 알람 상태 |
| `severity` | `string` | ✅ | 4가지 심각도 | 알람 심각도 레벨 |
| `compartmentId` | `string` | ✅ | OCID 형식 | OCI 구획 식별자 |
| `namespace` | `string` | ✅ | - | 메트릭 네임스페이스 |
| `query` | `string` | ✅ | MQL 형식 | 모니터링 쿼리 언어 |
| `timestamp` | `string` | ✅ | RFC 3339 | 알람 발생 시간 |
| `timestampEpochMillis` | `number` | ✅ | Unix timestamp | 밀리초 단위 타임스탬프 |
| `resourceId` | `string` | ❌ | OCID 형식 | 관련 리소스 ID |
| `metricData` | `array` | ❌ | 객체 배열 | 메트릭 상세 데이터 |
| `body` | `string` | ❌ | 최대 1000자 | 알람 설명 메시지 |
| `alarmUrl` | `string` | ❌ | HTTPS URL | OCI 콘솔 링크 |

## 📋 SpaceONE 응답 데이터 자료형 명세

### 1. WebhookPluginInfo 메시지 구조 (SpaceONE 표준)
```protobuf
message WebhookPluginInfo {
    google.protobuf.Struct metadata = 1;
}
```

#### 필드 상세
| 필드명 | 프로토콜 버퍼 타입 | Python 타입 | 필수 여부 | 설명 |
|--------|-------------------|-------------|-----------|------|
| `metadata` | `google.protobuf.Struct` | `dict` | ✅ | 플러그인 메타데이터 |

#### metadata 구조 (실제 SpaceONE 구현 기반)
```json
{
    "supported_resource_type": ["inventory.CloudService"],  // 고정값: SpaceONE 리소스 타입
    "supported_providers": ["oracle"],                      // 고정값: OCI 프로바이더
    "webhook_url": "https://webhook.spaceone.dev/monitoring/oci",  // 웹훅 엔드포인트 URL
    "capabilities": {                                       // 플러그인 지원 기능
        "subscription_confirmation": true,                  // OCI 구독 확인 지원
        "message_verification": true,                       // 디지털 서명 검증 지원
        "retry_mechanism": true,                           // 실패 시 재시도 지원
        "supported_message_types": [                       // 지원하는 메시지 타입
            "Notification",
            "Subscription Confirmation"
        ],
        "supported_alarm_states": [                        // 지원하는 알람 상태
            "FIRING",
            "OK", 
            "INSUFFICIENT_DATA"
        ]
    }
}
```

#### metadata 필드별 상세 명세
| 필드 경로 | 타입 | 필수 | 제약 조건 | 설명 |
|-----------|------|------|-----------|------|
| `supported_resource_type` | `array<string>` | ✅ | 고정값 | SpaceONE 리소스 타입 목록 |
| `supported_providers` | `array<string>` | ✅ | 고정값 | 지원하는 클라우드 프로바이더 |
| `webhook_url` | `string` | ✅ | HTTPS URL | 웹훅 수신 엔드포인트 |
| `capabilities.subscription_confirmation` | `boolean` | ✅ | - | 구독 확인 처리 지원 여부 |
| `capabilities.message_verification` | `boolean` | ✅ | - | 메시지 서명 검증 지원 여부 |
| `capabilities.retry_mechanism` | `boolean` | ✅ | - | 재시도 메커니즘 지원 여부 |

### 2. EventsInfo 메시지 구조 (SpaceONE 표준)
```protobuf
message EventsInfo {
    repeated EventInfo results = 1;
}
```

#### 필드 상세
| 필드명 | 프로토콜 버퍼 타입 | Python 타입 | 필수 여부 | 설명 |
|--------|-------------------|-------------|-----------|------|
| `results` | `repeated EventInfo` | `list[dict]` | ✅ | 이벤트 정보 배열 |

### 3. EventInfo 메시지 구조 (SpaceONE 표준, 실제 구현 기반)
```protobuf
message EventInfo {
    string event_key = 1;
    string event_type = 2;
    string title = 3;
    string description = 4;
    string severity = 5;
    google.protobuf.Struct resource = 6;
    string rule = 7;
    string occurred_at = 8;
    google.protobuf.Struct additional_info = 9;
    string image_url = 10;
}
```

#### 필드 상세 (실제 SpaceONE 구현 기반)
| 필드명 | 프로토콜 버퍼 타입 | Python 타입 | Schematics 타입 | 필수 여부 | 제약 조건 | 설명 |
|--------|-------------------|-------------|-----------------|-----------|-----------|------|
| `event_key` | `string` | `str` | `StringType(required=True)` | ✅ | 최대 255자 | 이벤트 고유 키 (OCI alarmId) |
| `event_type` | `string` | `str` | `StringType(choices=[...])` | ✅ | `RECOVERY` \| `ALERT` | 이벤트 타입 |
| `title` | `string` | `str` | `StringType(required=True)` | ✅ | 최대 500자 | 이벤트 제목 |
| `description` | `string` | `str` | `StringType(default='')` | ❌ | 최대 2000자 | 이벤트 설명 |
| `severity` | `string` | `str` | `StringType(choices=[...])` | ✅ | 6가지 레벨 | 심각도 |
| `resource` | `google.protobuf.Struct` | `dict` | `ModelType(ResourceModel)` | ❌ | - | 리소스 정보 |
| `rule` | `string` | `str` | `StringType(default='')` | ❌ | 최대 255자 | 알림 규칙명 |
| `occurred_at` | `string` | `str` | `DateTimeType()` → ISO8601 | ❌ | RFC 3339 형식 | 발생 시간 |
| `additional_info` | `google.protobuf.Struct` | `dict` | `DictType(StringType())` | ❌ | 최대 10KB | 추가 정보 |
| `image_url` | `string` | `str` | `StringType(default='')` | ❌ | 최대 1000자 | 이미지 URL |

#### severity 제약 조건 상세
```python
severity_choices = [
    'CRITICAL',      # 치명적 - 즉시 대응 필요
    'ERROR',         # 오류 - 빠른 대응 필요  
    'WARNING',       # 경고 - 주의 필요
    'INFO',          # 정보 - 참고용
    'NOT_AVAILABLE', # 데이터 부족으로 판단 불가
    'NONE'           # 심각도 없음 (기본값)
]
```

#### event_type 제약 조건 상세
```python
event_type_choices = [
    'ALERT',         # 알람 발생 (기본값)
    'RECOVERY'       # 알람 해제/복구
]
```

#### resource 구조 (google.protobuf.Struct)
```json
{
    "resource_id": "string",      // 리소스 ID
    "name": "string",             // 리소스 이름
    "resource_type": "string"     // 리소스 타입 (예: "inventory.CloudService")
}
```

#### additional_info 구조 (google.protobuf.Struct)
```json
{
    "compartment_id": "string",   // OCI 구획 ID
    "namespace": "string",        // 메트릭 네임스페이스
    "metric_name": "string",      // 메트릭 이름
    "threshold_value": "string",  // 임계값
    "current_value": "string",    // 현재값
    "alarm_url": "string",        // 알람 URL
    "region": "string"            // 리전 정보
}
```

### 4. Empty 메시지 구조
```protobuf
message Empty {
    // 빈 메시지
}
```

## 🔄 SpaceONE 데이터 타입 변환 규칙

### 1. Struct 타입 변환
```python
from spaceone.core.pygrpc.message_type import change_struct_type

# Python dict → google.protobuf.Struct 변환
metadata_dict = {"key": "value"}
metadata_struct = change_struct_type(metadata_dict)
```

### 2. 날짜/시간 변환
```python
from spaceone.core import utils
from datetime import datetime

# datetime → ISO8601 문자열 변환
occurred_at = datetime.utcnow()
iso8601_string = utils.datetime_to_iso8601(occurred_at)
# 결과: "2024-01-28T10:30:00.000Z"
```

### 3. 이벤트 타입 매핑
| OCI 상태 | SpaceONE event_type |
|----------|-------------------|
| `FIRING` | `ALERT` |
| `OK` | `RECOVERY` |
| `INSUFFICIENT_DATA` | `ALERT` |

### 4. 심각도 매핑
| OCI 심각도 | SpaceONE severity |
|------------|------------------|
| `CRITICAL` | `CRITICAL` |
| `ERROR` | `ERROR` |
| `WARNING` | `WARNING` |
| `INFO` | `INFO` |
| 기타 | `NOT_AVAILABLE` |

## 🔬 Schematics 데이터 타입 상세 분석

### 1. Schematics 필드 타입과 옵션
```python
from schematics.types import (
    StringType, DateTimeType, ModelType, DictType, 
    ListType, FloatType, IntType, BooleanType
)

# 실제 EventModel 구현 (코드베이스 기반)
class ResourceModel(Model):
    resource_id = StringType(serialize_when_none=False)    # None일 때 직렬화 제외
    name = StringType(serialize_when_none=False)           # None일 때 직렬화 제외  
    resource_type = StringType(serialize_when_none=False)  # None일 때 직렬화 제외

class EventModel(Model):
    event_key = StringType(required=True)                  # 필수 필드
    event_type = StringType(                               # 선택 제한
        choices=['RECOVERY', 'ALERT'], 
        default='ALERT'
    )
    title = StringType(required=True)                      # 필수 필드
    description = StringType(default='')                   # 기본값 빈 문자열
    severity = StringType(                                 # 선택 제한 + 기본값
        choices=['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'NOT_AVAILABLE', 'NONE'], 
        default='NONE'
    )
    resource = ModelType(ResourceModel)                    # 중첩 모델
    rule = StringType(default='')                          # 기본값 빈 문자열
    occurred_at = DateTimeType()                           # datetime 객체
    additional_info = DictType(StringType(), default={})   # 문자열 값을 가진 딕셔너리
    image_url = StringType(default='')                     # 기본값 빈 문자열
```

### 2. Schematics 타입별 특징 및 검증 규칙

#### StringType 상세
```python
# 기본 사용법
field = StringType()                    # 기본 문자열
field = StringType(required=True)       # 필수 필드
field = StringType(default='default')   # 기본값 설정
field = StringType(choices=['A', 'B'])  # 선택 제한
field = StringType(min_length=1)        # 최소 길이
field = StringType(max_length=100)      # 최대 길이
field = StringType(serialize_when_none=False)  # None일 때 직렬화 제외

# 검증 예시
event_type = StringType(choices=['RECOVERY', 'ALERT'], default='ALERT')
# → 'RECOVERY' 또는 'ALERT'만 허용, 기본값은 'ALERT'
```

#### DateTimeType 상세
```python
# 기본 사용법
occurred_at = DateTimeType()            # datetime 객체 허용
occurred_at = DateTimeType(required=True)  # 필수 datetime

# Python에서 사용 시
from datetime import datetime
event_data = {
    'occurred_at': datetime.utcnow()    # datetime 객체
}

# gRPC 변환 시 (EventInfo에서)
'occurred_at': utils.datetime_to_iso8601(event_data.get('occurred_at'))
# → "2024-01-28T10:30:00.000Z" (ISO8601 문자열로 변환)
```

#### ModelType 상세
```python
# 중첩 모델 정의
resource = ModelType(ResourceModel)     # ResourceModel 인스턴스 허용

# 사용 예시
resource_data = {
    'resource_id': 'ocid1.instance.oc1...',
    'name': 'web-server-01',
    'resource_type': 'inventory.CloudService'
}
event_data = {
    'resource': resource_data           # dict 형태로 전달
}

# 검증 시 ResourceModel로 자동 변환됨
```

#### DictType 상세
```python
# 딕셔너리 타입 정의
additional_info = DictType(StringType(), default={})
# → 키는 문자열, 값도 문자열인 딕셔너리

# 사용 예시
additional_info_data = {
    'compartment_id': 'ocid1.compartment.oc1...',
    'namespace': 'oci_computeagent',
    'metric_name': 'CpuUtilization',
    'threshold_value': '80',            # 문자열로 저장
    'current_value': '85.5'             # 문자열로 저장
}
```

### 3. 데이터 검증 및 변환 과정

#### EventModel 검증 과정
```python
# 1. 원시 데이터 입력
raw_event_data = {
    'event_key': 'ocid1.alarm.oc1...',
    'title': 'High CPU Alert',
    'severity': 'CRITICAL',
    # ... 기타 필드
}

# 2. EventModel 인스턴스 생성
event_model = EventModel(raw_event_data, strict=False)
# strict=False: 정의되지 않은 필드 무시

# 3. 검증 수행
event_model.validate()
# → required 필드 확인
# → choices 제약 조건 확인  
# → 타입 검증 수행

# 4. 네이티브 Python 객체로 변환
event_dict = event_model.to_native()
# → Schematics 모델 → 일반 Python dict
```

### 4. gRPC 프로토콜 버퍼 타입 매핑

#### Python → Protobuf 타입 변환
| Schematics 타입 | Python 타입 | Protobuf 타입 | 변환 함수 |
|-----------------|-------------|---------------|-----------|
| `StringType` | `str` | `string` | 직접 매핑 |
| `DateTimeType` | `datetime` | `string` | `utils.datetime_to_iso8601()` |
| `ModelType` | `dict` | `google.protobuf.Struct` | `change_struct_type()` |
| `DictType` | `dict` | `google.protobuf.Struct` | `change_struct_type()` |
| `IntType` | `int` | `int32/int64` | 직접 매핑 |
| `FloatType` | `float` | `float/double` | 직접 매핑 |
| `BooleanType` | `bool` | `bool` | 직접 매핑 |

#### 변환 함수 상세
```python
from spaceone.core.pygrpc.message_type import change_struct_type
from spaceone.core import utils

# 1. Struct 타입 변환 (dict → google.protobuf.Struct)
resource_dict = {'resource_id': 'ocid1...', 'name': 'server'}
resource_struct = change_struct_type(resource_dict)

# 2. 날짜/시간 변환 (datetime → ISO8601 문자열)
occurred_at = datetime.utcnow()
iso8601_string = utils.datetime_to_iso8601(occurred_at)
# 결과: "2024-01-28T10:30:00.000Z"

# 3. 빈 값 처리
empty_dict = {}
empty_struct = change_struct_type(empty_dict)  # 빈 Struct 생성

none_value = None
iso_string = utils.datetime_to_iso8601(none_value)  # None 반환
```

### 5. 실제 데이터 플로우 예시

#### 완전한 데이터 변환 과정
```python
# 1. OCI 원시 데이터 (JSON)
oci_raw_data = {
    "type": "Notification",
    "messageId": "12345678-1234-1234-1234-123456789012",
    "message": '{"alarmId":"ocid1.alarm.oc1...","status":"FIRING"}'
}

# 2. OCI 메시지 파싱
message_content = json.loads(oci_raw_data.get('message', '{}'))
# → {"alarmId": "ocid1.alarm.oc1...", "status": "FIRING"}

# 3. SpaceONE EventModel 데이터 생성
event_data = {
    'event_key': message_content.get('alarmId'),        # str
    'event_type': 'ALERT',                              # str (choices)
    'title': 'High CPU Alert (FIRING)',                # str (required)
    'severity': 'CRITICAL',                             # str (choices)
    'resource': {                                       # dict → ModelType
        'resource_id': 'ocid1.instance.oc1...',
        'name': 'web-server-01',
        'resource_type': 'inventory.CloudService'
    },
    'occurred_at': datetime.utcnow(),                   # datetime
    'additional_info': {                                # dict → DictType
        'compartment_id': 'ocid1.compartment.oc1...',
        'namespace': 'oci_computeagent'
    }
}

# 4. Schematics 검증
event_model = EventModel(event_data, strict=False)
event_model.validate()  # 타입 및 제약 조건 검증
validated_data = event_model.to_native()

# 5. gRPC EventInfo 변환
event_info = {
    'event_key': validated_data['event_key'],                    # str → string
    'event_type': validated_data['event_type'],                  # str → string
    'title': validated_data['title'],                            # str → string
    'severity': validated_data['severity'],                      # str → string
    'resource': change_struct_type(validated_data['resource']),  # dict → Struct
    'occurred_at': utils.datetime_to_iso8601(validated_data['occurred_at']), # datetime → string
    'additional_info': change_struct_type(validated_data['additional_info'])  # dict → Struct
}

# 6. 최종 gRPC 메시지 생성
return event_pb2.EventInfo(**event_info)
```

## 🛠️ SpaceONE 표준 구현 패턴

### 1. Info 함수 구현 패턴
```python
# 표준 EventInfo 구현
def EventInfo(event_data: EventModel):
    """EventModel을 gRPC EventInfo로 변환"""
    info = {
        'event_key': event_data['event_key'],
        'event_type': event_data['event_type'],
        'description': event_data.get('description'),
        'title': event_data['title'],
        'image_url': event_data.get('image_url'),
        'severity': event_data['severity'],
        'resource': change_struct_type(event_data['resource']),
        'rule': event_data.get('rule'),
        'occurred_at': utils.datetime_to_iso8601(event_data.get('occurred_at')),
        'additional_info': change_struct_type(event_data.get('additional_info'))
    }
    return event_pb2.EventInfo(**info)

# 표준 EventsInfo 구현  
def EventsInfo(event_datas, **kwargs):
    """EventModel 리스트를 gRPC EventsInfo로 변환"""
    return event_pb2.EventsInfo(
        results=list(map(functools.partial(EventInfo, **kwargs), event_datas))
    )
```

### 2. gRPC 인터페이스 구현 패턴
```python
class Webhook(BaseAPI, webhook_pb2_grpc.WebhookServicer):
    def init(self, request, context):
        params, metadata = self.parse_request(request, context)
        with self.locator.get_service('WebhookService', metadata) as webhook_service:
            # WebhookPluginInfo로 변환하여 반환
            return self.locator.get_info('WebhookPluginInfo', webhook_service.init(params))

    def verify(self, request, context):
        params, metadata = self.parse_request(request, context)
        with self.locator.get_service('WebhookService', metadata) as webhook_service:
            webhook_service.verify(params)
            # Empty 메시지 반환
            return self.locator.get_info('EmptyInfo')
```

## 📚 참고 자료

- **SpaceONE API 문서**: [SpaceONE Plugin API Guide](https://spaceone-dev.gitbook.io/spaceone-apis/)
- **SpaceONE Core**: [SpaceONE Core Library](https://github.com/spaceone-dev/spaceone-core)
- **OCI Notification API**: [Oracle Cloud Notification Service](https://docs.oracle.com/en-us/iaas/api/#/en/notification/)
- **gRPC 문서**: [gRPC Python Guide](https://grpc.io/docs/languages/python/)
- **Protocol Buffers**: [Google Protocol Buffers](https://developers.google.com/protocol-buffers)

---

## 🎯 데이터 타입 검증 및 오류 처리

### 1. Schematics 검증 오류 유형

#### 필수 필드 누락 오류
```python
# 오류 발생 예시
event_data = {
    # 'event_key' 누락 (required=True)
    'title': 'Test Alert'
}

try:
    event_model = EventModel(event_data)
    event_model.validate()
except ValidationError as e:
    # 오류: {'event_key': ['This field is required.']}
    print(e.errors)
```

#### 선택 제한 위반 오류
```python
# 오류 발생 예시
event_data = {
    'event_key': 'test-key',
    'title': 'Test Alert',
    'event_type': 'INVALID_TYPE'  # choices에 없는 값
}

try:
    event_model = EventModel(event_data)
    event_model.validate()
except ValidationError as e:
    # 오류: {'event_type': ['Value must be one of RECOVERY, ALERT.']}
    print(e.errors)
```

#### 타입 불일치 오류
```python
# 오류 발생 예시
event_data = {
    'event_key': 'test-key',
    'title': 'Test Alert',
    'occurred_at': 'invalid-date-string'  # datetime 객체 필요
}

try:
    event_model = EventModel(event_data)
    event_model.validate()
except ValidationError as e:
    # 오류: {'occurred_at': ['Could not parse invalid-date-string.']}
    print(e.errors)
```

### 2. gRPC 변환 시 타입 안전성

#### None 값 처리
```python
# 안전한 None 값 처리
def safe_event_info_conversion(event_data):
    info = {
        'event_key': event_data['event_key'],
        'event_type': event_data['event_type'],
        'title': event_data['title'],
        
        # None 값 안전 처리
        'description': event_data.get('description') or '',
        'image_url': event_data.get('image_url') or '',
        'rule': event_data.get('rule') or '',
        
        # 복합 타입 안전 처리
        'resource': change_struct_type(event_data.get('resource') or {}),
        'additional_info': change_struct_type(event_data.get('additional_info') or {}),
        
        # 날짜 안전 처리
        'occurred_at': utils.datetime_to_iso8601(event_data.get('occurred_at')) or '',
        
        'severity': event_data.get('severity', 'NONE')
    }
    return event_pb2.EventInfo(**info)
```

### 3. 실제 운영 환경 고려사항

#### 대용량 데이터 처리
```python
# additional_info 크기 제한 고려
MAX_ADDITIONAL_INFO_SIZE = 1024 * 10  # 10KB

def validate_additional_info_size(additional_info):
    """additional_info 크기 검증"""
    if additional_info:
        serialized = json.dumps(additional_info)
        if len(serialized.encode('utf-8')) > MAX_ADDITIONAL_INFO_SIZE:
            raise ValueError(f"additional_info size exceeds {MAX_ADDITIONAL_INFO_SIZE} bytes")
    return additional_info
```

#### 문자열 길이 제한
```python
# 실제 필드별 권장 길이 제한
class EventModel(Model):
    event_key = StringType(required=True, max_length=255)
    title = StringType(required=True, max_length=500)
    description = StringType(default='', max_length=2000)
    rule = StringType(default='', max_length=255)
    image_url = StringType(default='', max_length=1000)
```

### 4. 성능 최적화 고려사항

#### 메모리 효율적인 데이터 처리
```python
# 대량 이벤트 처리 시 메모리 최적화
def process_events_efficiently(raw_events):
    """메모리 효율적인 이벤트 처리"""
    results = []
    
    for raw_event in raw_events:
        try:
            # 즉시 검증 및 변환
            event_model = EventModel(raw_event, strict=False)
            event_model.validate()
            
            # 네이티브 변환 후 즉시 gRPC 변환
            event_dict = event_model.to_native()
            event_info = EventInfo(event_dict)
            results.append(event_info)
            
            # 메모리 해제를 위한 명시적 삭제
            del event_model, event_dict
            
        except ValidationError as e:
            _LOGGER.error(f"Event validation failed: {e.errors}")
            continue
    
    return results
```

## 📊 타입 호환성 매트릭스

### OCI → Schematics → gRPC 변환 매트릭스

| OCI 필드 | OCI 타입 | Schematics 타입 | gRPC 타입 | 변환 함수 | 예시 |
|----------|----------|-----------------|-----------|-----------|------|
| `alarmId` | `string` | `StringType(required=True)` | `string` | 직접 | `"ocid1.alarm.oc1..."` |
| `status` | `string` | `StringType(choices=[...])` | `string` | 매핑 | `"FIRING"` → `"ALERT"` |
| `severity` | `string` | `StringType(choices=[...])` | `string` | 매핑 | `"CRITICAL"` → `"CRITICAL"` |
| `displayName` | `string` | `StringType(required=True)` | `string` | 직접 | `"High CPU Alert"` |
| `timestampEpochMillis` | `number` | `DateTimeType()` | `string` | `datetime` → ISO8601 | `1706441400000` → `"2024-01-28T10:30:00.000Z"` |
| `compartmentId` | `string` | `DictType(StringType())` | `Struct` | `change_struct_type()` | `{"compartment_id": "ocid1..."}` |
| `resourceId` | `string` | `ModelType(ResourceModel)` | `Struct` | `change_struct_type()` | `{"resource_id": "ocid1..."}` |

### 타입 안전성 보장 체크리스트

#### ✅ 입력 검증
- [ ] 필수 필드 존재 확인
- [ ] 선택 제한 값 검증
- [ ] 문자열 길이 제한 확인
- [ ] 날짜 형식 유효성 검증

#### ✅ 변환 안전성
- [ ] None 값 안전 처리
- [ ] 타입 변환 오류 처리
- [ ] 메모리 사용량 모니터링
- [ ] 성능 임계값 확인

#### ✅ 출력 검증
- [ ] gRPC 메시지 유효성
- [ ] 프로토콜 버퍼 직렬화 성공
- [ ] 필드 누락 없음 확인
- [ ] 데이터 무결성 검증

---

**문서 버전**: 1.2.0  
**마지막 업데이트**: 2024년 1월 28일  
**API 버전**: v1  
**SpaceONE 호환성**: v2.0+  
**데이터 타입 명세**: 완전 버전
