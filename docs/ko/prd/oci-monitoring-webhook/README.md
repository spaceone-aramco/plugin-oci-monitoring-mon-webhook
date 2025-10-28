# SpaceONE OCI Monitoring Webhook Plugin PRD

## 1. 개요

### 1.1 목적
Oracle Cloud Infrastructure(OCI) Monitoring 서비스에서 발생하는 알람을 SpaceONE 플랫폼으로 전달받아 표준화된 이벤트 형식으로 변환하는 웹훅 플러그인을 개발합니다.

### 1.2 사용자 스토리
**As a** SpaceONE 관리자  
**I want to** OCI Monitoring 알람을 SpaceONE에서 통합 관리  
**So that** 멀티 클라우드 환경에서 일관된 모니터링 및 알람 관리가 가능합니다.

### 1.3 복잡도 분류
**SIMPLE_COLLECTOR** - 단일 웹훅 엔드포인트를 통한 OCI 알람 데이터 수신 및 변환

## 2. 기능 요구사항

### 2.1 핵심 기능
- OCI Monitoring 알람 웹훅 데이터 수신
- OCI 알람 데이터를 SpaceONE 표준 이벤트 형식으로 변환
- 알람 심각도 매핑 (Critical, Warning, Info)

### 2.2 OCI 알람 데이터 구조
```json
{
  "dedupeKey": "6b28ce05-7021-4407-b9c0-c5d7896b7361",
  "title": "Notifications",
  "body": "outside 1-10 Alram",
  "type": "OK_TO_FIRING",
  "severity": "CRITICAL",
  "timestampEpochMillis": 1761563100000,
  "timestamp": "2025-10-27T11:05:00Z",
  "alarmMetaData": [
    {
      "id": "ocid1.alarm.oc1.ap-seoul-1.aaaaaaaazxxxxxx",
      "status": "FIRING",
      "severity": "CRITICAL",
      "namespace": "oci_autonomous_database",
      "query": "DatabaseAvailability[5m]{deploymentType = \"Shared\", AutonomousDBType = \"ATP\", region = \"ap-seoul-1\"}.rate() not in (1, 10)",
      "totalMetricsFiring": 1,
      "dimensions": [
        {
          "AutonomousDBType": "ATP",
          "deploymentType": "Shared",
          "resourceId": "OCID1.AUTONOMOUSDATABASE.OC1.AP-SEOUL-1.ANUWGLJRExxxxxx",
          "resourceName": "ARAMCODEVAUTONOMOUS",
          "region": "ap-seoul-1",
          "displayName": "DatabaseAvailability"
        }
      ],
      "alarmUrl": "https://cloud.oracle.com/monitoring/alarms/ocid1.alarm.oc1.ap-seoul-1.aaaaaaaazxxxxxx?region=ap-seoul-1",
      "alarmSummary": "This is aramco_dev_autonomous_database_alarm_1. (DatabaseAvailability)",
      "metricValues": [
        {
          "DatabaseAvailability[5m]{deploymentType = \"Shared\", AutonomousDBType = \"ATP\", region = \"ap-seoul-1\"}.rate()": "0.00"
        }
      ]
    }
  ],
  "notificationType": "Grouped messages across metric streams",
  "version": 1.5
}
```

### 2.3 OCI 알람 데이터 필드 설명
| 필드명 | 타입 | 설명 |
|--------|------|------|
| `dedupeKey` | String | 중복 제거를 위한 고유 키 |
| `title` | String | 알림 제목 |
| `body` | String | 알림 본문 내용 |
| `type` | String | 알람 상태 변화 타입 (OK_TO_FIRING, FIRING_TO_OK 등) |
| `severity` | String | 알람 심각도 (CRITICAL, WARNING, INFO) |
| `timestampEpochMillis` | Number | 알람 발생 시간 (밀리초 단위) |
| `timestamp` | String | 알람 발생 시간 (ISO 8601 형식) |
| `alarmMetaData` | Array | 알람 메타데이터 배열 (여러 알람 지원) |
| `notificationType` | String | 알림 타입 설명 |
| `version` | Number | OCI 알람 데이터 버전 |

### 2.4 알람 메타데이터 구조
| 필드명 | 타입 | 설명 |
|--------|------|------|
| `id` | String | OCI 알람 OCID |
| `status` | String | 알람 상태 (FIRING, OK) |
| `severity` | String | 알람 심각도 |
| `namespace` | String | OCI 서비스 네임스페이스 |
| `query` | String | 메트릭 쿼리 조건 |
| `totalMetricsFiring` | Number | 발화된 메트릭 수 |
| `dimensions` | Array | 리소스 차원 정보 |
| `alarmUrl` | String | OCI 콘솔 알람 URL |
| `alarmSummary` | String | 알람 요약 설명 |
| `metricValues` | Array | 메트릭 값 정보 |

## 3. 기술 명세

### 3.1 플러그인 아키텍처
```
SpaceONE OCI Monitoring Webhook Plugin
├── Service Layer (webhook_service.py, event_service.py)
├── Manager Layer (event_manager.py, oci_alarm.py)
└── Model Layer (event_response_model.py)
```

### 3.2 gRPC 서비스 인터페이스

#### 3.2.1 Webhook Service
```protobuf
service Webhook {
    rpc init (PluginInitRequest) returns (PluginInfo);
    rpc verify (PluginVerifyRequest) returns (Empty);
}
```

#### 3.2.2 Event Service  
```protobuf
service Event {
    rpc parse (ParseEventRequest) returns (EventsInfo);
}
```

### 3.3 데이터 변환 매핑

#### 3.3.1 OCI → SpaceONE 이벤트 매핑
| OCI 필드 | SpaceONE 필드 | 변환 규칙 |
|----------|---------------|-----------|
| `dedupeKey` | `event_key` | 직접 매핑 (중복 제거 키) |
| `type` | `event_type` | OK_TO_FIRING, FIRING_TO_OK, REPEAT, RESET |
| `title` + `severity` | `title` | 가공 매핑 |
| `body` | `description` | 직접 매핑 |
| `severity` | `severity` | CRITICAL, ERROR, WARNING, INFO |
| `alarmMetaData[0].dimensions[0].resourceId` | `resource.resource_id` | 첫 번째 리소스 ID |
| `alarmMetaData[0].dimensions[0].resourceName` | `resource.name` | 첫 번째 리소스 이름 |
| - | `resource.resource_type` | `inventory.CloudService` 고정값
| `alarmMetaData[0].query` | `rule` | 직접 매핑 |
| `timestamp` | `occurred_at` | 직접 매핑 |
| `alarmMetaData[0].alarmUrl` | `additional_info.alarm_url` | OCI 콘솔 링크 |


### 3.4 SpaceONE 표준 이벤트 모델
```python
class EventModel(Model):
    event_key = StringType(required=True)                   # dedupeKey
    event_type = StringType(choices=['OK_TO_FIRING', 'FIRING_TO_OK', 'REPEAT', 'RESET'], default='NONE')  # type 변환
    title = StringType(required=True)                       # title
    description = StringType(default='')                    # body
    severity = StringType(choices=['CRITICAL', 'ERROR', 'WARNING', 'INFO'], default='NONE')  # severity
    resource = ModelType(ResourceModel)                     # dimensions 정보
    rule = StringType(default='')                           # alarmMetaData[0].query
    occurred_at = DateTimeType()                            # 2025-10-27T11:05:00Z
    additional_info = DictType(StringType(), default={})    # 추가 메타데이터

class ResourceModel(Model):
    resource_id = StringType(serialize_when_none=False)     # dimensions[0].resourceId
    name = StringType(serialize_when_none=False)            # dimensions[0].resourceName
    resource_type = StringType(serialize_when_none=False)   # inventory.CloudService 값 고정
    
```

## 4. 인증 및 보안

### 4.1 웹훅 인증
- **방식**: HMAC-SHA256 서명 검증
- **헤더**: `X-OCI-Signature`
- **시크릿**: SpaceONE 플러그인 설정에서 관리

### 4.2 필요 권한
- OCI Monitoring 서비스 접근 권한 (읽기 전용)
- 웹훅 엔드포인트 설정 권한

## 5. 성능 및 확장성

### 5.1 성능 목표
- **응답 시간**: 웹훅 수신 후 1초 이내 처리 완료
- **처리량**: 초당 100개 알람 이벤트 처리
- **가용성**: 99.9% 이상

### 5.2 확장성 고려사항
- 비동기 이벤트 처리 지원
- 배치 처리를 통한 성능 최적화
- 메모리 사용량 최적화

## 6. 에러 처리

### 6.1 OCI 웹훅 에러 상황
현재 플러그인과 동일한 에러 처리 방식 사용:

| 에러 상황 | 사용 에러 | 처리 방식 |
|-----------|-----------|-----------|
| OCI 이벤트 파싱 실패 | `ERROR_PARSE_EVENT` | 이벤트 파서에서 발생하는 모든 파싱 에러 |
| OCI 이벤트 모델 검증 실패 | `ERROR_CHECK_VALIDITY(field=e)` | 현재 `event_manager.py`와 동일한 처리 |
| OCI 알람 데이터 변환 실패 | `ERROR_CHECK_VALIDITY(field=e)` | 검증 실패 시 필드 정보와 함께 에러 발생 |
| 기타 모든 에러 상황 | 일반 Exception 처리 | 로그 기록 후 기본값으로 처리 |

**핵심**: 현재 플러그인에서 실제 정의된 `ERROR_PARSE_EVENT`와 `ERROR_CHECK_VALIDITY` 에러 사용

### 6.2 SpaceONE Core 예외 활용
현재 플러그인에서 **실제로 정의된** 에러들을 OCI에서도 동일하게 사용:

```python
# src/spaceone/monitoring/error/event.py (현재 정의된 에러들)
from spaceone.core.error import *

class ERROR_PARSE_EVENT(ERROR_BASE):
    _message = 'Failed to parse event'

class ERROR_CHECK_VALIDITY(ERROR_BASE):
    _message = 'Event model is not validate (field= {field})'
```

### 6.3 OCI에서의 동일한 에러 사용 방식
현재 `event_manager.py`와 동일한 패턴으로 OCI 알람 검증:

```python
# 현재 event_manager.py에서 사용 중인 방식
@staticmethod
def _check_validity(event_dict):
    try:
        event_result_model = EventModel(event_dict, strict=False)
        event_result_model.validate()
        event_result_model_primitive = event_result_model.to_native()
        return event_result_model_primitive
    except Exception as e:
        raise ERROR_CHECK_VALIDITY(field=e)

# OCI 알람 매니저에서도 동일하게 사용
class OCIAlarmManager(BaseManager):
    def parse_oci_alarm(self, raw_data):
        try:
            # OCI 데이터 변환 로직
            event_dict = self._convert_oci_to_spaceone(raw_data)
            
            # 현재 플러그인과 동일한 검증 방식
            event_vo = self._check_validity(event_dict)
            return event_vo
            
        except Exception as e:
            # 이벤트 파서에서 발생하는 에러는 ERROR_PARSE_EVENT 사용
            raise ERROR_PARSE_EVENT()
    
    def _convert_oci_to_spaceone(self, raw_data):
        try:
            # OCI alarmMetaData 파싱 로직
            # dedupeKey, timestampEpochMillis 등 변환
            return event_dict
        except Exception as e:
            # 파싱 실패 시 ERROR_PARSE_EVENT 발생
            raise ERROR_PARSE_EVENT()
    
    @staticmethod
    def _check_validity(event_dict):
        # 현재 event_manager.py와 완전히 동일한 로직
        try:
            event_result_model = EventModel(event_dict, strict=False)
            event_result_model.validate()
            event_result_model_primitive = event_result_model.to_native()
            return event_result_model_primitive
        except Exception as e:
            raise ERROR_CHECK_VALIDITY(field=e)
```

## 7. 로깅 및 모니터링

### 7.1 로깅 정책
- **민감 정보 제외**: 웹훅 시크릿, 인증 토큰
- **포함 정보**: 알람 ID, 처리 시간, 변환 결과
- **로그 레벨**: DEBUG, INFO, WARNING, ERROR

### 7.2 메트릭 수집
- 웹훅 수신 건수
- 이벤트 변환 성공/실패율
- 평균 처리 시간
- 알람 타입별 통계

## 8. 테스트 전략

### 8.1 단위 테스트
```python
# unittest.mock을 활용한 테스트 구조
class TestOCIEventManager(unittest.TestCase):
    @patch('spaceone.monitoring.connector.oci_monitoring_connector.OCIMonitoringConnector')
    def test_parse_oci_alarm_data(self, mock_connector):
        # OCI 알람 데이터 파싱 테스트
        pass
    
    def test_convert_severity_mapping(self):
        # 심각도 매핑 테스트
        pass
```

### 8.2 통합 테스트
- OCI Monitoring 웹훅 시뮬레이션
- SpaceONE 이벤트 생성 검증
- 에러 상황별 처리 검증

### 8.3 테스트 데이터
```json
{
  "test_scenarios": [
    {
      "name": "autonomous_database_availability",
      "oci_alarm_type": "OK_TO_FIRING",
      "namespace": "oci_autonomous_database",
      "severity": "CRITICAL",
      "expected_resource_type": "inventory.CloudService",
      "sample_data": {
        "dedupeKey": "test-dedupe-key-001",
        "title": "Database Availability Alert",
        "body": "Database availability test alarm",
        "type": "OK_TO_FIRING",
        "severity": "CRITICAL",
        "timestampEpochMillis": 1698765432000,
        "timestamp": "2023-10-31T12:30:32Z",
        "version": 1.5,
        "alarmMetaData": [
          {
            "id": "ocid1.alarm.oc1.test.example",
            "status": "FIRING",
            "severity": "CRITICAL",
            "namespace": "oci_autonomous_database",
            "query": "DatabaseAvailability[5m].rate() < 1",
            "dimensions": [
              {
                "resourceId": "ocid1.autonomousdatabase.oc1.test.example",
                "resourceName": "TEST_AUTONOMOUS_DB",
                "region": "ap-seoul-1",
                "AutonomousDBType": "ATP",
                "deploymentType": "Shared"
              }
            ]
          }
        ]
      }
    }
  ]
}
```

## 9. 배포 및 운영

### 9.1 Docker 이미지
```dockerfile
FROM cloudforet/python-core:2
ENV SPACEONE_PORT 50051
ENV SERVER_TYPE grpc
COPY src /tmp/src
WORKDIR /tmp/src
RUN python3 setup.py install
ENTRYPOINT ["spaceone"]
CMD ["grpc", "spaceone.monitoring"]
```

### 9.2 플러그인 등록
```yaml
# register_plugin.yml
name: plugin-oci-monitoring-webhook
service_type: monitoring.Webhook
image: cloudforet/plugin-oci-monitoring-webhook
labels:
  - OCI
  - Monitoring
  - Webhook
provider: oracle
capability:
  supported_schema: ["oci_monitoring_webhook_v1.0"]
template:
  options:
    webhook_url: "https://webhook.spaceone.dev/monitoring/webhooks/oci"
    secret_key: "your-webhook-secret-key"
```

## 10. 마이그레이션 가이드

### 10.1 GCP → OCI 변경사항
| 구성 요소 | GCP (기존) | OCI (신규) |
|-----------|------------|------------|
| 알람 데이터 구조 | Google Cloud Monitoring | OCI Monitoring |
| 인증 방식 | Google Cloud 서비스 계정 | OCI 웹훅 서명 |
| 리소스 타입 | GCP 서비스 | OCI 서비스 |
| 네임스페이스 | `gcp_monitoring` | `oci_monitoring` |

### 10.2 코드 변경 포인트
1. **데이터 파서**: 
   - `incident.py`, `incident_1_2.py` → `oci_alarm.py`
   - GCP `incident` 구조 → OCI `alarmMetaData` 배열 구조 처리
   - 단일 알람 → 다중 알람 지원 (alarmMetaData 배열)

2. **이벤트 매니저**: 
   - `event_manager.py`의 버전 처리 하지 않음 (oci 버전이 없음)
   - `raw_data.get('incident', {})` → `raw_data` 직접 처리

3. **데이터 변환**:
   - `dedupeKey` → `event_key` 매핑 추가
   - `alarmMetaData` 배열 처리 로직 (첫 번째 요소 사용)
   - `dimensions` 배열에서 리소스 정보 추출

4. **커넥터**: `GoogleCloudConnector` → `OCIMonitoringConnector`

5. **설정**: `global_conf.py`의 커넥터 설정 변경

6. **테스트**: GCP 모킹 → OCI 모킹으로 변경

### 10.3 주요 구조 변경사항
```python
# 기존 GCP 구조
{
  "version": "1.2",
  "incident": {
    "incident_id": "...",
    "condition_name": "...",
    "state": "open"
  }
}

# 신규 OCI 구조  
{
  "version": 1.5,
  "dedupeKey": "...",
  "alarmMetaData": [
    {
      "id": "...",
      "status": "FIRING",
      "dimensions": [...]
    }
  ]
}
```

## 11. 참고 자료

### 11.1 OCI 문서
- [OCI Monitoring Service](https://docs.oracle.com/en-us/iaas/Content/Monitoring/home.htm)
- [OCI Alarms](https://docs.oracle.com/en-us/iaas/Content/Monitoring/Tasks/managingalarms.htm)
- [OCI Notifications](https://docs.oracle.com/en-us/iaas/Content/Notification/home.htm)
- [Alarm Message Format](https://docs.public.content.oci.oraclecloud.com/en-us/iaas/Content/Monitoring/alarm-message-format.htm)
- [Example Alarm Message](https://docs.public.content.oci.oraclecloud.com/en-us/iaas/Content/Monitoring/alarm-message-examples.htm)

### 11.2 SpaceONE 문서
- [SpaceONE Plugin Development Guide](https://docs.spaceone.megazone.io/)
- [SpaceONE Monitoring Plugin API](https://docs.spaceone.megazone.io/api/monitoring/)

## 12. 릴리즈 계획

### 12.1 Phase 1 (MVP)
- 기본 OCI 알람 수신 및 변환
- Compute, Database 리소스 지원
- 기본 에러 처리

### 12.2 Phase 2 (확장)
- 추가 OCI 서비스 지원 (Load Balancer, Storage)
- 고급 필터링 기능
- 성능 최적화

### 12.3 Phase 3 (고도화)
- 커스텀 메트릭 지원
- 알람 상관관계 분석
- 대시보드 연동

---

**문서 버전**: v1.0  
**작성일**: 2024-10-27  
**작성자**: SpaceONE Development Team  
**승인자**: TBD
