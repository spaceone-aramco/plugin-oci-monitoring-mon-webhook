# REQUEST 로그 명세서

## 개요

이 문서는 OCI Monitoring Webhook 플러그인의 테스트 실행 시 생성되는 **JSON 형태의 REQUEST 로그**에 대한 상세한 명세를 제공합니다. REQUEST 로그는 각 테스트의 입력 데이터와 실행 컨텍스트를 구조화된 JSON 형태로 기록하여 디버깅, 분석, 모니터링을 용이하게 합니다.

## REQUEST 로그 기본 구조

모든 REQUEST 로그는 다음과 같은 공통 구조를 가집니다:

```json
{
  "test_type": "테스트_유형_식별자",
  "description": "테스트 설명",
  "method": "호출_메서드명",
  // 테스트별 특화 필드들...
}
```

### 공통 필드

| 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|
| `test_type` | string | ✅ | 테스트 유형을 식별하는 고유 문자열 |
| `description` | string | ✅ | 테스트의 목적과 내용을 설명하는 한국어 문자열 |
| `method` | string | ✅ | 실제로 호출되는 SpaceONE 메서드명 |

## 테스트 타입별 상세 구조

### 1. webhook_init

플러그인 초기화 테스트의 REQUEST 로그입니다.

```json
{
  "test_type": "webhook_init",
  "description": "플러그인 정보 초기화",
  "method": "Webhook.init",
  "options": {}
}
```

#### 특화 필드

| 필드 | 타입 | 설명 |
|------|------|------|
| `options` | object | SpaceONE API 표준 옵션 필드 (일반적으로 빈 객체) |

**참고**: `Webhook.init`은 SpaceONE API 표준에 따라 `params = {'options': dict}` 형태로 호출됩니다.

### 2. webhook_verify_notification

OCI Notification 메시지 검증 테스트의 REQUEST 로그입니다.

```json
{
  "test_type": "webhook_verify_notification",
  "description": "OCI Notification 메시지 검증",
  "method": "Webhook.verify",
  "options": {
    "Type": "Notification",
    "MessageId": "12345678-1234-1234-1234-123456789012",
    "TopicArn": "oci:ons:us-ashburn-1:ocid1.tenancy.oc1..aaaaaaaaexample:monitoring-alerts",
    "Subject": "OCI Monitoring Alarm - High CPU Usage",
    "Message": "{\"id\":\"ocid1.alarm.oc1.iad.aaaaaaaaexample\",\"newState\":\"FIRING\",...}",
    "Timestamp": "2024-01-28T10:30:00.000Z",
    "SignatureVersion": "1",
    "Signature": "example-signature-hash",
    "SigningCertURL": "https://cell-1.notification.us-ashburn-1.oci.oraclecloud.com/20181201/certificate",
    "UnsubscribeURL": "https://cell-1.notification.us-ashburn-1.oci.oraclecloud.com/20181201/subscription/example",
    "Region": "us-ashburn-1"
  }
}
```

#### 특화 필드

| 필드 | 타입 | 설명 |
|------|------|------|
| `options` | object | SpaceONE API 표준 옵션 필드 (OCI 메시지 데이터 포함) |
| `options.Type` | string | OCI 메시지 타입 ("Notification") |
| `options.MessageId` | string | 고유 메시지 식별자 |
| `options.TopicArn` | string | OCI Notification Service Topic ARN |
| `options.Subject` | string | 알람 제목 |
| `options.Message` | string | JSON 형태의 알람 상세 정보 |
| `options.Timestamp` | string | ISO 8601 형식의 타임스탬프 |
| `options.SignatureVersion` | string | 서명 버전 |
| `options.Signature` | string | 메시지 서명 (보안용) |
| `options.SigningCertURL` | string | 서명 인증서 URL |
| `options.UnsubscribeURL` | string | 구독 해제 URL |
| `options.Region` | string | OCI 리전 |

**참고**: `Webhook.verify`는 SpaceONE API 표준에 따라 `params = {'options': dict}` 형태로 호출되며, OCI 메시지 데이터가 `options` 필드에 포함됩니다.

### 3. webhook_verify_subscription

OCI SubscriptionConfirmation 메시지 검증 테스트의 REQUEST 로그입니다.

```json
{
  "test_type": "webhook_verify_subscription",
  "description": "OCI SubscriptionConfirmation 메시지 검증",
  "method": "Webhook.verify",
  "options": {
    "Type": "SubscriptionConfirmation",
    "MessageId": "12345678-1234-1234-1234-123456789014",
    "TopicArn": "oci:ons:us-ashburn-1:ocid1.tenancy.oc1..aaaaaaaaexample:monitoring-alerts",
    "Message": "You have chosen to subscribe to the topic...",
    "SubscribeURL": "https://cell-1.notification.us-ashburn-1.oci.oracl...",
    "Timestamp": "2024-01-28T09:00:00.000Z",
    "SignatureVersion": "1",
    "Signature": "example-signature-hash",
    "SigningCertURL": "https://cell-1.notification.us-ashburn-1.oci.oraclecloud.com/20181201/certificate",
    "Region": "us-ashburn-1"
  }
}
```

#### 특화 필드

| 필드 | 타입 | 설명 |
|------|------|------|
| `options` | object | SpaceONE API 표준 옵션 필드 (OCI 구독 확인 메시지 데이터 포함) |
| `options.Type` | string | "SubscriptionConfirmation" |
| `options.Message` | string | 구독 확인 메시지 내용 |
| `options.SubscribeURL` | string | 구독 확인 URL (보안상 일부만 표시) |

**참고**: 구독 확인 메시지도 동일하게 `params = {'options': dict}` 형태로 처리됩니다.

### 4. event_parse_oci

OCI 알람 메시지 파싱 테스트의 REQUEST 로그입니다.

```json
{
  "test_type": "event_parse_oci",
  "scenario": "FIRING 알람 (High CPU Usage)",
  "description": "OCI Notification 메시지 파싱",
  "method": "Event.parse",
  "options": {},
  "data": {
    "Type": "Notification",
    "MessageId": "12345678-1234-1234-1234-123456789012",
    "TopicArn": "oci:ons:us-ashburn-1:ocid1.tenancy.oc1..aaaaaaaaexample:monitoring-alerts",
    "Subject": "OCI Monitoring Alarm - High CPU Usage",
    "Message": "{\"id\":\"ocid1.alarm.oc1.iad.aaaaaaaaexample\",\"newState\":\"FIRING\",\"previousState\":\"OK\",\"body\":\"CPU utilization exceeded 80% threshold for instance web-server-01\",\"timestamp\":\"2024-01-28T10:30:00.000Z\",\"alarmMetaData\":{\"displayName\":\"High CPU Usage Alert\",\"severity\":\"WARNING\",\"compartmentId\":\"ocid1.compartment.oc1..aaaaaaaaexample\",\"namespace\":\"oci_computeagent\",\"dimensions\":{\"resourceId\":\"ocid1.instance.oc1.iad.aaaaaaaaexample\"}}}",
    "Timestamp": "2024-01-28T10:30:00.000Z",
    "SignatureVersion": "1",
    "Signature": "example-signature-hash",
    "SigningCertURL": "https://cell-1.notification.us-ashburn-1.oci.oraclecloud.com/20181201/certificate",
    "UnsubscribeURL": "https://cell-1.notification.us-ashburn-1.oci.oraclecloud.com/20181201/subscription/example",
    "Region": "us-ashburn-1"
  }
}
```

#### 특화 필드

| 필드 | 타입 | 설명 |
|------|------|------|
| `scenario` | string | 테스트 시나리오명 (로깅 메타데이터) |
| `options` | object | SpaceONE API 표준 옵션 필드 |
| `data` | object | SpaceONE API 표준 데이터 필드 (파싱할 원본 OCI 메시지) |
| `data.Type` | string | OCI 메시지 타입 ("Notification") |
| `data.MessageId` | string | 고유 메시지 식별자 |
| `data.TopicArn` | string | OCI Notification Service Topic ARN |
| `data.Subject` | string | 알람 제목 |
| `data.Message` | string | JSON 형태의 OCI 알람 상세 정보 (파싱 대상) |
| `data.Timestamp` | string | ISO 8601 형식의 타임스탬프 |
| `data.Region` | string | OCI 리전 |

**참고**: `Event.parse`는 SpaceONE API 표준에 따라 `params = {'options': dict, 'data': dict}` 형태로 호출되며, 파싱할 원본 데이터가 `data` 필드에 포함됩니다.

#### 지원되는 시나리오

1. **FIRING 알람 (High CPU Usage)**: CPU 사용률 초과 알람
2. **OK 알람 (CPU 정상 복구)**: CPU 사용률 정상 복구
3. **Database 알람 (Connection Pool Full)**: 데이터베이스 연결 풀 포화
4. **Storage 알람 (Low Disk Space)**: 디스크 공간 부족
5. **최소 필드 알람**: 필수 필드만 포함된 최소 구성 알람

### 5. event_parse_google_cloud

Google Cloud Monitoring 호환성 테스트의 REQUEST 로그입니다.

```json
{
  "test_type": "event_parse_google_cloud",
  "scenario": "Google Cloud 호환성 테스트",
  "description": "Google Cloud Monitoring 메시지 파싱",
  "method": "Event.parse",
  "options": {},
  "data": {
    "incident": {
      "incident_id": "0.mtdi83m6w8ao",
      "condition_name": "VM Instance - CPU utilization",
      "state": "open",
      "summary": "CPU utilization for test VM Instance is above the threshold of 0.500 with a value of 0.790.",
      "policy_name": "test-server-cpu-alert-policy",
      "resource_id": "test-instance-id",
      "resource_name": "test-vm-instance",
      "started_at": 1675315787,
      "url": "https://console.cloud.google.com/monitoring/alerting/incidents/0.mtdi83m6w8ao"
    },
    "version": "test"
  }
}
```

#### 특화 필드

| 필드 | 타입 | 설명 |
|------|------|------|
| `scenario` | string | 테스트 시나리오명 (로깅 메타데이터) |
| `options` | object | SpaceONE API 표준 옵션 필드 |
| `data` | object | SpaceONE API 표준 데이터 필드 (파싱할 Google Cloud 메시지) |
| `data.incident` | object | Google Cloud incident 정보 |
| `data.incident.incident_id` | string | Google Cloud incident 식별자 |
| `data.incident.condition_name` | string | 알람 조건명 |
| `data.incident.state` | string | 알람 상태 ("open", "closed") |
| `data.incident.summary` | string | 알람 요약 메시지 |
| `data.incident.policy_name` | string | 알람 정책명 |
| `data.incident.resource_id` | string | 리소스 식별자 |
| `data.incident.resource_name` | string | 리소스명 |
| `data.incident.started_at` | number | Unix 타임스탬프 |
| `data.incident.url` | string | Google Cloud Console URL |
| `data.version` | string | Google Cloud 메시지 버전 |

**참고**: Google Cloud 호환성을 위해 기존 형식을 유지하되, SpaceONE API 표준에 맞게 `data` 필드에 포함됩니다.

## REQUEST 로그 분석 방법

### 1. JSON 파서 활용

#### jq를 사용한 분석

```bash
# 모든 REQUEST 로그 추출 및 포맷팅
grep -A 20 '\[REQUEST\] {' server_debug.log | jq '.'

# 특정 테스트 타입만 필터링
grep -A 20 '"test_type": "event_parse_oci"' server_debug.log

# 시나리오별 검색
grep -A 20 '"scenario": "FIRING 알람"' server_debug.log

# 테스트 타입 통계
grep '"test_type":' server_debug.log | sort | uniq -c
```

#### Python을 사용한 분석

```python
import re
import json

with open('server_debug.log', 'r', encoding='utf-8') as f:
    content = f.read()

# REQUEST JSON 블록 추출
pattern = r'\[REQUEST\] (\{.*?\n\})'
matches = re.findall(pattern, content, re.DOTALL)

# 각 REQUEST 분석
for i, match in enumerate(matches, 1):
    try:
        json_obj = json.loads(match)
        test_type = json_obj.get('test_type')
        scenario = json_obj.get('scenario', 'N/A')
        print(f"Request {i}: {test_type} - {scenario}")
    except json.JSONDecodeError as e:
        print(f"JSON 파싱 오류: {e}")
```

### 2. 테스트별 분석 포인트

#### Webhook.init
- `options` 필드 구조 검증
- 플러그인 메타데이터 반환값 확인

#### Webhook.verify
- `options` 필드의 OCI 메시지 구조 검증
- 필수 필드 (Type, MessageId, Message 등) 존재 확인
- OCI 메시지 타입별 처리 로직 검증

#### Event.parse
- `data` 필드의 원본 메시지 구조 확인
- OCI Message 필드 내 JSON 파싱 정확성 검증
- 상태 매핑 규칙 확인 (FIRING → ALERT, OK → RECOVERY)
- 심각도 변환 로직 검증

### 3. 모니터링 및 자동화

#### 로그 모니터링 스크립트 예시

```bash
#!/bin/bash
# REQUEST 로그 모니터링 스크립트

LOG_FILE="server_debug.log"
ALERT_THRESHOLD=5

# REQUEST 로그 개수 확인
REQUEST_COUNT=$(grep -c '\[REQUEST\]' "$LOG_FILE")

if [ "$REQUEST_COUNT" -lt "$ALERT_THRESHOLD" ]; then
    echo "⚠️  REQUEST 로그가 예상보다 적습니다: $REQUEST_COUNT개"
fi

# JSON 유효성 검사
INVALID_JSON=$(grep -A 20 '\[REQUEST\] {' "$LOG_FILE" | python3 -c "
import sys, json, re
content = sys.stdin.read()
pattern = r'\[REQUEST\] (\{.*?\n\})'
matches = re.findall(pattern, content, re.DOTALL)
invalid_count = 0
for match in matches:
    try:
        json.loads(match)
    except:
        invalid_count += 1
print(invalid_count)
")

if [ "$INVALID_JSON" -gt 0 ]; then
    echo "❌ 유효하지 않은 JSON REQUEST 로그: $INVALID_JSON개"
else
    echo "✅ 모든 REQUEST 로그가 유효한 JSON 형태입니다"
fi
```

## 활용 사례

### 1. 디버깅
- 특정 테스트 실패 시 해당 REQUEST 로그를 통해 입력 데이터 확인
- 알람 파싱 오류 시 `alarm_info` 필드 상세 분석

### 2. 성능 분석
- 각 테스트별 입력 데이터 크기 측정
- 복잡한 시나리오의 처리 시간 분석

### 3. 호환성 검증
- Google Cloud 메시지와 OCI 메시지의 구조적 차이점 분석
- 새로운 OCI 서비스 지원 시 필드 매핑 검증

### 4. 자동화된 테스트
- REQUEST 로그를 기반으로 한 회귀 테스트 생성
- CI/CD 파이프라인에서의 자동 검증

## 보안 고려사항

### 1. 민감 정보 처리
- `signature`, `subscribe_url` 등은 보안상 일부만 표시
- 실제 OCI 자격증명이나 토큰은 로그에 포함되지 않음

### 2. 로그 보관
- REQUEST 로그에는 테스트 데이터만 포함되므로 상대적으로 안전
- 실제 운영 환경에서는 로그 순환 정책 적용 권장

## SpaceONE API 형식 준수 가이드라인

### 🎯 필수 준수 사항

모든 REQUEST 로그는 **반드시** SpaceONE API 표준을 준수해야 합니다.

#### 1. **API별 필수 필드**

| SpaceONE API | 필수 필드 | 설명 |
|--------------|-----------|------|
| `Webhook.init` | `options` | 플러그인 초기화 옵션 |
| `Webhook.verify` | `options` | 메시지 검증 데이터 |
| `Event.parse` | `options`, `data` | 옵션 + 파싱할 원본 데이터 |

#### 2. **금지된 필드**

다음 필드들은 **절대 사용하지 않습니다**:
- ❌ `input_parameters` → ✅ `options` 사용
- ❌ `input_data` → ✅ `options` 또는 `data` 사용
- ❌ `validation_criteria` → 제거 (테스트용 필드)
- ❌ `expected_output` → 제거 (테스트용 필드)

#### 3. **표준 구조 템플릿**

**Webhook API 템플릿**:
```json
{
  "test_type": "webhook_[api_type]",
  "description": "API 설명",
  "method": "Webhook.[method]",
  "options": {
    // SpaceONE API 표준 필드
    // 실제 API 호출 시 사용되는 데이터
  }
}
```

**Event API 템플릿**:
```json
{
  "test_type": "event_parse_[type]",
  "scenario": "시나리오명",
  "description": "API 설명",
  "method": "Event.parse",
  "options": {},
  "data": {
    // 파싱할 원본 메시지 데이터
  }
}
```

### 🔧 개발 및 구현 가이드라인

#### 1. **새로운 테스트 작성 시**
- SpaceONE API 표준 필드만 사용
- 실제 소스코드의 `@check_required` 데코레이터 확인
- 문서의 템플릿 구조 준수

#### 2. **기존 코드 수정 시**
- 비표준 필드를 표준 필드로 변경
- 테스트용 필드 완전 제거
- SpaceONE API 호출 방식과 일치하도록 수정

#### 3. **코드 리뷰 시 확인사항**
- [ ] SpaceONE 필수 필드 존재 여부
- [ ] 비표준 필드 사용 여부
- [ ] 실제 API 구조와 일치성
- [ ] 문서와 코드 일관성

### ⚠️ 준수하지 않을 경우의 문제점

1. **운영 환경 불일치**: 테스트와 실제 환경의 구조 차이
2. **개발자 혼란**: 잘못된 API 사용법 학습
3. **유지보수 어려움**: 비표준 구조로 인한 코드 복잡성
4. **SpaceONE 호환성 문제**: 플랫폼 표준 위반

### 📋 검증 방법

#### 자동 검증 스크립트
```bash
# SpaceONE API 준수 여부 검증
python3 -c "
import re, json
with open('server_debug.log', 'r') as f:
    content = f.read()
matches = re.findall(r'\[REQUEST\] (\{.*?\n\})', content, re.DOTALL)
for match in matches:
    data = json.loads(match)
    method = data.get('method', '')
    if 'Webhook' in method and 'options' not in data:
        print(f'❌ {data.get(\"test_type\")}: options 필드 누락')
    elif 'Event.parse' in method and ('options' not in data or 'data' not in data):
        print(f'❌ {data.get(\"test_type\")}: options/data 필드 누락')
"
```

## 문제 해결

### 자주 발생하는 문제

1. **JSON 파싱 오류**
   - 원인: 멀티라인 JSON 구조
   - 해결: `re.DOTALL` 플래그 사용

2. **필드 누락**
   - 원인: `null` 값 처리
   - 해결: 안전한 딕셔너리 접근 (`get()` 메서드 사용)

3. **인코딩 문제**
   - 원인: 한글 문자 포함
   - 해결: `encoding='utf-8'` 명시적 지정

4. **SpaceONE API 형식 위반**
   - 원인: 비표준 필드 사용 또는 필수 필드 누락
   - 해결: 위의 가이드라인 준수 및 자동 검증 스크립트 활용

## 실제 로그 검증 결과

### 검증 통계 (test_results_20251019_222002 기준)

```
📊 SpaceONE 형식 적용 후 검증 결과
============================================================
✅ 총 REQUEST 로그: 9개
✅ 고유 테스트 타입: 5개  
✅ JSON 파싱 성공률: 100%
✅ SpaceONE API 준수율: 100% (완벽 준수)
✅ 비표준 필드 제거: 100% 완료
✅ 필수 필드 완전성: 100%
```

### SpaceONE 형식 준수 개선 결과

#### 🔴 수정 전 (test_results_20251019_214730)
- **SpaceONE API 준수**: 0% (비표준 필드 사용)
- **문제점**: `input_data`, `validation_criteria`, `expected_output` 등 테스트용 필드 사용

#### 🟢 수정 후 (test_results_20251019_222002)  
- **SpaceONE API 준수**: 100% ✅ **완벽 준수**
- **개선사항**: 
  - 모든 API에 표준 필드 적용 (`options`, `data`)
  - 비표준 필드 완전 제거
  - 실제 SpaceONE API 구조와 100% 일치

### 테스트 타입별 검증 상세

| 테스트 타입 | 로그 수 | 필수 필드 | SpaceONE API 필드 | 상태 |
|-------------|---------|-----------|-------------------|------|
| `webhook_init` | 1개 | ✅ | `options` ✅ | 완료 |
| `webhook_verify_notification` | 1개 | ✅ | `options` (OCI 메시지) ✅ | 완료 |
| `webhook_verify_subscription` | 1개 | ✅ | `options` (구독 확인) ✅ | 완료 |
| `event_parse_oci` | 5개 | ✅ | `options`, `data` (OCI 원본) ✅ | 완료 |
| `event_parse_google_cloud` | 1개 | ✅ | `options`, `data` (GCP 원본) ✅ | 완료 |

### 품질 지표

- **SpaceONE API 준수**: 모든 REQUEST 로그가 SpaceONE API 표준 형식 준수
- **구조 일관성**: 공통 메타데이터 + API별 특화 필드 구조 일관성 유지
- **데이터 완전성**: `options`/`data` 필드 100% 포함
- **JSON 유효성**: 모든 로그가 유효한 JSON 형태
- **인코딩 안정성**: 한글 문자 완벽 지원
- **파싱 안정성**: 멀티라인 JSON 구조 안정적 처리

---

**문서 버전**: 3.1  
**최종 업데이트**: 2025-10-19  
**기반 로그**: `test_results_20251019_222002/server_debug.log` (SpaceONE 형식 적용 완료)  
**총 REQUEST 로그**: 9개 (5개 테스트 타입)  
**SpaceONE API 준수**: ✅ 100% 완벽 준수  
**테스트 스크립트 수정**: ✅ 완료 (SpaceONE 형식 적용)  
**가이드라인 추가**: ✅ 완료 (개발 및 구현 가이드라인)  
**검증 상태**: ✅ 모든 항목 통과 (준수율 0% → 100% 개선)
