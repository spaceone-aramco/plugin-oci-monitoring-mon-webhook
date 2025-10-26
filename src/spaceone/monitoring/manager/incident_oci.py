import json
import logging
from datetime import datetime

from spaceone.monitoring.manager.incident import Incident

_LOGGER = logging.getLogger(__name__)


class IncidentOCI(Incident):
    """OCI Monitoring 알람 전용 처리기"""

    def __init__(self, oci_notification, version="oci"):
        """OCI Notification 메시지 초기화

        Args:
            oci_notification (dict): OCI Notification 메시지
            version (str): 버전 정보 (기본값: 'oci')
        """
        self.oci_notification = oci_notification
        self.version = version

        # OCI Message 파싱
        try:
            message_content = oci_notification.get("Message", "{}")
            if isinstance(message_content, str):
                self.alarm_message = json.loads(message_content)
            else:
                self.alarm_message = message_content
        except (json.JSONDecodeError, TypeError) as e:
            _LOGGER.error(f"[IncidentOCI] Failed to parse OCI message: {e}")
            self.alarm_message = {}

        # 기본 incident 데이터 구조로 변환
        self.incident = self._convert_oci_to_incident()

        # 부모 클래스 초기화
        super().__init__(self.incident, version)

    def _convert_oci_to_incident(self):
        """OCI 알람 메시지를 기존 incident 형식으로 변환"""
        alarm_meta = self.alarm_message.get("alarmMetaData", {})

        # 기본 incident 구조 생성
        incident = {
            "incident_id": self.alarm_message.get("id", ""),
            "condition_name": alarm_meta.get("displayName", "OCI Alarm"),
            "state": self._convert_oci_state(
                self.alarm_message.get("newState", "UNKNOWN")
            ),
            "summary": self.alarm_message.get("body", ""),
            "policy_name": alarm_meta.get("displayName", ""),
            "resource_id": self._extract_resource_id(),
            "resource_name": self._extract_resource_name(),
            "started_at": self._convert_timestamp(self.alarm_message.get("timestamp")),
            "url": self._generate_console_url(),
        }

        return incident

    def _convert_oci_state(self, oci_state):
        """OCI 알람 상태를 표준 상태로 변환

        Args:
            oci_state (str): OCI 알람 상태 (FIRING, OK, etc.)

        Returns:
            str: 표준 상태 (open, closed)
        """
        state_mapping = {
            "FIRING": "open",
            "OK": "closed",
            "RESET": "closed",
            "UNKNOWN": "open",  # 안전을 위해 알 수 없는 상태는 open으로 처리
        }

        converted_state = state_mapping.get(oci_state.upper(), "open")
        _LOGGER.debug(
            f"[IncidentOCI] Converted OCI state {oci_state} to {converted_state}"
        )

        return converted_state

    def _extract_resource_id(self):
        """OCI 알람에서 리소스 ID 추출"""
        # OCI 알람 메타데이터에서 리소스 정보 추출
        dimensions = self.alarm_message.get("alarmMetaData", {}).get("dimensions", {})

        # 일반적인 리소스 ID 필드들 확인
        resource_id_fields = ["resourceId", "instanceId", "compartmentId"]

        for field in resource_id_fields:
            if field in dimensions:
                return dimensions[field]

        # 기본값으로 알람 ID 사용
        return self.alarm_message.get("id", "")

    def _extract_resource_name(self):
        """OCI 알람에서 리소스 이름 추출"""
        alarm_meta = self.alarm_message.get("alarmMetaData", {})

        # 알람 표시명을 리소스 이름으로 사용
        resource_name = alarm_meta.get("displayName", "")

        if not resource_name:
            # 대체값으로 알람 ID 사용
            resource_name = f"OCI Resource {self.alarm_message.get('id', 'Unknown')}"

        return resource_name

    def _convert_timestamp(self, timestamp_str):
        """OCI 타임스탬프를 Unix timestamp로 변환

        Args:
            timestamp_str (str): OCI 타임스탬프 (ISO 8601 형식)

        Returns:
            int: Unix timestamp
        """
        if not timestamp_str:
            return int(datetime.now().timestamp())

        try:
            # ISO 8601 형식 파싱 (예: 2024-01-28T10:30:00.000Z)
            if timestamp_str.endswith("Z"):
                timestamp_str = timestamp_str[:-1] + "+00:00"

            dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            return int(dt.timestamp())

        except (ValueError, AttributeError) as e:
            _LOGGER.warning(
                f"[IncidentOCI] Failed to parse timestamp {timestamp_str}: {e}"
            )
            return int(datetime.now().timestamp())

    def _generate_console_url(self):
        """OCI Console 알람 상세 페이지 URL 생성"""
        alarm_id = self.alarm_message.get("id", "")
        region = self.oci_notification.get("Region", "us-ashburn-1")

        if alarm_id:
            # OCI Console 알람 URL 형식
            return (
                f"https://cloud.oracle.com/monitoring/alarms/{alarm_id}?region={region}"
            )

        return "https://cloud.oracle.com/monitoring/alarms"

    def _update_severity(self, event_state):
        """OCI 특화 심각도 매핑

        Args:
            event_state (str): 이벤트 상태

        Returns:
            str: SpaceONE 심각도
        """
        # OCI 알람 심각도 정보가 있는 경우 사용
        alarm_severity = self.alarm_message.get("alarmMetaData", {}).get("severity")

        if alarm_severity:
            severity_mapping = {
                "CRITICAL": "CRITICAL",
                "ERROR": "ERROR",
                "WARNING": "WARNING",
                "INFO": "INFO",
            }
            mapped_severity = severity_mapping.get(alarm_severity.upper())
            if mapped_severity:
                return mapped_severity

        # 기본 상태 기반 심각도 매핑 사용
        return super()._update_severity(event_state)

    def get_event_dict(self):
        """OCI 특화 이벤트 딕셔너리 반환"""
        event_dict = super().get_event_dict()

        # OCI 특화 추가 정보
        oci_info = {
            "Oci Alarm Id": self.alarm_message.get("id", ""),
            "Oci Region": self.oci_notification.get("Region", ""),
            "Oci Compartment Id": self.alarm_message.get("alarmMetaData", {}).get(
                "compartmentId", ""
            ),
            "Oci Namespace": self.alarm_message.get("alarmMetaData", {}).get(
                "namespace", ""
            ),
        }

        # 빈 값 제거
        oci_info = {k: v for k, v in oci_info.items() if v}

        # additional_info에 OCI 정보 추가
        if event_dict.get("additional_info"):
            event_dict["additional_info"].update(oci_info)
        else:
            event_dict["additional_info"] = oci_info

        return event_dict
