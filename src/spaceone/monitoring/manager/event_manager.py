import logging

from spaceone.core.manager import BaseManager
from spaceone.monitoring.error.event import *
from spaceone.monitoring.manager.incident import Incident
from spaceone.monitoring.manager.incident_1_2 import Incident_1_2
from spaceone.monitoring.manager.incident_oci import IncidentOCI
from spaceone.monitoring.model.event_response_model import EventModel

_LOGGER = logging.getLogger(__name__)
_EXCEPTION_TO_PASS = ["Test notification"]


class EventManager(BaseManager):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def parse(self, raw_data):
        results = []

        # OCI Notification 메시지 감지
        if self._is_oci_notification(raw_data):
            _LOGGER.info("[EventManager] Processing OCI Notification message")
            inst = IncidentOCI(raw_data, "oci")
        else:
            # 기존 Google Cloud 형식 처리
            version = raw_data.get("version")
            if version == "1.2":
                inst = Incident_1_2(raw_data.get("incident", {}), version)
            elif version == "test":
                inst = Incident(raw_data.get("incident", {}), version)
            else:
                # unsupported version
                inst = Incident(raw_data.get("incident", {}), version)
                _LOGGER.warning(
                    f"[EventManager] Unsupported version: {version}, using default processor"
                )

        event_dict = inst.get_event_dict()
        event_vo = self._check_validity(event_dict)
        results.append(event_vo)
        _LOGGER.debug(f"[EventManager] Parsed event: {event_dict}")

        return results

    def _is_oci_notification(self, raw_data):
        """OCI Notification 메시지인지 확인

        Args:
            raw_data (dict): 원시 데이터

        Returns:
            bool: OCI Notification 메시지 여부
        """
        # OCI Notification 메시지의 특징적인 필드들 확인
        oci_fields = ["Type", "Message", "MessageId", "TopicArn"]

        # 모든 필드가 존재하고, Type이 Notification인 경우
        has_oci_fields = all(field in raw_data for field in oci_fields)
        is_notification = raw_data.get("Type") == "Notification"

        return has_oci_fields and is_notification

    @staticmethod
    def _check_validity(event_dict):
        """이벤트 데이터 유효성 검증 (강화된 에러 처리)"""
        try:
            # 필수 필드 사전 검증
            required_fields = ["event_key", "title"]
            for field in required_fields:
                if not event_dict.get(field):
                    _LOGGER.error(f"[EventManager] Missing required field: {field}")
                    raise ERROR_CHECK_VALIDITY(field=f"Missing required field: {field}")

            # Schematics 모델 검증
            event_result_model = EventModel(event_dict, strict=False)
            event_result_model.validate()
            event_result_model_primitive = event_result_model.to_native()

            _LOGGER.debug(
                f"[EventManager] Event validation successful for: {event_dict.get('event_key')}"
            )
            return event_result_model_primitive

        except Exception as e:
            error_msg = str(e)
            _LOGGER.error(f"[EventManager] Event validation failed: {error_msg}")
            raise ERROR_CHECK_VALIDITY(field=error_msg)
