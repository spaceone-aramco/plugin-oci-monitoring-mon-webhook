import logging

from spaceone.core.manager import BaseManager
from spaceone.monitoring.error.event import (
    ERROR_CHECK_VALIDITY,
    ERROR_UNSUPPORTED_DATA_FORMAT,
)
from spaceone.monitoring.manager.oci_alarm import OCIAlarm
from spaceone.monitoring.model.event_response_model import EventModel

_LOGGER = logging.getLogger(__name__)
_EXCEPTION_TO_PASS = ["Test notification"]


class EventManager(BaseManager):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def parse(self, raw_data):
        results = []

        # OCI data detect (dedupeKey and alarmMetaData exist)
        if "dedupeKey" in raw_data and "alarmMetaData" in raw_data:
            inst = OCIAlarm(raw_data)
            event_dict = inst.get_event_dict()
            event_vo = self._check_validity(event_dict)
            results.append(event_vo)
        else:
            raise ERROR_UNSUPPORTED_DATA_FORMAT()

        return results

    @staticmethod
    def _check_validity(event_dict):
        try:
            event_result_model = EventModel(event_dict, strict=False)
            event_result_model.validate()
            event_result_model_primitive = event_result_model.to_native()
            return event_result_model_primitive

        except Exception as e:
            raise ERROR_CHECK_VALIDITY(field=e)

