import logging
import time
from datetime import datetime

_LOGGER = logging.getLogger(__name__)


class Incident:
    def __init__(self, *args, **kwargs):
        self.event_dict = {}
        self.incident = args[0]
        self.version = args[1]
        self.event_dict["title"] = self._update_title()
        self.event_dict["event_type"] = self._update_event_type(
            self.incident.get("state", "")
        )
        self.event_dict["severity"] = self._update_severity(
            self.incident.get("state", "")
        )
        self.event_dict["resource"] = self._update_resource()
        self.event_dict["additional_info"] = self._update_additional()
        self.event_dict["occurred_at"] = self._update_ocurred_at()

        self._update()

    def _update(self):
        map_keys = {
            "incident_id": "event_key",
            "summary": "description",
            "policy_name": "rule",
        }
        for k, v in map_keys.items():
            item = self.incident.get(k, None)
            if item:
                self.event_dict[v] = item
            else:
                _LOGGER.debug(f"[Incident] Missing optional field: {k}")

    def _update_title(self):
        # title = condition_name + state
        # ex) VM Instance - CPU utilization (open)
        # ex) VM Instance - CPU utilization (closed)
        title_1 = self.incident.get("condition_name", "no title")
        title_2 = self.incident.get("state", "unknown")
        return f"{title_1} ({title_2})"

    def _update_resource(self):
        resource = {
            "resource_id": self.incident.get("resource_id", ""),
            "name": self.incident.get("resource_name", ""),
            "resource_type": "inventory.CloudService",
        }
        return resource

    def _update_additional(self):
        additional = {}
        map_keys = {"url": "url"}

        for k, v in map_keys.items():
            item = self.incident.get(k, None)
            if item:
                additional[v] = item
            else:
                _LOGGER.debug(f"[Incident] Missing optional additional field: {k}")
        return additional

    def _update_ocurred_at(self):
        """발생 시간 처리 (기본적인 에러 처리 포함)"""
        try:
            timestamp = self.incident.get("started_at", time.time())

            # 타임스탬프 유효성 검증
            if isinstance(timestamp, str):
                try:
                    timestamp = float(timestamp)
                except ValueError:
                    _LOGGER.warning(
                        f"[Incident] Invalid timestamp format: {timestamp}, using current time"
                    )
                    timestamp = time.time()
            elif not isinstance(timestamp, (int, float)):
                _LOGGER.warning(
                    f"[Incident] Invalid timestamp type: {type(timestamp)}, using current time"
                )
                timestamp = time.time()

            # Unix timestamp 범위 검증 (1970년 이후, 2100년 이전)
            if timestamp < 0 or timestamp > 4102444800:  # 2100-01-01
                _LOGGER.warning(
                    f"[Incident] Timestamp out of range: {timestamp}, using current time"
                )
                timestamp = time.time()

            datetimeobj = datetime.fromtimestamp(timestamp)
            return datetimeobj

        except (OSError, ValueError, OverflowError) as e:
            _LOGGER.error(
                f"[Incident] Failed to convert timestamp: {e}, using current time"
            )
            return datetime.now()

    def get_event_dict(self):
        return self.event_dict

    @staticmethod
    def _update_event_type(event_state):
        return "RECOVERY" if event_state == "closed" else "ALERT"

    @staticmethod
    def _update_severity(event_state):
        return "WARNING" if event_state == "open" else "INFO"
