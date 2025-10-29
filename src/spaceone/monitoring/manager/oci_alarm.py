import logging
from datetime import datetime

_LOGGER = logging.getLogger(__name__)


class OCIAlarm:
    def __init__(self, *args, **kwargs):
        self.event_dict = {}
        self.raw_data = args[0]

        self.event_dict["event_type"] = self._update_event_type(
            self.raw_data.get("type")
        )
        self.event_dict["severity"] = self._update_severity(
            self.raw_data.get("severity")
        )
        self.event_dict["title"] = self._update_title()
        self.event_dict["occurred_at"] = self._update_occurred_at()
        self._update_resource_and_rule_and_additional()

        self._update()

    def _update(self):
        map_keys = {"dedupeKey": "event_key", "body": "description"}
        for k, v in map_keys.items():
            item = self.raw_data.get(k, None)
            if item:
                self.event_dict[v] = item
            else:
                _LOGGER.warning(f"Fail to get key: {k}")

    def _update_title(self):
        # title = title + severity
        # ex) Database Availability Alert (CRITICAL)
        title = self.raw_data.get("title", "no title")
        severity = self.raw_data.get("severity", "unknown")
        return f"{title} ({severity})"

    def _update_resource_and_rule_and_additional(self):
        # resource_id = alarmMetaData[0].dimensions[0].resourceId
        # resource_name = alarmMetaData[0].dimensions[0].resourceName
        # resource_type = inventory.CloudService
        alarm_metadata = self.raw_data.get("alarmMetaData", [])
        alarm_metadata_0 = alarm_metadata[0]
        dimensions = alarm_metadata_0.get("dimensions", [])
        dimension_0 = dimensions[0]

        resource = {
            "resource_id": dimension_0.get("resourceId", ""),
            "name": dimension_0.get("resourceName", ""),
            "resource_type": "inventory.CloudService",
        }

        additional = {
            "alarm_url": alarm_metadata_0.get("alarmUrl", ""),
        }

        self.event_dict["resource"] = resource
        self.event_dict["rule"] = alarm_metadata_0.get("query", "")
        self.event_dict["additional_info"] = additional

    def _update_occurred_at(self):
        timestamp_str = self.raw_data.get("timestamp")
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ")
        return timestamp

    def get_event_dict(self):
        return self.event_dict

    @staticmethod
    def _update_event_type(type):
        if type == "FIRING_TO_OK" or type == "RESET":
            return "RECOVERY"
        elif type == "OK_TO_FIRING" or type == "REPEAT":
            return "ALERT"

    @staticmethod
    def _update_severity(severity):
        if severity == "CRITICAL":
            return "CRITICAL"
        elif severity == "ERROR":
            return "ERROR"
        elif severity == "WARNING":
            return "WARNING"
        elif severity == "INFO":
            return "INFO"
        else:
            return "NONE"
