import logging

from spaceone.monitoring.manager.incident import Incident

_LOGGER = logging.getLogger(__name__)


class Incident_1_2(Incident):
    """Google Cloud Monitoring v1.2 형식 처리기"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _parse(self):
        """Google Cloud v1.2 특화 파싱 로직"""
        _LOGGER.debug(
            f"[Incident_1_2] Processing Google Cloud v1.2 incident: {self.incident}"
        )
