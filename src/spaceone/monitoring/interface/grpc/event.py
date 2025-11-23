import ipaddress
import logging
from urllib.parse import urlparse

import requests

from spaceone.api.monitoring.plugin import event_pb2, event_pb2_grpc
from spaceone.core.pygrpc import BaseAPI

_LOGGER = logging.getLogger(__name__)


class Event(BaseAPI, event_pb2_grpc.EventServicer):
    pb2 = event_pb2
    pb2_grpc = event_pb2_grpc

    def parse(self, request, context):
        params, metadata = self.parse_request(request, context)

        request_data = params.get("data")
        if "ConfirmationURL" in request_data:
            # OCI ConfirmationURL detect
            confirmation_url = request_data["ConfirmationURL"]
            self.safe_confirmation_request(confirmation_url)
            return self.locator.get_info("EventsInfo", [])
        else:
            # OCI Alarm data detect
            with self.locator.get_service("EventService", metadata) as event_service:
                return self.locator.get_info("EventsInfo", event_service.parse(params))

    def safe_confirmation_request(self, url, timeout=10):
        """safe confirmation request"""
        try:
            parsed = urlparse(url)

            # only https allowed
            if parsed.scheme != "https":
                raise ValueError("Only HTTPS URLs are allowed")

            # internal ip block
            try:
                ip = ipaddress.ip_address(parsed.hostname)
                if ip.is_private or ip.is_loopback:
                    raise ValueError("Internal IP addresses not allowed")
            except ValueError:
                pass  # domain name is allowed

            # safe request
            response = requests.get(
                url, timeout=timeout, allow_redirects=False, verify=True
            )
            return response

        except Exception as e:
            _LOGGER.error(f"failed to process confirmation url: {e}")
            raise
