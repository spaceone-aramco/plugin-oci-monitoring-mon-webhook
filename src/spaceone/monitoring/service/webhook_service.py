import logging

from spaceone.core.service import *
from spaceone.monitoring.error import *
from spaceone.monitoring.error.webhook import ERROR_INVALID_MESSAGE

_LOGGER = logging.getLogger(__name__)


@authentication_handler
@authorization_handler
@event_handler
class WebhookService(BaseService):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @check_required(["options"])
    def init(self, params):
        """웹훅 플러그인 초기화

        Args:
            params (dict): {
                'options': dict - 웹훅 설정 옵션
            }

        Returns:
            dict: 플러그인 메타데이터
        """
        options = params.get("options", {})

        # 기본 메타데이터 반환
        metadata = {
            "supported_resource_type": ["inventory.CloudService"],
            "supported_providers": ["oracle"],
            "capabilities": {
                "subscription_confirmation": True,
                "message_verification": True,
            },
        }

        # 웹훅 URL이 제공된 경우 추가
        webhook_url = options.get("webhook_url")
        if webhook_url:
            metadata["webhook_url"] = webhook_url

        _LOGGER.info(f"[WebhookService] Plugin initialized with metadata: {metadata}")

        return {"metadata": metadata}

    @transaction
    @check_required(["options"])
    def verify(self, params):
        """웹훅 메시지 검증

        Args:
            params (dict): {
                'options': dict - 검증 옵션 및 메시지 데이터
            }

        Returns:
            None

        Raises:
            ERROR_INVALID_MESSAGE: 메시지 형식이 올바르지 않은 경우
        """
        options = params.get("options", {})

        # 기본적인 메시지 구조 검증
        message_type = options.get("Type")
        if not message_type:
            _LOGGER.error("[WebhookService] Missing message Type field")
            raise ERROR_INVALID_MESSAGE(message="Missing Type field")

        # OCI Notification 메시지 타입 검증
        valid_types = [
            "Notification",
            "SubscriptionConfirmation",
            "UnsubscribeConfirmation",
        ]
        if message_type not in valid_types:
            _LOGGER.error(f"[WebhookService] Invalid message type: {message_type}")
            raise ERROR_INVALID_MESSAGE(message=f"Invalid message type: {message_type}")

        # 구독 확인 메시지 처리
        if message_type == "SubscriptionConfirmation":
            _LOGGER.info("[WebhookService] Subscription confirmation received")
            # 실제 환경에서는 구독 확인 URL을 호출해야 하지만, 기본 구현에서는 로깅만 수행
            return

        # 일반 알림 메시지 기본 검증
        if message_type == "Notification":
            message_content = options.get("Message")
            if not message_content:
                _LOGGER.error("[WebhookService] Missing Message content")
                raise ERROR_INVALID_MESSAGE(message="Missing Message content")

        _LOGGER.info(
            f"[WebhookService] Message verification completed for type: {message_type}"
        )
        return
