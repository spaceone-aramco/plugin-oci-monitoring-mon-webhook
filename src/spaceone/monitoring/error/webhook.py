from spaceone.core.error import *


class ERROR_INVALID_MESSAGE(ERROR_BASE):
    _message = "Invalid message format: {message}"


class ERROR_INVALID_WEBHOOK_URL(ERROR_BASE):
    _message = "Invalid webhook URL format"
