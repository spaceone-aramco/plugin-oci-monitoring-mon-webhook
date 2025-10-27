from schematics.models import Model
from schematics.types import DateTimeType, DictType, ModelType, StringType

__all__ = ["EventModel"]


class ResourceModel(Model):
    resource_id = StringType(serialize_when_none=False)
    name = StringType(serialize_when_none=False)
    resource_type = StringType(serialize_when_none=False)


class EventModel(Model):
    event_key = StringType(required=True)
    event_type = StringType(
        choices=["OK_TO_FIRING", "FIRING_TO_OK", "REPEAT", "RESET"], default="NONE"
    )
    title = StringType(required=True)
    description = StringType(default="")
    severity = StringType(
        choices=["CRITICAL", "ERROR", "WARNING", "INFO"], default="NONE"
    )
    resource = ModelType(ResourceModel)
    rule = StringType(default="")
    occurred_at = DateTimeType()
    additional_info = DictType(StringType(), default={})
    image_url = StringType(default="")
