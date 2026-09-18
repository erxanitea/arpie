from arpie.models.alert import Alert
from arpie.models.base import DatabaseBase, SCHEMA
from arpie.models.operator import OperatorMixin
from arpie.models.session import SessionMixin
from arpie.models.event import EventMixin
from arpie.models.action import ActionMixin
from arpie.models.threat_intel import ThreatIntelCacheMixin
from arpie.models.config import ConfigMixin


class Database(
    OperatorMixin,
    SessionMixin,
    EventMixin,
    ActionMixin,
    ThreatIntelCacheMixin,
    ConfigMixin,
    DatabaseBase,
):
    pass


__all__ = [
    "Database",
    "SCHEMA",
    "DatabaseBase",
    "OperatorMixin",
    "SessionMixin",
    "EventMixin",
    "ActionMixin",
    "ThreatIntelCacheMixin",
    "ConfigMixin",
]
