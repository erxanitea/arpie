from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from arpie.models.base import DatabaseBase
    MixinBase = DatabaseBase
else:
    MixinBase = object
