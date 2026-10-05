"""
Application settings — paths, interfaces, and the composed runtime config.

``CONFIG`` is the single module-level instance the rest of the app reads.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path

from arpie.config.thresholds import DetectionThresholds, SealModeConfig, ThreatIntelConfig, _default_db_path


@dataclass
class AppConfig:
    app_name: str = "Arpie"
    db_path: str = field(default_factory=_default_db_path)
    interface: str = os.environ.get("ARPIE_IFACE", "")
    export_dir: str = os.environ.get("ARPIE_EXPORT_DIR", "")
    thresholds: DetectionThresholds = field(default_factory=DetectionThresholds)
    seal: SealModeConfig = field(default_factory=SealModeConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)

    def default_reports_dir(self) -> Path:
        """Resolve the export directory: explicit env override, else Documents, else home.

        Callers may still override this with an operator-saved preference; this is
        only the fallback when nothing has been configured.
        """
        configured = (self.export_dir or "").strip()
        if configured:
            return Path(configured).expanduser()
        documents = Path.home() / "Documents"
        if documents.is_dir():
            return documents / "Arpie_Reports"
        return Path.home() / "Arpie_Reports"


CONFIG = AppConfig()
