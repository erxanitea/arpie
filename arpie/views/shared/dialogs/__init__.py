"""
Dialogs — modal presentation, one module per dialog.

Split out of a single 355-line module; each dialog is now independently readable.
"""

from .evidence import show_evidence_dialog
from .seal import show_seal_dialog
from .mfa_setup import show_mfa_setup_dialog
from .mfa_disable import show_mfa_disable_dialog

__all__ = [
    "show_evidence_dialog",
    "show_seal_dialog",
    "show_mfa_setup_dialog",
    "show_mfa_disable_dialog",
]
