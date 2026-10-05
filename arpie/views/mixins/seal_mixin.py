from arpie.views.mixins._typing import MixinBase


class SealMixin(MixinBase):
    """Thin delegation to ``seal_controller`` for endpoint isolation actions."""

    def activate_seal(self, dlg, target_ip=None, event_id=None):
        return self.seal_controller.activate(dlg, target_ip=target_ip, event_id=event_id)

    def block_ip(self, ip: str, dlg, event_id=None):
        return self.seal_controller.block_ip(ip, dlg, event_id=event_id)

    def unblock_ip(self, ip: str):
        return self.seal_controller.unblock_ip(ip)
