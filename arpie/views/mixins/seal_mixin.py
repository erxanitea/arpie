from arpie.views.mixins._typing import MixinBase


class SealMixin(MixinBase):
    """Thin delegation to ``seal_controller`` for endpoint isolation actions."""

    def activate_seal(self, dlg):
        self.seal_controller.activate(dlg)

    def block_ip(self, ip: str, dlg):
        self.seal_controller.block_ip(ip, dlg)

    def unblock_ip(self, ip: str):
        self.seal_controller.unblock_ip(ip)
