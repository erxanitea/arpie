from typing import Optional


from arpie.views.mixins._typing import MixinBase


class ReportsMixin(MixinBase):
    """Export directory management and thin delegation to the report/capture controllers."""

    def set_reports_dir(self, path_str: str) -> tuple[bool, str]:
        from pathlib import Path
        cleaned = path_str.strip()
        if not cleaned:
            return False, "Export path cannot be empty."
        try:
            target = Path(cleaned).expanduser().resolve()
            target.mkdir(parents=True, exist_ok=True)
            self.reports_dir = target
            self.db.set_config("reports_dir", str(target))
            self.status_toast = f"Export directory updated to: {target}"
            self.update_view_content()
            self.page.update()
            return True, str(target)
        except Exception as ex:
            return False, str(ex)

    def open_reports_directory(self):
        import platform
        import subprocess
        system = platform.system()
        path = str(self.reports_dir)
        try:
            if system == "Linux":
                subprocess.Popen(["xdg-open", path])
            elif system == "Darwin":
                subprocess.Popen(["open", path])
            elif system == "Windows":
                subprocess.Popen(["explorer", path])
        except Exception:
            pass

    def pick_reports_directory(self):
        async def _pick():
            try:
                chosen = await self.file_picker.get_directory_path(
                    dialog_title="Select Report Export Directory",
                    initial_directory=str(self.reports_dir),
                )
                if chosen:
                    self.set_reports_dir(chosen)
            except Exception as ex:
                self.status_toast = f"Folder picker error: {ex}"
                self.update_view_content()
                self.page.update()

        self.page.run_task(_pick)

    def export_report(self, fmt: str, target_session_id: Optional[int] = None):
        self.report_controller.export(fmt, target_session_id)

    def run_pcap_replay(self, pcap_path: str):
        self.capture_controller.run_pcap_replay(pcap_path)
