import subprocess

from arpie.infrastructure import notifications


def test_linux_notification_dispatches_when_notify_send_exists(monkeypatch):
    commands = []

    def fake_which(name):
        return "/usr/bin/notify-send" if name == "notify-send" else None

    def fake_run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(notifications.platform, "system", lambda: "Linux")
    monkeypatch.setattr(notifications.shutil, "which", fake_which)
    monkeypatch.setattr(notifications.subprocess, "run", fake_run)
    monkeypatch.setattr(notifications.os, "geteuid", lambda: 1000)

    delivered = notifications.send_desktop_notification("Alert", "Test", "high")

    assert delivered is True
    assert commands[0][:6] == [
        "/usr/bin/notify-send",
        "-a",
        "Arpie Endpoint NIDS",
        "-u",
        "critical",
        "-i",
    ]


def test_linux_notification_relays_through_runuser_when_run_as_root(monkeypatch):
    commands = []

    def fake_which(name):
        return f"/usr/bin/{name}"

    def fake_run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(notifications.platform, "system", lambda: "Linux")
    monkeypatch.setattr(notifications.shutil, "which", fake_which)
    monkeypatch.setattr(notifications.subprocess, "run", fake_run)
    monkeypatch.setattr(notifications.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_USER", "erxanitea")

    delivered = notifications.send_desktop_notification("Alert", "Test", "high")

    assert delivered is True
    assert commands[0][:3] == ["runuser", "-u", "erxanitea"]
    assert "/usr/bin/notify-send" in commands[0]


def test_linux_notification_reports_failure_instead_of_swallowing_it(monkeypatch):
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, returncode=1, stdout=b"", stderr=b"No such bus")

    monkeypatch.setattr(notifications.platform, "system", lambda: "Linux")
    monkeypatch.setattr(notifications.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(notifications.subprocess, "run", fake_run)
    monkeypatch.setattr(notifications.os, "geteuid", lambda: 1000)

    delivered = notifications.send_desktop_notification("Alert", "Test", "high")

    assert delivered is False


def test_notification_returns_false_when_platform_has_no_backend(monkeypatch):
    monkeypatch.setattr(notifications.platform, "system", lambda: "Other")

    assert notifications.send_desktop_notification("Alert", "Test") is False