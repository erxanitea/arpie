from arpie.infrastructure import notifications


def test_linux_notification_dispatches_when_notify_send_exists(monkeypatch):
    commands = []
    monkeypatch.setattr(notifications.platform, "system", lambda: "Linux")
    monkeypatch.setattr(notifications.shutil, "which", lambda name: "/usr/bin/notify-send")
    monkeypatch.setattr(
        notifications.subprocess,
        "Popen",
        lambda command, **kwargs: commands.append(command),
    )

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


def test_notification_returns_false_when_platform_has_no_backend(monkeypatch):
    monkeypatch.setattr(notifications.platform, "system", lambda: "Other")

    assert notifications.send_desktop_notification("Alert", "Test") is False