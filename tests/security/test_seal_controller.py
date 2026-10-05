from types import SimpleNamespace

from arpie.controllers.seal_controller import SealController
from arpie.models import Database
from arpie.security.seal import SealManager, SealResult


def _app(tmp_path):
    db = Database(str(tmp_path / "seal.db"))
    operator_id = db.create_operator("tester", "tester@example.com", "TestPass123")
    session_id = db.start_session("Demo", "public-untrusted", "wlan0", operator_id=operator_id)
    return SimpleNamespace(
        db=db,
        session_id=session_id,
        seal_mgr=SealManager(db, session_id),
        active_blocks=[],
        operator_id=operator_id,
        user_role="Evaluator/Administrator",
        local_ip="192.168.1.9",
        network_context=SimpleNamespace(gateway_ip="192.168.1.1"),
        selected_alert=None,
        status_toast="",
        update_view_content=lambda: None,
        page=SimpleNamespace(update=lambda: None),
        close_dialog=lambda _: None,
    )


def test_controller_rejects_gateway_and_invalid_targets(tmp_path):
    app = _app(tmp_path)
    controller = SealController(app)

    assert controller.block_ip("192.168.1.1") is None
    assert controller.block_ip("not-an-ip") is None
    assert app.active_blocks == []


def test_controller_rejects_end_user_seal_attempt(tmp_path):
    app = _app(tmp_path)
    app.user_role = "End User"

    assert SealController(app).block_ip("192.168.1.50") is None
    assert app.active_blocks == []


def test_controller_records_block_only_after_success(tmp_path, monkeypatch):
    app = _app(tmp_path)
    controller = SealController(app)
    monkeypatch.setattr(app.seal_mgr, "seal", lambda *args, **kwargs: SealResult(True, "blocked"))

    result = controller.block_ip("192.168.1.50")

    assert result.success is True
    assert app.active_blocks == ["192.168.1.50"]