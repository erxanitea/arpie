from arpie.network.context import detect_network_context


def test_arpi_iface_overrides_automatic_interface(monkeypatch):
    monkeypatch.setenv("ARPIE_IFACE", "demo-hotspot0")
    monkeypatch.setattr("arpie.network.context._default_interface", lambda: "wrong0")

    context = detect_network_context()

    assert context.interface == "demo-hotspot0"