"""Network-context classification (Objective 1): trusted / public-untrusted /
unknown, driven by the user-confirmed trusted-SSID list."""

from arpie.network.context import classify_network


def test_no_ssid_is_unknown():
    assert classify_network(None, []) == "unknown"


def test_ssid_not_in_trusted_list_is_public():
    assert classify_network("CoffeeShop_Free", []) == "public-untrusted"
    assert classify_network("CoffeeShop_Free", ["HomeNet"]) == "public-untrusted"


def test_ssid_in_trusted_list_is_trusted():
    assert classify_network("HomeNet", ["HomeNet"]) == "trusted"
    assert classify_network("Office-5G", ["HomeNet", "Office-5G"]) == "trusted"


def test_trusted_match_is_exact_not_substring():
    # A public SSID that merely contains a trusted name must not be trusted.
    assert classify_network("HomeNet_Guest", ["HomeNet"]) == "public-untrusted"
