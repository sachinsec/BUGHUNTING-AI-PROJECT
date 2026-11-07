from app.services.tool_manager import KatanaAdapter, NucleiAdapter, WhatWebAdapter


def test_public_crawlers_disable_cross_target_redirects():
    katana = KatanaAdapter().arguments("app.example.com")
    nuclei = NucleiAdapter().arguments("app.example.com")
    whatweb = WhatWebAdapter().arguments("app.example.com")

    assert "-dr" in katana
    assert "-cs" in katana
    assert r"app\.example\.com" in katana[katana.index("-cs") + 1]
    assert "-dr" in nuclei
    assert "--follow-redirect=never" in whatweb
