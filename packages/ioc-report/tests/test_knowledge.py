from __future__ import annotations

import pytest

from ioc_report.knowledge import (
    FAMILIES,
    REPORT_FAMILIES,
    SERVICES,
    SHARED_NETWORKS,
    SOFTWARE_SIGNALS,
    TCP,
    family_background,
    family_profile,
    is_unnamed_family,
    name_facts,
    service_for,
    tenant_domain,
    under,
)


def test_every_family_and_service_cites_a_source() -> None:
    for profile in FAMILIES.values():
        assert profile.sources and all(url.startswith("https://") for url in profile.sources)
    for service in SERVICES:
        assert service.sources and service.client_ports


def test_a_family_described_for_the_reports_alone_cites_a_source_and_decides_nothing() -> None:
    assert not set(REPORT_FAMILIES) & set(FAMILIES)
    for entry in REPORT_FAMILIES.values():
        assert entry.sources and all(url.startswith("https://") for url in entry.sources)
        assert entry.background and entry.check
        # Rules and case files read family_profile, which must not see it.
        assert family_profile(entry.family) is None
        assert family_background(entry.family.upper()) == entry
    nanocore = family_background("win.nanocore")
    assert nanocore is not None and nanocore.name == "NanoCore RAT"
    assert family_background("win.notdescribed") is None


def test_a_shared_network_cites_sources_and_a_channel_is_for_a_described_family() -> None:
    assert SHARED_NETWORKS
    for entry in SHARED_NETWORKS.values():
        assert entry.name and all(url.startswith("https://") for url in entry.sources)
    assert all(entry.channel is None or entry.sources for entry in REPORT_FAMILIES.values())


def test_generic_threatfox_labels_name_no_family() -> None:
    assert is_unnamed_family("unknown") and is_unnamed_family(" Unknown_RAT ")
    assert not is_unnamed_family("win.asyncrat") and not is_unnamed_family("unknownrat")


def test_only_nanocore_carries_decision_bearing_c2_fields() -> None:
    nanocore = family_profile("Win.NanoCore ")
    assert nanocore is not None
    assert (nanocore.client, nanocore.c2_tls, nanocore.c2_udp) == ("native", False, False)
    for profile in FAMILIES.values():
        if profile.family != "win.nanocore":
            assert profile.c2_tls is None and profile.c2_udp is None
    assert family_profile("win.asyncrat") is None


def test_platform_tenants_and_operator_names_are_recognised() -> None:
    assert name_facts("abc.github.io").platform_tenant
    assert name_facts("abc.github.io").registered == "github.io"
    assert tenant_domain("abc.github.io") == "abc.github.io"
    assert name_facts("c2.duckdns.org").operator_controlled
    assert name_facts("x.trycloudflare.com").category == "tunnel"
    assert name_facts("cloudflare-ech.com").category == "ech"
    plain = name_facts("www.example.com")
    assert (plain.registered, plain.platform_tenant, plain.category) == ("example.com", False, None)


def test_a_tunnel_service_knows_its_own_client_port() -> None:
    bore = service_for("bore.pub")
    assert bore is not None and bore.is_client_port(7835, TCP)
    assert not bore.is_client_port(41234, TCP)
    assert service_for("www.example.com") is None
    assert under("a.b.example.com", "example.com") and not under("badexample.com", "example.com")


def test_every_software_signal_cites_a_source_and_hashes_as_a_name() -> None:
    from ioc_report.history import name_key

    keys = [signal.key for signal in SOFTWARE_SIGNALS]
    assert len(keys) == len(set(keys))
    for signal in SOFTWARE_SIGNALS:
        assert signal.sources and all(url.startswith("https://") for url in signal.sources)
        for domain in signal.domains:
            # Only a registered domain the product owns can be looked up in hashed history.
            assert name_facts(domain).registered == domain, domain
            assert name_key(domain) is not None, domain


def test_only_a_listing_whose_publisher_names_cves_carries_advisories() -> None:
    from ioc_report.knowledge import LISTINGS

    assert LISTINGS["threatfox"].advisories == ()
    assert LISTINGS["amazon-php2shell"].advisories


def test_a_synthetic_world_reads_test_as_a_public_suffix_as_the_publisher_does(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("NETWORK_BEHAVIOUR_SYNTHETIC", raising=False)
    assert tenant_domain("cdn.lure.test") is None

    monkeypatch.setenv("NETWORK_BEHAVIOUR_SYNTHETIC", "1")
    assert tenant_domain("cdn.lure.test") == tenant_domain("lure.test") == "lure.test"
    assert not name_facts("cdn.lure.test").platform_tenant
    # Real names read the same either way.
    assert tenant_domain("abc.github.io") == "abc.github.io"
    assert name_facts("abc.github.io").platform_tenant
    assert tenant_domain("www.example.com") == "example.com"
