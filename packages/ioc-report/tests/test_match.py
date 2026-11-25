"""`ioc-match`: a synthetic ThreatFox export against a synthetic source. Nothing here is a real
indicator: the export lists documentation-range addresses and `.test` names."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ioc_report.feed import load_feed, load_listing_dates
from ioc_report.match import load_threatfox, main
from tests.source_builders import activity, long_flow, write_source

HOST = "192.0.2.10"
OTHER = "192.0.2.20"


def _export(path: Path, records: list[dict[str, Any]]) -> Path:
    path.write_text(
        json.dumps({str(n): [record] for n, record in enumerate(records, 1)}), encoding="utf-8"
    )
    return path


def _ioc(value: str, kind: str, **extra: Any) -> dict[str, Any]:
    return {
        "ioc_value": value,
        "ioc_type": kind,
        "threat_type": "botnet_cc",
        "malware": "win.nanocore",
        "confidence_level": 75,
        "first_seen_utc": "2026-09-01 08:00:00 UTC",
        "last_seen_utc": None,
        **extra,
    }


def test_the_export_yields_ip_port_and_domain_indicators_and_skips_the_rest(
    tmp_path: Path,
) -> None:
    path = _export(
        tmp_path / "export.json",
        [
            _ioc("1.1.1.1:443", "ip:port"),
            _ioc("C2.Example.Test.", "domain"),
            _ioc("http://9.9.9.9/gate.php", "url"),
            _ioc("https://drop.example.test:8443/x", "url"),
            _ioc("d41d8cd98f00b204e9800998ecf8427e", "md5_hash"),
            _ioc("not-an-address:99999", "ip:port"),
            _ioc("1.1.1.1:443", "ip:port", malware="duplicate"),
        ],
    )

    found = load_threatfox(path)

    assert [(i.kind, i.value) for i in found] == [
        ("domain", "c2.example.test"),
        ("domain", "drop.example.test"),
        ("ip:port", "1.1.1.1:443"),
        ("ip:port", "9.9.9.9:80"),
    ]
    assert found[0].first_seen == "2026-09-01T08:00:00Z" and found[0].confidence == 75


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[int, Path]:
    source = write_source(
        tmp_path / "source.duckdb",
        [
            activity("2026-10-05 10:00:00", sni="www.c2.example.test", root="example.test"),
            activity("2026-10-05 10:01:00", server="9.9.9.9", port=80),
            activity("2026-10-05 10:02:00", server="9.9.9.9", port=443),  # wrong port
            activity("2026-10-05 10:03:00", OTHER, dns="c2.example.test", root="example.test"),
            activity("2026-10-05 10:04:00", sni="notc2.example.test", root="example.test"),
            activity("2026-10-06 10:00:00", sni="www.c2.example.test", root="example.test"),
        ],
        [long_flow("F1", "2026-10-04 23:00:00", "2026-10-05 10:30:00", server="1.1.1.1")],
    )
    export = _export(
        tmp_path / "export.json",
        [_ioc("c2.example.test", "domain"), _ioc("http://9.9.9.9/gate.php", "url")],
    )
    out = tmp_path / "data" / "feed.json"
    monkeypatch.setenv("NETWORK_BEHAVIOUR_SOURCE_PATH", str(source))
    monkeypatch.setenv("IOC_METADATA_PATH", str(tmp_path / "data" / "ioc_metadata.json"))
    monkeypatch.chdir(tmp_path)
    code = _match(export, out)
    return code, out


def _match(export: Path, out: Path) -> int:
    return main([str(export), "--day", "2026-10-05", "--out", str(out)])


def test_matched_minutes_become_a_feed_the_report_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out = _run(tmp_path, monkeypatch)

    assert code == 0
    printed = capsys.readouterr().out
    assert "3 matched minute record(s), 2 host(s), 2 indicator(s) matched" in printed
    assert "c2.example.test" not in printed and HOST not in printed
    feed = load_feed(out)
    assert feed.rejected == () and feed.record_count == 3
    cases = {(case.indicator, case.host) for case in feed.cases}
    assert cases == {
        ("c2.example.test", HOST),
        ("c2.example.test", OTHER),
        ("9.9.9.9:80", HOST),
    }
    records = json.loads(out.read_text(encoding="utf-8"))
    first = next(
        r for r in records if r["affected_host"] == HOST and r["indicator_type"] == "domain"
    )
    assert first["threatfox"]["first_seen_utc"] == "2026-10-05T10:00:00Z"
    assert [flow["flow_id"] for flow in first["evidence"]["long_flows"]] == ["F1"]
    dates = load_listing_dates(tmp_path / "data" / "ioc_metadata.json")
    assert dates["c2.example.test"][0] is not None


def test_a_rerun_writes_the_same_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _code, out = _run(tmp_path, monkeypatch)
    first = out.read_bytes()

    assert _match(tmp_path / "export.json", out) == 0
    assert out.read_bytes() == first


def test_a_missing_source_stops_with_a_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    export = _export(tmp_path / "export.json", [_ioc("1.1.1.1:443", "ip:port")])
    monkeypatch.setenv("NETWORK_BEHAVIOUR_SOURCE_PATH", str(tmp_path / "absent.duckdb"))

    assert main([str(export), "--day", "2026-10-05"]) == 2
    assert "load Zeek logs first" in capsys.readouterr().err
