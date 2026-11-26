# zeek-real

A small synthetic packet capture and the logs real Zeek wrote from it. The loader's unit tests use
hand-written log rows; this checks the loader against what Zeek actually writes.

| File | What it is |
|---|---|
| `make_pcap.py` | Builds `trace.pcap` with scapy. Byte-stable: every address, port, sequence number, payload and timestamp is fixed |
| `trace.pcap` | Four minutes on 2026-03-02 (UTC), 12:00 to 12:04: DNS answered, unanswered and unsolicited; TLS with SNI; HTTP named only by DNS; an inbound session; a 1.2 MB upload across three minutes |
| `logs/json/` | Zeek's JSON logs |
| `logs/json-iso/` | The same, with ISO 8601 timestamps (`LogAscii::json_timestamps=JSON::TS_ISO8601`) |
| `logs/tsv/` | Zeek's default tab-separated logs |

`packages/triage/tests/integration/source/test_zeek_real.py` loads each log set twice, once by Zeek's
`local_orig`/`local_resp` and once with `--local-nets`, and checks all four source tables against
values worked out by hand from the capture.

## Rebuilding

```shell
make zeek-fixture   # from the repository root; needs uv and Docker
```

It runs `make_pcap.py` (scapy comes from the script's inline metadata, not the workspace), then
`zeek -D -C -r trace.pcap` in the `zeek/zeek:9.0.1` image, once per format. `-D` makes Zeek's
connection ids repeatable, so a rebuild changes only the `#open`/`#close` lines of the TSV logs,
which hold the wall-clock time. Zeek's `packet_filter.log` holds nothing else and is deleted.

The site config passed to Zeek matters:

```zeek
redef Site::private_address_space_is_local = F;
redef Site::local_nets += { 10.0.0.0/8 };
```

Zeek's `Site::private_address_space` includes the documentation ranges the capture uses for servers,
and by default private space counts as local. Without the first line, every connection here has
both sides local, and loading by Zeek's flags drops all of them. On a real network the servers are
public addresses and this does not arise; `--local-nets` avoids it either way.

## What real Zeek showed

- A DNS reply with no query is logged in dns.log with an `rcode` and no `rtt`, and Zeek 9 raises no
  `dns_unmatched_reply` weird. The loader had counted such a row as an unanswered query; it now
  counts it as an unsolicited reply.
- Zeek flips a lone reply so the querier is the originator (history `^d`), with no query packets.
- TSV writes `rtt` to the microsecond while JSON keeps the full float, so service times differ by
  nanoseconds between the formats.
- Otherwise the JSON, ISO and TSV logs load to identical tables, and match the capture exactly.
