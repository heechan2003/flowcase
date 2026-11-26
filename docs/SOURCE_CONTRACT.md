# Source contract: the four tables and how Zeek fills them

Triage, the IOC report's live queries and `ioc-match` read four tables and nothing else. The original deployment read them from a
commercial flow probe. Here, `network-behaviour load-zeek` writes them from Zeek logs into a DuckDB file.
Every reader opens that file read-only. Detectors, rules and the writer never see a Zeek field.

- **Code:**
  - `packages/triage/src/network_behaviour/source/zeek/loader.py`: the mapping
  - `source/contracts.py`: the exact column types the contract check requires
  - `sql/source/` (triage) and `packages/ioc-report/src/ioc_report/sql/` (IOC report, `ioc-match`): the queries
- **Tests:** one per mapping rule in `packages/triage/tests/unit/source/zeek/`.
  `tests/integration/source/test_zeek_day.py` loads a generated day, runs every source check and publishes it.
  `tests/integration/source/test_zeek_real.py` loads logs that real Zeek (9.0.1) wrote from a synthetic
  capture (`fixtures/zeek-real/`), in JSON, ISO-timestamp JSON and TSV.

## Inputs

| Zeek log | Fields read | Required |
|---|---|---|
| `conn` | `ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes orig_pkts resp_pkts local_orig local_resp` | yes |
| `ssl` | `ts uid server_name` | no: without it, no SNI |
| `dns` | `ts uid id.orig_h id.resp_h id.resp_p query rcode rtt answers TTLs` | no: without it, no DNS names and no `dns_pairs` |
| `weird` | `ts uid id.orig_h id.resp_h name` | no: only older Zeek versions report unsolicited replies here |

Logs may be JSON (one object per line) or Zeek's TSV, plain or gzipped, with either of Zeek's timestamp
styles.

A folder of Zeek's dated subfolders (`YYYY-MM-DD/`) contributes day D and day D+1. Zeek writes a connection
when it ends, so one that crosses midnight is in the next day's logs. Loading a day replaces that day in
all four tables, in one transaction.

## Rules that apply to every table

- **The local side is the client.** Local means inside `--local-nets` (`NETWORK_BEHAVIOUR_LOCAL_NETS`, IPv4) when
  that is given. Otherwise it is whatever Zeek's `local_orig` and `local_resp` say.
  - A connection with both sides local, or neither, is dropped, because a border sensor never sees one.
  - Zeek counts private address space as local unless `Site::private_address_space_is_local` is `F`,
    and its private space includes the documentation ranges. On synthetic data, Zeek's flags therefore
    mark both sides local; give `--local-nets` or that site config. `load-zeek` warns when every
    connection of a day was dropped.
  - `server_ip` is the remote side.
  - `server_port` is the remote side's port, whoever opened the session. That is how the original probe
    oriented rows.
- **Plain DNS goes only to `dns_pairs`.** A connection is plain DNS when it is TCP or UDP and either its
  remote port is 53 or Zeek's `service` is `dns`. Plain DNS is left out of activity, rate and long flows,
  as on the original probe (`CASE_STUDY` §9).
- **Transport** is `proto` as a protocol number: tcp 6, udp 17, icmp 1, anything else 0. ICMP has no
  `server_port` (0).

## `flow.activity_1m`: one row per minute and grain

Grain: `time, client_ip, server_ip, server_port, transport_protocol, application, application_category,
root_domain, sni, dns, asn`. Rows are aggregated to this grain, so the duplicate check finds none.

| Column | From Zeek |
|---|---|
| `time` | Each minute the connection spans, from `ts` to `ts + duration`. Only minutes inside the loaded day are written |
| `up_bytes`, `down_bytes` | The local side's sent and received bytes (`orig_bytes`/`resp_bytes`, turned by orientation), split across the minutes in proportion to overlap. The split is integer arithmetic on microseconds, so the minutes sum exactly to the connection |
| `up_packets`, `down_packets` | The same split, on `orig_pkts`/`resp_pkts` |
| `flow_count` | Connections that start in the minute |
| `sni` | ssl.log `server_name` for the connection's `uid`, lowercased; otherwise empty |
| `dns` | The name this client last resolved to this server address: the newest dns.log answer before the connection started, and only if its TTL still covered the start. Otherwise empty |
| `root_domain` | The registered domain of `sni`, or else of `dns` (`normalization/service.py: registered_domain`) |
| `application` | The registered domain's first label (`news` for `news.test`). Otherwise Zeek's `service`, or empty |
| `application_category` | Zeek's `service`, or `_unknown` |
| `asn` | From an ip2asn-format table (`--asn-table`, IPv4 ranges only). AS 0 and IPv6 servers carry none |

## `flow.host_load_5m`: one row per client and five-minute bucket

| Column | From Zeek |
|---|---|
| `up_bytes`, `down_bytes` | The sum of the client's activity minutes in the bucket, so activity and rate reconcile exactly |
| `active_minutes` | Minutes in the bucket with any activity |
| `up_rate_p95_bps` | **Approximation.** The original was a p95 of 1-second peak upload rates. Here, each minute's rate is the sum of the average upload rates (`up bytes × 8 / duration`) of the connections active in that minute. The bucket keeps the p95 of its minutes. Detectors compare it only with the host's own history and its peers, never with an absolute value |

## `flow.long_flows`: one row per connection of 1 MB or more

Connections starting in the day whose `up_bytes + down_bytes` is at least 1,000,000. That is the same
floor every query applies (`long_flow.min_bytes`). `flow_id` is the Zeek `uid`. `client_port` is the
local port. `initiator` is `client` when the local side originated and `server` otherwise.

The original probe had direction only on these rows (`CASE_STUDY` §7). Zeek knows it for every
connection, but activity keeps the original columns.

## `flow.dns_pairs`: one row per hour, client and resolver

| Column | From Zeek |
|---|---|
| `complete_sessions` | dns.log transactions with an `rtt` |
| `unanswered_sessions` | Transactions with neither an `rtt` nor an `rcode`: no reply was seen |
| `unsolicited_sessions`, `unsolicited_response_packets` | Transactions with an `rcode` but no `rtt`: Zeek logs a reply it saw no query for that way. One packet each. Older Zeek versions reported these in weird.log as `dns_unmatched_reply`; those count too, once per `uid`. Zeek also drops an `rtt` of exactly zero, so a reply timestamped with its query would count here; that is rare |
| `query_packets`, `response_packets` | The transaction's conn.log `orig_pkts`/`resp_pkts`, counted once per `uid`, less the unsolicited replies |
| `unanswered_query_packets` | Query packets of `uid`s with no answered transaction |
| `mean_service_nanos` | Mean `rtt` of the complete transactions, in nanoseconds |

The client is the local side, as everywhere. A campus resolver that queries outside servers therefore
appears as a client, and the DNS family identifies and leaves out such servers as it always has.

## What differs from the original probe

- **No unaddressed rows.** The probe gave every address an unaddressed `Web Browsing` row in nearly every
  minute (`CASE_STUDY` §3). Zeek reports connections, so the scored population is only the addresses
  with traffic.
- **The upload rate is approximated** (above).
- **Detail is kept while loaded.** The probe kept about fifteen days (`CASE_STUDY` §1). A Zeek-loaded day
  stays until it is reloaded. `NETWORK_BEHAVIOUR_SOURCE_DETAIL_DAYS` reproduces the old limit.
- **IPv6 locality** comes only from Zeek's flags, and IPv6 servers carry no ASN.

## Synthetic data

The demo and the tests use documentation and benchmarking ranges for servers and `.test` names, so
nothing falls in real address space. Setting `NETWORK_BEHAVIOUR_SYNTHETIC=1` makes those ranges count as
public destinations and `.test` as a public suffix. A day published that way records
`+synthetic` in its normalization version (`network_behaviour/synthetic.py`).
