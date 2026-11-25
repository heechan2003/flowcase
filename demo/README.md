# demo

One command runs the whole pipeline on a synthetic network and checks every planted case:

```shell
make sync
make demo        # about 10 minutes; everything it writes goes to demo/work/ (git-ignored)
```

`demo/run.py --from STEP` resumes at a step (`generate`, `load`, `triage`, `match`, `report`, `check`)
over the files an earlier run left, and `--sample` refreshes `sample-output/` after a passing check. On
an 8-core laptop: generate under 30 s (2.15 M connections), load 1-2 min, triage 8-11 min (35 days,
slower as history grows), match and report a few seconds.

## What runs

| Step | Command | Writes |
|---|---|---|
| generate | `demo/generate.py` | 35 days of Zeek `conn`/`ssl`/`dns` logs (JSON, gzip), an ip2asn table, a ThreatFox export, an RDAP cache |
| load | `network-behaviour load-zeek` | the four source tables (`source.duckdb`) |
| triage | `network-behaviour backfill` | one published day per day, into the retained store (`store.duckdb`) |
| match | `ioc-match` | the IOC-match feed for the last three days (`matches.json`) |
| report | `ioc-report --no-model --case-reports` | `report/demo.html`, `.md`, `.json`, and a PDF per review case |
| check | `demo/run.py` | compares every case with `expected.json`, and checks triage published every day and streamed the beacon host on each scenario day |

No model runs and nothing leaves the machine. Every page holds code's own text. The RDAP cache holds
the registration dates of the synthetic names, and its bootstrap sends every other lookup to a closed
loopback port, so a real name (bore.pub) is reported as a failed lookup with an unknown age, which
changes no decision.

## The world

`generate.py` is seeded, and a given seed and end day give the same bytes. The end day defaults to the
latest day the publisher may process (day D runs no earlier than D+1 08:00 UTC).

- **Hosts:** 400 local hosts in `10.30.0.0/16`, in five profiles: office (120), lab (80), student (100),
  device (50) and server (50). Each profile sits inside one peer band of bytes and destinations, so every
  occupied band has at least 40 hosts (`bands.min_cohort`).
- **Servers:** documentation ranges and `198.18.0.0/15`, under `.test` names, on synthetic networks with
  private-use AS numbers. The pipeline counts these as public only with `NETWORK_BEHAVIOUR_SYNTHETIC=1`,
  which every step sets. Three public names stay because the rules know them: `bore.pub` (a tunnelling
  service), `cloudflare-ech.com` (the ECH outer name), and AS13335, which labels one documentation block
  as a network that shares its addresses by design.
- **Every minute:** each host holds a push connection open all day, so every day has activity in all
  1,440 minutes and 288 buckets.
- **Stable:** each host keeps its sites from day to day (with fewer office visits at the weekend), so the
  scored population, the DNS population and the service mix stay inside the drift gates. A few
  one-off visits to long-tail sites each day keep novelty ordinary.
- **History:** 32 days before the three scenario days, so `confidence.day_edges` reaches 30.

## The planted cases

Each scenario has its own host and its own indicator. `expected.json` holds what code must decide: the
disposition, the rules behind it, and the rules that explain individual contacts.

| Scenario | What the host does | Code decides |
|---|---|---|
| `cdn-edge` | visits a campus site it has used for weeks, on a shared CDN address listed as C2 | explained, E4 |
| `beacon` | raw TCP to a listed C2 port every 30 minutes, low volume, for three days | review, K4 |
| `tunnel-client` | has run a bore client (port 7835) every day | review, K3; every contact explained by E5 |
| `tunnel-visitor` | reaches a port published through bore.pub | review, K1 K2 K3 |
| `download` | downloads 3.2 MB from a listed payload server | review, K5 |
| `unanswered-inbound` | receives traffic from a listed address and never answers | explained, E6 |
| `udp-to-tcp-family` | QUIC to an address listed for a TCP-only family | explained, E1 |
| `ech-outer-name` | TLS with the ECH outer name to a native family's C2 | explained, E2 |
| `flagged-domain` | loads a page from a listed lure domain | review, K1 K3 |
| `tls-old-name` | TLS to a long-registered site on an address listed for a family with no TLS | explained, E3 |
| `tls-new-name` | the same, but the name was registered five days earlier | review, unexplained |

K3 is where triage and the IOC report meet: it keeps a case when the published triage stream has an
episode on the flagged destination itself. Three of the rows show how that plays out:

- **The beacon has no K3.** Triage raises an episode on nearly every one of its contacts, but it hashes a
  contact with no name under its network (ASN), so those episodes cover the whole network, not the
  flagged address. ioc-report does not count an episode on a whole network as one on the destination.
- **The domain cases have K3.** Triage's "rare or new external relationship" family raises an episode on
  a new, rare name: the visitor's bore.pub and the lure domain.
- **The tunnel client stays in review.** E5 explains every contact it had (bore's own client port), but
  one host in 400 using bore.pub every day is a repeated rare relationship, so triage's persistence
  family raises an episode on it each day, and K3 keeps the case. Code does not let one explanation
  outrank an independent signal.

## Sample output

`sample-output/` holds one run's HTML report (`demo.html`) and the PDFs for three review cases
(`case-beacon.pdf`, `case-flagged-domain.pdf`, `case-download.pdf`). Everything in them was written by
code, since the demo runs without a model. A run with a model (`ioc-case-report --budget`) changes
only the PDFs' paragraphs, never a decision.
