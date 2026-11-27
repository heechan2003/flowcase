# IOC match report: demo

Generated 2026-11-27 02:36 UTC from matches.json: 11 case(s) from 4632 record(s), 11 host(s), 10 indicator(s). Sensitive: internal addresses and domains; share only with people cleared to see the network's data. The writer's overviews, the digests and the case files are in `demo.json`.

## Summary

11 case(s): 6 kept for review and 5 explained by code. The largest group: NanoCore RAT (botnet_cc): kept for review by a stream episode on the flagged destination.

**6 to review, 5 explained** (0 with caveats, 5 with every check run). Code decides every case; no case says a host is compromised, infected or benign, because flow records cannot show that. *Summary code's own text (--no-model).*

- **Feed:** matches.json; no creation times; 0 record(s) rejected.
- **Live source:** minute detail queried for 2026-11-22..2026-11-24; expired for none; long flows from 2026-11-21 onwards; context around review contacts for 2026-11-22..2026-11-24; destinations for the after-contact view on 2026-11-21..2026-11-24.
- **Live re-query:** every match day re-queried for 11 of 11 case(s), some for 0, none for 0.
- **Retained history:** 35 day(s), 2026-10-21 to 2026-11-24; not retained: none. Published stream days: 35. Opened read-only.
- **Query footprint:** 15 source quer(ies), 8,040,189 rows read in 0 s; aggregate-only, read-only.

## Threats

- **NanoCore RAT** (ThreatFox `win.nanocore`, botnet_cc; cases #1, #2, #5, #6, #7, #9, #10, #11): Windows remote-access trojan. The victim connects out to an operator-chosen host and port and speaks NanoCore's own protocol: length-prefixed, DES-encrypted frames over plain TCP. That channel carries no TLS handshake and never uses UDP. Sources: https://github.com/nict-csl/NanoCoreRAT-Analysis, https://unit42.paloaltonetworks.com/nanocorerat-behind-an-increase-in-tax-themed-phishing-e-mails/, https://malpedia.caad.fkie.fraunhofer.de/details/win.nanocore.
- **ShadowV2 (Linux botnet)** (ThreatFox `elf.shadowv2`, payload_delivery; cases #3): Linux botnet malware for servers and devices. A payload_delivery listing is a server that hands out the binary or the script that fetches it. Sources: https://malpedia.caad.fkie.fraunhofer.de/details/elf.shadowv2.
- **ClearFake** (ThreatFox `js.clearfake`, payload_delivery; cases #4): JavaScript injected into compromised legitimate sites. It shows a fake browser update, and the real payload arrives afterwards from another address. The flagged domain is often the compromised site itself. Sources: https://malpedia.caad.fkie.fraunhofer.de/details/js.clearfake.
- **win.lumma** (ThreatFox `win.lumma`, botnet_cc; cases #8): No cited profile describes this family, so no rule draws on it.

## Cases

| # | Indicator | Host | Listing | First match | Decision | Reason |
|---|---|---|---|---|---|---|
| [1](#case-1) | `bore.pub` | `10.30.5.12` | win.nanocore, botnet_cc | 2026-11-22 00:00 UTC | review (K3) | kept for review by a stream episode on the flagged destination |
| [2](#case-2) | `198.51.100.77:8443` | `10.30.1.33` | win.nanocore, botnet_cc | 2026-11-22 06:00 UTC | review (K4) | kept for review by a scheduled low-volume contact |
| [3](#case-3) | `198.51.100.120:443` | `10.30.5.21` | elf.shadowv2, payload_delivery | 2026-11-23 11:30 UTC | review (K5) | kept for review by a transfer of 1 MB or more |
| [4](#case-4) | `promo.smallbakery-news.test` | `10.30.1.104` | js.clearfake, payload_delivery | 2026-11-23 12:00 UTC | review (K1, K3) | kept for review by the host named the flagged domain, a stream episode on the flagged destination |
| [5](#case-5) | `bore.pub` | `10.30.1.58` | win.nanocore, botnet_cc | 2026-11-23 13:00 UTC | review (K1, K2, K3) | kept for review by the host named the flagged domain, a tunnel reached as a visitor, a stream episode on the flagged destination |
| [6](#case-6) | `198.51.100.170:443` | `10.30.2.47` | win.nanocore, botnet_cc | 2026-11-23 14:30 UTC | review (unexplained) | kept for review by a contact no rule explains |
| [7](#case-7) | `203.0.113.200:1604` | `10.30.3.44` | win.nanocore, botnet_cc | 2026-11-23 04:00 UTC | explained (E6) | explained by inbound traffic the host did not answer |
| [8](#case-8) | `203.0.113.10:443` | `10.30.1.7` | win.lumma, botnet_cc | 2026-11-23 10:12 UTC | explained (E4) | explained by an established shared site |
| [9](#case-9) | `198.51.100.160:443` | `10.30.2.15` | win.nanocore, botnet_cc | 2026-11-23 14:00 UTC | explained (E3) | explained by TLS to another site |
| [10](#case-10) | `198.51.100.140:443` | `10.30.3.71` | win.nanocore, botnet_cc | 2026-11-23 15:00 UTC | explained (E1) | explained by UDP contact |
| [11](#case-11) | `203.0.113.20:443` | `10.30.1.90` | win.nanocore, botnet_cc | 2026-11-23 16:00 UTC | explained (E2) | explained by ECH browser traffic |

## Next steps by system

Start with the review cases, in the order below; each card lists what to look up and where. Flow records carry no payload, process or user, so none of them can show what a host ran.

| Where | What to do | Cases |
|---|---|---|
| Device lease | Identify the device that held each address in its match window, from DHCP, network access control or VPN logs: an address is not a device. | #1, #2, #3, #4, #5, #6 |
| Endpoint record | Check the endpoint record around each match for the process behind the contact and anything it fetched or started. | #2, #3, #4, #5, #6 |
| Triage stream | Read the stream's episode on the flagged destination beside the match. | #1, #4, #5 |
| Web gateway or proxy | Pull the web gateway or proxy logs for the flagged domain: the full URL, the user agent and any file served. | #1, #4, #5 |
| Resolver logs | Pull the resolver logs for the device's queries for the flagged domain. | #1, #4, #5 |
| Mail gateway | Look for mail linking to the flagged domain in the 24 hours before the visit. | #4 |

## Each case

<a id="case-1"></a>
### 1. `bore.pub` · `10.30.5.12` · review (K3)

win.nanocore, botnet_cc · first match 2026-11-22 00:00 UTC · 4308 matched minute(s) in 4308 feed record(s) · registered unknown · ThreatFox first saw the indicator 2026-11-16 06:03 UTC, 6 day(s) before the first match (from data/ioc_metadata.json) · live re-query fully · blind model not asked.

**Why:**

- K3 on 3 finding(s); the first: the published triage stream has a persistence E2 episode on bore.pub itself on 2026-11-22.
- E5 explains 1 kind(s) of contact: bore (reverse TCP tunnel) client port 7835/TCP: the host runs a bore client: it publishes one of its own ports at bore.pub. A C2 client would instead connect to the tunnel's public port, not to 7835.

| From (UTC) | To | Source | What | Min / flows | In | Out | Longest | Judged |
|---|---|---|---|---|---|---|---|---|
| 2026-11-22 00:00 | 2026-11-22 23:58 | Live source, also in the IOC feed | contact: 198.51.100.90 7835/TCP, DNS bore.pub, no SNI | 1436 | 826.3 KB | 1.4 MB | — | explained by E5 (bore (reverse TCP tunnel) client port 7835/TCP: the host runs a bore client: it publishes one of its own ports at bore.pub. A C2 client would instead connect to the tunnel's public port, not to 7835) |
| 2026-11-23 00:00 | 2026-11-23 23:58 | Live source | contact: 198.51.100.90 7835/TCP, DNS bore.pub, no SNI | 1436 | 790.7 KB | 1.3 MB | — | explained by E5 (bore (reverse TCP tunnel) client port 7835/TCP: the host runs a bore client: it publishes one of its own ports at bore.pub. A C2 client would instead connect to the tunnel's public port, not to 7835) |
| 2026-11-24 00:00 | 2026-11-24 23:58 | Live source | contact: 198.51.100.90 7835/TCP, DNS bore.pub, no SNI | 1436 | 903.3 KB | 1.4 MB | — | explained by E5 (bore (reverse TCP tunnel) client port 7835/TCP: the host runs a bore client: it publishes one of its own ports at bore.pub. A C2 client would instead connect to the tunnel's public port, not to 7835) |

**Threat**

- [ThreatFox, about the indicator only] bore.pub (domain) is listed as win.nanocore, threat type botnet_cc.
- [IOC feed] the flagged address 198.51.100.90 is in AS64510 Example VPS B.V. (NL).
- [IOC feed] 1 other host(s) in this feed matched the same indicator.

**Host**

- [Retained history] the address appears on 35 retained day(s) from 2026-10-21 to 2026-11-24, with traffic to or from a known remote address on 35.
- [Retained history, cited knowledge] none of the products with a known purpose appears on its retained days.
- [Retained history] on 2026-11-22 it used 10 distinct services (campus addresses with a service row had a median of 13 and a 90th percentile of 22) and moved 1.9 GB.
- [Published triage stream] 42 episode(s) on 35 day(s): persistence 31, fanout 8, transfer 2, relationship 1.
- [Live source] names it used on the most of the 4 day(s) read, with the number of days: bolt-bank.test (4), bore.pub (4), comet-games.test (4), drift-cloud.test (4), notify-hub.test (4), pkg-cache.test (4), ridge-shop.test (4), soft-depot.test (4).

**What happened**

- [Live source] The host's contact with the flagged address: 198.51.100.90 7835/TCP, DNS bore.pub, no SNI, 4308 minute(s) on 2026-11-22..2026-11-24, first 2026-11-22 00:00 UTC, last 2026-11-24 23:58 UTC; 2.5 MB received, 4.1 MB sent.
- [Retained history] bore.pub in the 32 retained day(s) before the first match: 1 campus address(es) on 32 day(s); established (7+ addresses on 9+ days, CASE_STUDY §15): no.
- [Measured, CASE_STUDY §14] 198.51.100.90 carried at most 1 registered domain(s): not shown to be shared (10+ would be).
- [Live source] Read 2026-11-21 to 2026-11-24 (4 day(s)): no named destination was new to this host after the first match; 0 new named destination(s) and 0 network(s) with no name in all; uploads of 1 MB or more to new destinations (CASE_STUDY §8): none.

**Could not check:** nothing; every check ran (live re-query, published stream, retained 5-minute timing).

**Next steps:**

1. Identify the device: the address lease (DHCP, network access control or VPN logs) for 10.30.5.12 from 2026-11-21 23:45 UTC to 2026-11-23 00:58 UTC, and on the later match day(s) 2026-11-23..2026-11-24. An address is not a device (CASE_STUDY §6).
2. Read the triage stream's episode for this host on the same destination (see [Published triage stream]) beside this match.
3. Web gateway or proxy logs for requests to bore.pub from 2026-11-21 23:45 UTC to 2026-11-23 00:58 UTC, and on the later match day(s) 2026-11-23..2026-11-24: the full URL, the user agent and any file served (name, size, hash).
4. Resolver logs for the device's queries for bore.pub from 2026-11-21 23:45 UTC to 2026-11-23 00:58 UTC, and on the later match day(s) 2026-11-23..2026-11-24; flow records carry no query names (CASE_STUDY §9).

**Would change it:** the stream episode read beside the match.

<a id="case-2"></a>
### 2. `198.51.100.77:8443` · `10.30.1.33` · review (K4)

win.nanocore, botnet_cc · first match 2026-11-22 06:00 UTC · 132 matched minute(s) in 132 feed record(s) · ThreatFox first saw the indicator 2026-11-17 06:02 UTC, 5 day(s) before the first match (from data/ioc_metadata.json) · live re-query fully · blind model not asked.

**Why:**

- K4 on 3 finding(s); the first: scheduled low-volume contact with 198.51.100.77 on 2026-11-22: 36 minutes, mean gap 30.0 min, CV 0.00, over 17.5 h (CASE_STUDY §10).
- Not explained: 1 kind(s) of contact with 198.51.100.77 (no TLS name, so no site can be named). The first in full: no SNI: the contact cannot be attributed to a site.

| From (UTC) | To | Source | What | Min / flows | In | Out | Longest | Judged |
|---|---|---|---|---|---|---|---|---|
| 2026-11-22 06:00 | 2026-11-22 23:30 | Live source, also in the IOC feed | contact: 198.51.100.77 8443/TCP, no name | 36 | 9.4 KB | 15.0 KB | — | not explained: no SNI: the contact cannot be attributed to a site |
| 2026-11-23 00:00 | 2026-11-23 23:30 | Live source | contact: 198.51.100.77 8443/TCP, no name | 48 | 12.6 KB | 20.2 KB | — | not explained: no SNI: the contact cannot be attributed to a site |
| 2026-11-24 00:00 | 2026-11-24 23:30 | Live source | contact: 198.51.100.77 8443/TCP, no name | 48 | 12.4 KB | 20.0 KB | — | not explained: no SNI: the contact cannot be attributed to a site |

**Threat**

- [ThreatFox, about the indicator only] 198.51.100.77:8443 (ip:port) is listed as win.nanocore, threat type botnet_cc.
- [IOC feed] the flagged address 198.51.100.77 is in AS64510 Example VPS B.V. (NL).

**Host**

- [Retained history] the address appears on 35 retained day(s) from 2026-10-21 to 2026-11-24, with traffic to or from a known remote address on 35.
- [Retained history, cited knowledge] none of the products with a known purpose appears on its retained days.
- [Retained history] on 2026-11-22 it used 10 distinct services (campus addresses with a service row had a median of 13 and a 90th percentile of 22) and moved 9.2 MB.
- [Published triage stream] 162 episode(s) on 21 day(s): relationship 159, fanout 3.
- [Live source] names it used on the most of the 4 day(s) read, with the number of days: juniper-cloud.test (4), notify-hub.test (4), chalk-video.test (3), comet-games.test (3), drift-books.test (3), ember-code.test (3), ember-docs.test (3), hazel-health.test (3).

**What happened**

- [Live source] The host's contact with the flagged address: 198.51.100.77 8443/TCP, no name, 132 minute(s) on 2026-11-22..2026-11-24, first 2026-11-22 06:00 UTC, last 2026-11-24 23:30 UTC; 34.3 KB received, 55.2 KB sent.
- [Measured, CASE_STUDY §14] 198.51.100.77 carried at most 0 registered domain(s): not shown to be shared (10+ would be).
- [Live source] Read 2026-11-21 to 2026-11-24 (4 day(s)): after the first match the next destination new to this host was harbor-anchor-code.test, 13.6 h later; 3 new named destination(s) and 1 network(s) with no name in all; uploads of 1 MB or more to new destinations (CASE_STUDY §8): none.

**Could not check:** nothing; every check ran (live re-query, published stream, retained 5-minute timing).

**Next steps:**

1. Identify the device: the address lease (DHCP, network access control or VPN logs) for 10.30.1.33 from 2026-11-22 05:45 UTC to 2026-11-23 00:30 UTC, and on the later match day(s) 2026-11-23..2026-11-24. An address is not a device (CASE_STUDY §6).
2. Find which process makes the scheduled contact listed under K4; a schedule this regular is a program, not a person.
3. Identify the process behind contact 198.51.100.77 8443/TCP, no name at 2026-11-22 06:00 UTC: no SNI: the contact cannot be attributed to a site.
4. Check the host's endpoint record for a NanoCore client process and its persistence (a .NET executable started from the user profile) and for outbound TCP from it.

**Would change it:** the process behind the scheduled contact.

<a id="case-3"></a>
### 3. `198.51.100.120:443` · `10.30.5.21` · review (K5)

elf.shadowv2, payload_delivery · first match 2026-11-23 11:30 UTC · 1 matched minute(s) in 1 feed record(s) · ThreatFox first saw the indicator 2026-11-15 06:04 UTC, 8 day(s) before the first match (from data/ioc_metadata.json) · live re-query fully · blind model not asked.

**Why:**

- K5: 1 transfer(s) of 1 MB or more with the flagged address (4,078,873 bytes received) on a payload-delivery indicator, not explained as an established site.
- Not explained: 1 kind(s) of contact with 198.51.100.120 (a payload-delivery listing, so the family's protocol says nothing; a name the campus had not established). Names: dl.fresh-mirror.test, fresh-mirror.test. The first in full: a payload_delivery listing names a download server, so the family's protocol cannot explain it; fresh-mirror.test was used by 0 campus address(es) on 0 of 33 retained days before the first match; an established site needs 7 on 9 (CASE_STUDY §15).
- Not explained: 1 long flow(s) with 198.51.100.120 (a long flow overlapping an unexplained contact). The first in full: it overlaps a contact that no rule explains.

| From (UTC) | To | Source | What | Min / flows | In | Out | Longest | Judged |
|---|---|---|---|---|---|---|---|---|
| 2026-11-23 11:30 | 2026-11-23 11:30 | Live source, also in the IOC feed | contact: 198.51.100.120 443/TCP, SNI dl.fresh-mirror.test | 1 | 4.1 MB | 5.2 KB | — | not explained: a payload_delivery listing names a download server, so the family's protocol cannot explain it; fresh-mirror.test was used by 0 campus address(es) on 0 of 33 retained days before the first match; an established site needs 7 on 9 (CASE_STUDY §15) |
| 2026-11-23 11:30 | 2026-11-23 11:30 | Live source, also in the IOC feed | long flows: 198.51.100.120 443/TCP | 1 | 4.1 MB | 5.2 KB | 2 s | not explained: it overlaps a contact that no rule explains |

**Threat**

- [ThreatFox, about the indicator only] 198.51.100.120:443 (ip:port) is listed as elf.shadowv2, threat type payload_delivery.
- [IOC feed] the flagged address 198.51.100.120 is in AS64510 Example VPS B.V. (NL).

**Host**

- [Retained history] the address appears on 35 retained day(s) from 2026-10-21 to 2026-11-24, with traffic to or from a known remote address on 35.
- [Retained history, cited knowledge] none of the products with a known purpose appears on its retained days.
- [Retained history] on 2026-11-23 it used 11 distinct services (campus addresses with a service row had a median of 20 and a 90th percentile of 35) and moved 1.7 GB.
- [Published triage stream] 2 episode(s) on 2 day(s): relationship 1, transfer 1.
- [Live source] names it used on the most of the 3 day(s) read, with the number of days: chalk-weather.test (3), notify-hub.test (3), orbit-cloud.test (3), pkg-cache.test (3), store-backup.test (3), topaz-mail.test (3), velvet-travel.test (3), wren-chat.test (3).

**What happened**

- [Live source] The host's contact with the flagged address: 198.51.100.120 443/TCP, SNI dl.fresh-mirror.test, 1 minute(s) on 2026-11-23, first 2026-11-23 11:30 UTC, last 2026-11-23 11:30 UTC; 4.1 MB received, 5.2 KB sent.
- [Live source] 1 long flow(s) of about 1 MB or more with it, the longest 2 s, 4.1 MB received and 5.2 KB sent in all.
- [Measured, CASE_STUDY §14] 198.51.100.120 carried at most 1 registered domain(s): not shown to be shared (10+ would be).
- [Live source] Read 2026-11-22 to 2026-11-24 (3 day(s)): no named destination was new to this host after the first match; 0 new named destination(s) and 0 network(s) with no name in all; uploads of 1 MB or more to new destinations (CASE_STUDY §8): none.
- [Live source] No contact with the flagged address(es) on the re-queried day(s) after the match (2026-11-24); matched on the address, so a moved name would not show.
- [Live source] Named destinations shared by the 1 active day(s) before and after the match: 0.82; no traffic with a known remote address on 0 of 1 later day(s) (retained history: 0 of 35 days).

**Could not check:** nothing; every check ran (live re-query, published stream, retained 5-minute timing).

**Next steps:**

1. Identify the device: the address lease (DHCP, network access control or VPN logs) for 10.30.5.21 from 2026-11-23 11:15 UTC to 2026-11-23 12:30 UTC. An address is not a device (CASE_STUDY §6). To judge whether the address still holds that device: its named destinations after the match overlap those before it by 0.82, and it had no traffic with a known remote address on 0 of 1 later day(s) (see [Live source, continuity]).
2. Find what the host downloaded from 198.51.100.120 (proxy, browser or endpoint file events) and whether it ran.
3. Identify the process behind the 2 contacts and flows no rule explains, starting with contact 198.51.100.120 443/TCP, SNI dl.fresh-mirror.test at 2026-11-23 11:30 UTC: a payload_delivery listing names a download server, so the family's protocol cannot explain it; fresh-mirror.test was used by 0 campus address(es) on 0 of 33 retained days before the first match; an established site needs 7 on 9 (CASE_STUDY §15).
4. Find what the host downloaded from the indicator and whether it ran: shell history, new binaries or cron entries on the host.

**Would change it:** what the transfer was, from proxy or endpoint file records.

<a id="case-4"></a>
### 4. `promo.smallbakery-news.test` · `10.30.1.104` · review (K1, K3)

js.clearfake, payload_delivery · first match 2026-11-23 12:00 UTC · 1 matched minute(s) in 1 feed record(s) · registered 2019-06-11, 2722 day(s) before · ThreatFox first saw the indicator 2026-11-11 06:08 UTC, 12 day(s) before the first match (from data/ioc_metadata.json) · live re-query fully · blind model not asked.

**Why:**

- K1: the host's traffic named the flagged domain on 1 kind(s) of contact (promo.smallbakery-news.test); a visit to a flagged lure or payload site cannot be cleared from flow records.
- K3: the published triage stream has a relationship E2 episode on smallbakery-news.test itself on 2026-11-23.
- Not explained: 1 kind(s) of contact with 198.51.100.150 (a payload-delivery listing, so the family's protocol says nothing; the name is under the flagged domain). Names: promo.smallbakery-news.test, smallbakery-news.test. The first in full: a payload_delivery listing names a download server, so the family's protocol cannot explain it; promo.smallbakery-news.test is under the indicator's own domain.

| From (UTC) | To | Source | What | Min / flows | In | Out | Longest | Judged |
|---|---|---|---|---|---|---|---|---|
| 2026-11-23 12:00 | 2026-11-23 12:00 | Live source, also in the IOC feed | contact: 198.51.100.150 443/TCP, SNI promo.smallbakery-news.test | 1 | 3.5 KB | 385 B | — | not explained: a payload_delivery listing names a download server, so the family's protocol cannot explain it; promo.smallbakery-news.test is under the indicator's own domain |

**Threat**

- [ThreatFox, about the indicator only] promo.smallbakery-news.test (domain) is listed as js.clearfake, threat type payload_delivery.
- [IOC feed] the flagged address 198.51.100.150 is in AS64511 Example Virtual Servers LLC (US).

**Host**

- [Retained history] the address appears on 35 retained day(s) from 2026-10-21 to 2026-11-24, with traffic to or from a known remote address on 35.
- [Retained history, cited knowledge] none of the products with a known purpose appears on its retained days.
- [Retained history] on 2026-11-23 it used 38 distinct services (campus addresses with a service row had a median of 20 and a 90th percentile of 35) and moved 39.6 MB.
- [Published triage stream] 33 episode(s) on 19 day(s): relationship 33.
- [Live source] names it used on the most of the 3 day(s) read, with the number of days: bloom-jobs.test (3), breeze-news.test (3), cinder-bank.test (3), cinder-cloud.test (3), crest-jobs.test (3), juniper-jobs.test (3), lotus-maps.test (3), maple-maps.test (3).

**What happened**

- [Live source] The host's contact with the flagged address: 198.51.100.150 443/TCP, SNI promo.smallbakery-news.test, 1 minute(s) on 2026-11-23, first 2026-11-23 12:00 UTC, last 2026-11-23 12:00 UTC; 3.5 KB received, 385 B sent.
- [Retained history] smallbakery-news.test in the 33 retained day(s) before the first match: 0 campus address(es) on 0 day(s); established (7+ addresses on 9+ days, CASE_STUDY §15): no.
- [Measured, CASE_STUDY §14] 198.51.100.150 carried at most 1 registered domain(s): not shown to be shared (10+ would be).
- [RDAP] smallbakery-news.test was registered 2019-06-11, 2722 day(s) before the first match.
- [Live source] Read 2026-11-22 to 2026-11-24 (3 day(s)): after the first match the next destination new to this host was fable-nectar-learn.test, 3.3 h later; 2 new named destination(s) and 0 network(s) with no name in all; uploads of 1 MB or more to new destinations (CASE_STUDY §8): none.
- [Live source] No contact with the flagged address(es) on the re-queried day(s) after the match (2026-11-24); matched on the address, so a moved name would not show.
- [Live source] Named destinations shared by the 1 active day(s) before and after the match: 0.38; no traffic with a known remote address on 0 of 1 later day(s) (retained history: 0 of 35 days).

**Could not check:** nothing; every check ran (live re-query, published stream, retained 5-minute timing).

**Next steps:**

1. Identify the device: the address lease (DHCP, network access control or VPN logs) for 10.30.1.104 from 2026-11-23 11:45 UTC to 2026-11-23 13:00 UTC. An address is not a device (CASE_STUDY §6). To judge whether the address still holds that device: its named destinations after the match overlap those before it by 0.38, and it had no traffic with a known remote address on 0 of 1 later day(s) (see [Live source, continuity]).
2. Check the browser's download history and the endpoint record around the visit for a fake 'browser update' download and anything it started.
3. Read the triage stream's episode for this host on the same destination (see [Published triage stream]) beside this match.
4. Identify the process behind contact 198.51.100.150 443/TCP, SNI promo.smallbakery-news.test at 2026-11-23 12:00 UTC: a payload_delivery listing names a download server, so the family's protocol cannot explain it; promo.smallbakery-news.test is under the indicator's own domain.
5. Web gateway or proxy logs for requests to promo.smallbakery-news.test from 2026-11-23 11:45 UTC to 2026-11-23 13:00 UTC: the full URL, the user agent and any file served (name, size, hash).
6. Resolver logs for the device's queries for promo.smallbakery-news.test from 2026-11-23 11:45 UTC to 2026-11-23 13:00 UTC; flow records carry no query names (CASE_STUDY §9).
7. Mail gateway: messages to the device's user in the 24 hours before 2026-11-23 12:00 UTC that link to promo.smallbakery-news.test.

**Would change it:** the endpoint and web-gateway records of what the visit fetched or started; the stream episode read beside the match.

<a id="case-5"></a>
### 5. `bore.pub` · `10.30.1.58` · review (K1, K2, K3)

win.nanocore, botnet_cc · first match 2026-11-23 13:00 UTC · 181 matched minute(s) in 181 feed record(s) · registered unknown · ThreatFox first saw the indicator 2026-11-16 06:03 UTC, 7 day(s) before the first match (from data/ioc_metadata.json) · live re-query fully · blind model not asked.

**Why:**

- K1: the host's traffic named the flagged domain on 1 kind(s) of contact (bore.pub); flow records cannot show such a contact was harmless.
- K2: bore (reverse TCP tunnel) reached on 41234/TCP, not its client port: the host was a visitor to something published through it.
- K3: the published triage stream has a relationship E3 episode on bore.pub itself on 2026-11-23.
- Not explained: 1 kind(s) of contact with 198.51.100.90 (no TLS name, so no site can be named). Names: bore.pub. The first in full: no SNI: the contact cannot be attributed to a site.
- Not explained: 1 long flow(s) with 198.51.100.90 (a long flow overlapping an unexplained contact). The first in full: it overlaps a contact that no rule explains.

| From (UTC) | To | Source | What | Min / flows | In | Out | Longest | Judged |
|---|---|---|---|---|---|---|---|---|
| 2026-11-23 13:00 | 2026-11-23 16:00 | Live source, also in the IOC feed | contact: 198.51.100.90 41234/TCP, DNS bore.pub, no SNI | 181 | 1.8 MB | 300.0 KB | — | not explained: no SNI: the contact cannot be attributed to a site |
| 2026-11-23 13:00 | 2026-11-23 16:00 | Live source, also in the IOC feed | long flows: 198.51.100.90 41234/TCP | 1 | 1.8 MB | 300.0 KB | 3.0 h | not explained: it overlaps a contact that no rule explains |

**Threat**

- [ThreatFox, about the indicator only] bore.pub (domain) is listed as win.nanocore, threat type botnet_cc.
- [IOC feed] the flagged address 198.51.100.90 is in AS64510 Example VPS B.V. (NL).
- [IOC feed] 1 other host(s) in this feed matched the same indicator.

**Host**

- [Retained history] the address appears on 35 retained day(s) from 2026-10-21 to 2026-11-24, with traffic to or from a known remote address on 35.
- [Retained history, cited knowledge] none of the products with a known purpose appears on its retained days.
- [Retained history] on 2026-11-23 it used 35 distinct services (campus addresses with a service row had a median of 20 and a 90th percentile of 35) and moved 31.9 MB.
- [Published triage stream] 41 episode(s) on 21 day(s): relationship 40, transfer 1.
- [Live source] names it used on the most of the 3 day(s) read, with the number of days: arbor-books.test (3), bloom-bank.test (3), flint-shop.test (3), frost-health.test (3), glade-photo.test (3), heron-books.test (3), iris-cloud.test (3), maple-maps.test (3).

**What happened**

- [Live source] The host's contact with the flagged address: 198.51.100.90 41234/TCP, DNS bore.pub, no SNI, 181 minute(s) on 2026-11-23, first 2026-11-23 13:00 UTC, last 2026-11-23 16:00 UTC; 1.8 MB received, 300.0 KB sent.
- [Live source] 1 long flow(s) of about 1 MB or more with it, the longest 3.0 h, 1.8 MB received and 300.0 KB sent in all.
- [Retained history] bore.pub in the 33 retained day(s) before the first match: 1 campus address(es) on 33 day(s); established (7+ addresses on 9+ days, CASE_STUDY §15): no.
- [Measured, CASE_STUDY §14] 198.51.100.90 carried at most 1 registered domain(s): not shown to be shared (10+ would be).
- [Live source] Read 2026-11-22 to 2026-11-24 (3 day(s)): after the first match the next destination new to this host was flint-birch-travel.test, 1.1 h later; 3 new named destination(s) and 0 network(s) with no name in all; uploads of 1 MB or more to new destinations (CASE_STUDY §8): none.
- [Live source] No contact with the flagged address(es) on the re-queried day(s) after the match (2026-11-24); matched on the address, so a moved name would not show.
- [Live source] Named destinations shared by the 1 active day(s) before and after the match: 0.41; no traffic with a known remote address on 0 of 1 later day(s) (retained history: 0 of 35 days).

**Could not check:** nothing; every check ran (live re-query, published stream, retained 5-minute timing).

**Next steps:**

1. Identify the device: the address lease (DHCP, network access control or VPN logs) for 10.30.1.58 from 2026-11-23 12:45 UTC to 2026-11-23 17:00 UTC. An address is not a device (CASE_STUDY §6). To judge whether the address still holds that device: its named destinations after the match overlap those before it by 0.41, and it had no traffic with a known remote address on 0 of 1 later day(s) (see [Live source, continuity]).
2. Check the host's endpoint record for a NanoCore client process and its persistence (a .NET executable started from the user profile) and for outbound TCP from it.
3. Find the process on the host that connected to the tunnel at 2026-11-23 13:00 UTC and what it reached through it.
4. Read the triage stream's episode for this host on the same destination (see [Published triage stream]) beside this match.
5. Identify the process behind the 2 contacts and flows no rule explains, starting with contact 198.51.100.90 41234/TCP, DNS bore.pub, no SNI at 2026-11-23 13:00 UTC: no SNI: the contact cannot be attributed to a site.
6. Web gateway or proxy logs for requests to bore.pub from 2026-11-23 12:45 UTC to 2026-11-23 17:00 UTC: the full URL, the user agent and any file served (name, size, hash).
7. Resolver logs for the device's queries for bore.pub from 2026-11-23 12:45 UTC to 2026-11-23 17:00 UTC; flow records carry no query names (CASE_STUDY §9).

**Would change it:** the endpoint and web-gateway records of what the visit fetched or started; the process that used the tunnel and what it reached; the stream episode read beside the match.

<a id="case-6"></a>
### 6. `198.51.100.170:443` · `10.30.2.47` · review (unexplained)

win.nanocore, botnet_cc · first match 2026-11-23 14:30 UTC · 1 matched minute(s) in 1 feed record(s) · ThreatFox first saw the indicator 2026-11-18 06:10 UTC, 5 day(s) before the first match (from data/ioc_metadata.json) · live re-query fully · blind model not asked.

**Why:**

- Not explained: 1 kind(s) of contact with 198.51.100.170 (the name was registered under 32 days before the match; a name the campus had not established). Names: cdn.fresh-parcel.test, fresh-parcel.test. The first in full: not a protocol mismatch: fresh-parcel.test was registered 2026-11-18, 5 day(s) before the first match; a name that new may be the operator's (CASE_STUDY §16); fresh-parcel.test was used by 0 campus address(es) on 0 of 33 retained days before the first match; an established site needs 7 on 9 (CASE_STUDY §15).

| From (UTC) | To | Source | What | Min / flows | In | Out | Longest | Judged |
|---|---|---|---|---|---|---|---|---|
| 2026-11-23 14:30 | 2026-11-23 14:30 | Live source, also in the IOC feed | contact: 198.51.100.170 443/TCP, SNI cdn.fresh-parcel.test | 1 | 43.1 KB | 4.5 KB | — | not explained: not a protocol mismatch: fresh-parcel.test was registered 2026-11-18, 5 day(s) before the first match; a name that new may be the operator's (CASE_STUDY §16); fresh-parcel.test was used by 0 campus address(es) on 0 of 33 retained days before the first match; an established site needs 7 on 9 (CASE_STUDY §15) |

**Threat**

- [ThreatFox, about the indicator only] 198.51.100.170:443 (ip:port) is listed as win.nanocore, threat type botnet_cc.
- [IOC feed] the flagged address 198.51.100.170 is in AS64511 Example Virtual Servers LLC (US).

**Host**

- [Retained history] the address appears on 35 retained day(s) from 2026-10-21 to 2026-11-24, with traffic to or from a known remote address on 35.
- [Retained history, cited knowledge] none of the products with a known purpose appears on its retained days.
- [Retained history] on 2026-11-23 it used 29 distinct services (campus addresses with a service row had a median of 20 and a 90th percentile of 35) and moved 790.2 MB.
- [Published triage stream] 26 episode(s) on 15 day(s): relationship 25, transfer 1.
- [Live source] names it used on the most of the 3 day(s) read, with the number of days: fable-health.test (3), fjord-travel.test (3), hazel-music.test (3), kelp-shop.test (3), lark-jobs.test (3), notify-hub.test (3), open-archive.test (3), ridge-shop.test (3).

**What happened**

- [Live source] The host's contact with the flagged address: 198.51.100.170 443/TCP, SNI cdn.fresh-parcel.test, 1 minute(s) on 2026-11-23, first 2026-11-23 14:30 UTC, last 2026-11-23 14:30 UTC; 43.1 KB received, 4.5 KB sent.
- [Measured, CASE_STUDY §14] 198.51.100.170 carried at most 1 registered domain(s): not shown to be shared (10+ would be).
- [Live source] Read 2026-11-22 to 2026-11-24 (3 day(s)): after the first match the next destination new to this host was nimbus-pebble-health.test, 1.1 h later; 2 new named destination(s) and 0 network(s) with no name in all; uploads of 1 MB or more to new destinations (CASE_STUDY §8): none.
- [Live source] No contact with the flagged address(es) on the re-queried day(s) after the match (2026-11-24); matched on the address, so a moved name would not show.
- [Live source] Named destinations shared by the 1 active day(s) before and after the match: 0.45; no traffic with a known remote address on 0 of 1 later day(s) (retained history: 0 of 35 days).

**Could not check:** nothing; every check ran (live re-query, published stream, retained 5-minute timing).

**Next steps:**

1. Identify the device: the address lease (DHCP, network access control or VPN logs) for 10.30.2.47 from 2026-11-23 14:15 UTC to 2026-11-23 15:30 UTC. An address is not a device (CASE_STUDY §6). To judge whether the address still holds that device: its named destinations after the match overlap those before it by 0.45, and it had no traffic with a known remote address on 0 of 1 later day(s) (see [Live source, continuity]).
2. Identify the process behind contact 198.51.100.170 443/TCP, SNI cdn.fresh-parcel.test at 2026-11-23 14:30 UTC: not a protocol mismatch: fresh-parcel.test was registered 2026-11-18, 5 day(s) before the first match; a name that new may be the operator's (CASE_STUDY §16); fresh-parcel.test was used by 0 campus address(es) on 0 of 33 retained days before the first match; an established site needs 7 on 9 (CASE_STUDY §15).
3. Check the host's endpoint record for a NanoCore client process and its persistence (a .NET executable started from the user profile) and for outbound TCP from it.

**Would change it:** an ordinary reason for the contacts no rule explains.

<a id="case-7"></a>
### 7. `203.0.113.200:1604` · `10.30.3.44` · explained (E6)

win.nanocore, botnet_cc · first match 2026-11-23 04:00 UTC · 3 matched minute(s) in 3 feed record(s) · ThreatFox first saw the indicator 2026-11-14 06:05 UTC, 9 day(s) before the first match (from data/ioc_metadata.json) · live re-query fully · blind model not asked.

**Why:**

- E6 explains 1 kind(s) of contact: the host sent 0 bytes in these minutes: inbound traffic it did not answer.

| From (UTC) | To | Source | What | Min / flows | In | Out | Longest | Judged |
|---|---|---|---|---|---|---|---|---|
| 2026-11-23 04:00 | 2026-11-23 04:19 | Live source, also in the IOC feed | contact: 203.0.113.200 1604/TCP, no name | 3 | 1.8 KB | 0 B | — | explained by E6 (the host sent 0 bytes in these minutes: inbound traffic it did not answer) |

**Threat**

- [ThreatFox, about the indicator only] 203.0.113.200:1604 (ip:port) is listed as win.nanocore, threat type botnet_cc.
- [IOC feed] the flagged address 203.0.113.200 is in AS64512 Example Bulletproof Hosting (RU).

**Host**

- [Retained history] the address appears on 35 retained day(s) from 2026-10-21 to 2026-11-24, with traffic to or from a known remote address on 35.
- [Retained history, cited knowledge] none of the products with a known purpose appears on its retained days.
- [Retained history] on 2026-11-23 it used 13 distinct services (campus addresses with a service row had a median of 20 and a 90th percentile of 35) and moved 2.8 MB.
- [Published triage stream] 12 episode(s) on 12 day(s): relationship 11, fanout 1.

**What happened**

- [Live source] The host's contact with the flagged address: 203.0.113.200 1604/TCP, no name, 3 minute(s) on 2026-11-23, first 2026-11-23 04:00 UTC, last 2026-11-23 04:19 UTC; 1.8 KB received, 0 B sent.
- [Measured, CASE_STUDY §14] 203.0.113.200 carried at most 0 registered domain(s): not shown to be shared (10+ would be).
- [Live source] No contact with the flagged address(es) on the re-queried day(s) after the match (2026-11-24); matched on the address, so a moved name would not show.

**Could not check:** nothing; every check ran (live re-query, published stream, retained 5-minute timing).

**Would change it:** new contact with the flagged address that no rule explains.

<a id="case-8"></a>
### 8. `203.0.113.10:443` · `10.30.1.7` · explained (E4)

win.lumma, botnet_cc · first match 2026-11-23 10:12 UTC · 1 matched minute(s) in 1 feed record(s) · ThreatFox first saw the indicator 2026-11-18 06:01 UTC, 5 day(s) before the first match (from data/ioc_metadata.json) · live re-query fully · blind model not asked.

**Why:**

- E4 explains 1 kind(s) of contact: campus-print.test: 50 campus addresses on 32 days before the first match, served from AS13335; 203.0.113.10 is on Cloudflare's network, shared by design.

| From (UTC) | To | Source | What | Min / flows | In | Out | Longest | Judged |
|---|---|---|---|---|---|---|---|---|
| 2026-11-23 10:12 | 2026-11-23 10:12 | Live source, also in the IOC feed | contact: 203.0.113.10 443/TCP, SNI portal.campus-print.test | 1 | 51.6 KB | 19.2 KB | — | explained by E4 (campus-print.test: 50 campus addresses on 32 days before the first match, served from AS13335; 203.0.113.10 is on Cloudflare's network, shared by design) |

**Threat**

- [ThreatFox, about the indicator only] 203.0.113.10:443 (ip:port) is listed as win.lumma, threat type botnet_cc.
- [IOC feed] the flagged address 203.0.113.10 is in AS13335 Cloudflare, Inc. (US).

**Host**

- [Retained history] the address appears on 35 retained day(s) from 2026-10-21 to 2026-11-24, with traffic to or from a known remote address on 35.
- [Retained history, cited knowledge] none of the products with a known purpose appears on its retained days.
- [Retained history] on 2026-11-23 it used 31 distinct services (campus addresses with a service row had a median of 20 and a 90th percentile of 35) and moved 25.6 MB.
- [Published triage stream] 35 episode(s) on 23 day(s): relationship 35.

**What happened**

- [Live source] The host's contact with the flagged address: 203.0.113.10 443/TCP, SNI portal.campus-print.test, 1 minute(s) on 2026-11-23, first 2026-11-23 10:12 UTC, last 2026-11-23 10:12 UTC; 51.6 KB received, 19.2 KB sent.
- [Measured, CASE_STUDY §14] 203.0.113.10 carried at most 1 registered domain(s), and is on Cloudflare's network, whose sites share its addresses by design: shared hosting.
- [Live source] No contact with the flagged address(es) on the re-queried day(s) after the match (2026-11-24); matched on the address, so a moved name would not show.

**Could not check:** nothing; every check ran (live re-query, published stream, retained 5-minute timing).

**Would change it:** new contact with the flagged address that no rule explains.

<a id="case-9"></a>
### 9. `198.51.100.160:443` · `10.30.2.15` · explained (E3)

win.nanocore, botnet_cc · first match 2026-11-23 14:00 UTC · 1 matched minute(s) in 1 feed record(s) · ThreatFox first saw the indicator 2026-11-19 06:09 UTC, 4 day(s) before the first match (from data/ioc_metadata.json) · live re-query fully · blind model not asked.

**Why:**

- E3 explains 1 kind(s) of contact: TLS to api.kiwi-garden.test; win.nanocore's C2 channel carries no TLS; kiwi-garden.test registered 2014-03-02.

| From (UTC) | To | Source | What | Min / flows | In | Out | Longest | Judged |
|---|---|---|---|---|---|---|---|---|
| 2026-11-23 14:00 | 2026-11-23 14:00 | Live source, also in the IOC feed | contact: 198.51.100.160 443/TCP, SNI api.kiwi-garden.test | 1 | 18.4 KB | 4.8 KB | — | explained by E3 (TLS to api.kiwi-garden.test; win.nanocore's C2 channel carries no TLS; kiwi-garden.test registered 2014-03-02) |

**Threat**

- [ThreatFox, about the indicator only] 198.51.100.160:443 (ip:port) is listed as win.nanocore, threat type botnet_cc.
- [IOC feed] the flagged address 198.51.100.160 is in AS64511 Example Virtual Servers LLC (US).

**Host**

- [Retained history] the address appears on 35 retained day(s) from 2026-10-21 to 2026-11-24, with traffic to or from a known remote address on 35.
- [Retained history, cited knowledge] none of the products with a known purpose appears on its retained days.
- [Retained history] on 2026-11-23 it used 34 distinct services (campus addresses with a service row had a median of 20 and a 90th percentile of 35) and moved 366.0 MB.
- [Published triage stream] 24 episode(s) on 19 day(s): relationship 22, fanout 2.

**What happened**

- [Live source] The host's contact with the flagged address: 198.51.100.160 443/TCP, SNI api.kiwi-garden.test, 1 minute(s) on 2026-11-23, first 2026-11-23 14:00 UTC, last 2026-11-23 14:00 UTC; 18.4 KB received, 4.8 KB sent.
- [Measured, CASE_STUDY §14] 198.51.100.160 carried at most 1 registered domain(s): not shown to be shared (10+ would be).
- [Live source] No contact with the flagged address(es) on the re-queried day(s) after the match (2026-11-24); matched on the address, so a moved name would not show.

**Could not check:** nothing; every check ran (live re-query, published stream, retained 5-minute timing).

**Would change it:** new contact with the flagged address that no rule explains.

<a id="case-10"></a>
### 10. `198.51.100.140:443` · `10.30.3.71` · explained (E1)

win.nanocore, botnet_cc · first match 2026-11-23 15:00 UTC · 2 matched minute(s) in 2 feed record(s) · ThreatFox first saw the indicator 2026-11-13 06:06 UTC, 10 day(s) before the first match (from data/ioc_metadata.json) · live re-query fully · blind model not asked.

**Why:**

- E1 explains 1 kind(s) of contact: UDP contact; win.nanocore's C2 channel is TCP only.

| From (UTC) | To | Source | What | Min / flows | In | Out | Longest | Judged |
|---|---|---|---|---|---|---|---|---|
| 2026-11-23 15:00 | 2026-11-23 15:03 | Live source, also in the IOC feed | contact: 198.51.100.140 443/UDP, no name | 2 | 240.0 KB | 18.0 KB | — | explained by E1 (UDP contact; win.nanocore's C2 channel is TCP only) |

**Threat**

- [ThreatFox, about the indicator only] 198.51.100.140:443 (ip:port) is listed as win.nanocore, threat type botnet_cc.
- [IOC feed] the flagged address 198.51.100.140 is in AS64511 Example Virtual Servers LLC (US).

**Host**

- [Retained history] the address appears on 35 retained day(s) from 2026-10-21 to 2026-11-24, with traffic to or from a known remote address on 35.
- [Retained history, cited knowledge] none of the products with a known purpose appears on its retained days.
- [Retained history] on 2026-11-23 it used 10 distinct services (campus addresses with a service row had a median of 20 and a 90th percentile of 35) and moved 1.9 MB.
- [Published triage stream] 10 episode(s) on 9 day(s): relationship 10.

**What happened**

- [Live source] The host's contact with the flagged address: 198.51.100.140 443/UDP, no name, 2 minute(s) on 2026-11-23, first 2026-11-23 15:00 UTC, last 2026-11-23 15:03 UTC; 240.0 KB received, 18.0 KB sent.
- [Measured, CASE_STUDY §14] 198.51.100.140 carried at most 0 registered domain(s): not shown to be shared (10+ would be).
- [Live source] No contact with the flagged address(es) on the re-queried day(s) after the match (2026-11-24); matched on the address, so a moved name would not show.

**Could not check:** nothing; every check ran (live re-query, published stream, retained 5-minute timing).

**Would change it:** new contact with the flagged address that no rule explains.

<a id="case-11"></a>
### 11. `203.0.113.20:443` · `10.30.1.90` · explained (E2)

win.nanocore, botnet_cc · first match 2026-11-23 16:00 UTC · 1 matched minute(s) in 1 feed record(s) · ThreatFox first saw the indicator 2026-11-12 06:07 UTC, 11 day(s) before the first match (from data/ioc_metadata.json) · live re-query fully · blind model not asked.

**Why:**

- E2 explains 1 kind(s) of contact: ECH outer name cloudflare-ech.com: only browsers send ECH, and win.nanocore is a native program.

| From (UTC) | To | Source | What | Min / flows | In | Out | Longest | Judged |
|---|---|---|---|---|---|---|---|---|
| 2026-11-23 16:00 | 2026-11-23 16:00 | Live source, also in the IOC feed | contact: 203.0.113.20 443/TCP, SNI cloudflare-ech.com (ECH outer name) | 1 | 60.0 KB | 4.0 KB | — | explained by E2 (ECH outer name cloudflare-ech.com: only browsers send ECH, and win.nanocore is a native program) |

**Threat**

- [ThreatFox, about the indicator only] 203.0.113.20:443 (ip:port) is listed as win.nanocore, threat type botnet_cc.
- [IOC feed] the flagged address 203.0.113.20 is in AS13335 Cloudflare, Inc. (US).

**Host**

- [Retained history] the address appears on 35 retained day(s) from 2026-10-21 to 2026-11-24, with traffic to or from a known remote address on 35.
- [Retained history, cited knowledge] none of the products with a known purpose appears on its retained days.
- [Retained history] on 2026-11-23 it used 35 distinct services (campus addresses with a service row had a median of 20 and a 90th percentile of 35) and moved 33.4 MB.
- [Published triage stream] 39 episode(s) on 23 day(s): relationship 39.

**What happened**

- [Live source] The host's contact with the flagged address: 203.0.113.20 443/TCP, SNI cloudflare-ech.com (ECH outer name), 1 minute(s) on 2026-11-23, first 2026-11-23 16:00 UTC, last 2026-11-23 16:00 UTC; 60.0 KB received, 4.0 KB sent.
- [Measured, CASE_STUDY §14] 203.0.113.20 carried at most 0 registered domain(s), and is on Cloudflare's network, whose sites share its addresses by design: shared hosting.
- [Live source] No contact with the flagged address(es) on the re-queried day(s) after the match (2026-11-24); matched on the address, so a moved name would not show.

**Could not check:** nothing; every check ran (live re-query, published stream, retained 5-minute timing).

**Would change it:** new contact with the flagged address that no rule explains.

## Appendix

### The rules

| Rule | Meaning | Basis | Cases |
|---|---|---|---|
| E1 | UDP, and the family's C2 channel is TCP only (cited profile; botnet_cc) | knowledge | 1 |
| E2 | ECH outer name: only browsers send ECH; the family is a native program | knowledge | 1 |
| E3 | TLS to another site no operator chose, not newly registered; the family's C2 has no TLS | knowledge, CASE_STUDY §16 | 1 |
| E4 | established site (7+ campus addresses on 9+ days before the match), served from its usual network, on an address carrying 10+ registered domains or on a network that shares its addresses by design | CASE_STUDY §14, §15; knowledge | 1 |
| E5 | a tunnelling service's own client port: the host runs the tunnel client | knowledge | 0 |
| E6 | the host sent nothing: inbound traffic it did not answer | feed | 1 |
| K1 | the host's traffic named the flagged domain (lure and payload visits too) | feed | 2 |
| K2 | a tunnelling service reached on another port: a visitor | knowledge | 1 |
| K3 | a triage-stream episode on the flagged destination itself | stream | 3 |
| K4 | scheduled low-volume contact not explained as an established site | CASE_STUDY §10, §13 | 1 |
| K5 | payload delivery: 1 MB or more not explained as an established site | CASE_STUDY §8 | 1 |
| — | review because at least one contact has no explanation | — | 5 |

### The checks behind every verdict

| Check | Scope | A positive would be | Result |
|---|---|---|---|
| Named the flagged domain | 3 case(s) on a domain indicator | a contact whose TLS or DNS name is under the flagged domain | 2 case(s): #4, #5 |
| A tunnel reached as a visitor | 2 case(s) with a name of a cited tunnelling service | a tunnelling service reached on a port other than its client port | 1 case(s): #5 |
| A stream episode on the flagged destination | 11 of 11 case(s) with every match day published | a relationship or persistence episode on the flagged domain or address | 3 case(s): #1, #4, #5 |
| A scheduled low-volume contact | minute grain on 11 of 11 case(s) re-queried; 5-minute grain on 11 with every match day retained | regular contact over 6 h or more at low volume (CASE_STUDY §10, §13) | 1 case(s): #2 |
| A transfer from a payload server | 2 payload-delivery case(s) | a long flow of 1 MB or more not on an established shared site | 1 case(s): #3 |
| A newly registered TLS name | 1 kind(s) of contact explained by the TLS-name rule alone | a name registered under 32 days before the match (RDAP) | 1 checked; the age of the names in 0 case(s) is unknown |
