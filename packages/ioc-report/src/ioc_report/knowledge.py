"""What is known about a ThreatFox family, a tunnelling service or a name, before any traffic.

Knowledge, not measurement: nothing here is a threshold. Every family and service entry cites the
public references it rests on, and an entry is added only when its decision-bearing fields can be
cited. A family without an entry, or with a field left `None`, enables no rule that depends on it:
unknown never explains anything.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

import tldextract
from network_behaviour.normalization.service import registered_domain
from network_behaviour.synthetic import SYNTHETIC_PUBLIC_SUFFIXES, synthetic_world

TCP = 6
UDP = 17

# The same extractor configuration the publisher uses (`normalization/service.py`), with the
# public suffix list's private section switched on. A name under a private suffix (github.io,
# workers.dev, duckdns.org, ...) belongs to one tenant of a shared platform, while retained
# history hashes it under the platform's registered domain, so its prevalence there describes the
# platform, not the tenant. In a synthetic world `test` is a public suffix here too, as it is for
# the publisher, so `a.lure.test` and `b.lure.test` share a tenant.
_PRIVATE_AWARE = tldextract.TLDExtract(
    cache_dir=None, suffix_list_urls=(), include_psl_private_domains=True
)
_PRIVATE_AWARE_SYNTHETIC = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(),
    include_psl_private_domains=True,
    extra_suffixes=SYNTHETIC_PUBLIC_SUFFIXES,
)


def _private_aware(name: str) -> tldextract.tldextract.ExtractResult:
    return (_PRIVATE_AWARE_SYNTHETIC if synthetic_world() else _PRIVATE_AWARE)(name)


# Encrypted Client Hello: the outer SNI names the CDN, and the site actually visited is hidden.
# Only browsers send ECH (https://developers.cloudflare.com/ssl/edge-certificates/ech/).
ECH_OUTER_NAMES = frozenset({"cloudflare-ech.com"})

# Ported from IOC_Processor `agent/knowledge.py`. A name in these lists is never accepted as an
# ordinary site: an operator controls the name, so how common the parent domain is says nothing.
DYNAMIC_DNS_DOMAINS = frozenset(
    {
        "duckdns.org", "no-ip.com", "no-ip.org", "no-ip.biz", "no-ip.info", "noip.com",
        "ddns.net", "hopto.org", "zapto.org", "sytes.net", "serveftp.com", "servehttp.com",
        "myftp.biz", "myftp.org", "redirectme.net", "servebeer.com", "freeddns.org", "dynu.net",
        "dynu.com", "dyndns.org", "dyndns.biz", "changeip.com", "afraid.org", "mooo.com",
        "3utilities.com", "bounceme.net", "ddnsking.com", "gotdns.ch", "linkpc.net",
        "publicvm.com", "kozow.com",
    }
)  # fmt: skip
FREE_HOSTING_DOMAINS = frozenset(
    {
        "000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com", "github.io",
        "netlify.app", "vercel.app", "pages.dev", "workers.dev", "glitch.me", "firebaseapp.com",
        "web.app", "herokuapp.com", "repl.co", "godaddysites.com", "square.site",
    }
)  # fmt: skip
TUNNEL_DOMAINS = frozenset(
    {
        "bore.pub", "argotunnel.com", "cftunnel.com", "trycloudflare.com", "ngrok.io",
        "ngrok.com", "ngrok.app", "ngrok.dev", "ngrok-free.app", "ngrok-free.dev",
        "ngrok-agent.com", "playit.gg", "ply.gg", "joinmc.link", "loca.lt", "serveo.net",
        "localhost.run", "lhr.life", "pinggy.io", "pinggy.link", "localtonet.com",
    }
)  # fmt: skip


@dataclass(frozen=True, slots=True)
class FamilyProfile:
    """A ThreatFox (Malpedia) family. Decision-bearing fields are `None` unless cited."""

    family: str
    name: str
    client: str | None
    """"native" for a program, "browser" for script that runs in a web page."""
    c2_tls: bool | None
    """Whether the family's command-and-control channel is TLS."""
    c2_udp: bool | None
    """Whether the family's command-and-control channel can use UDP."""
    background: str
    check: str
    """What an analyst can check on the host, for the report's next steps."""
    sources: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ServiceProfile:
    """A tunnelling service: its own client connects to `client_ports`; anything else on its
    addresses is a visitor reaching something published through it."""

    key: str
    name: str
    domains: tuple[str, ...]
    client_ports: tuple[tuple[int, int], ...]
    """(port, transport) pairs the service's own client uses."""
    exposes: str
    sources: tuple[str, ...]

    def is_client_port(self, port: int, transport: int) -> bool:
        return (port, transport) in self.client_ports


FAMILIES: dict[str, FamilyProfile] = {
    profile.family: profile
    for profile in (
        FamilyProfile(
            family="win.nanocore",
            name="NanoCore RAT",
            client="native",
            c2_tls=False,
            c2_udp=False,
            background=(
                "Windows remote-access trojan. The victim connects out to an operator-chosen host "
                "and port and speaks NanoCore's own protocol: length-prefixed, DES-encrypted "
                "frames over plain TCP. That channel carries no TLS handshake and never uses UDP."
            ),
            check=(
                "Check the host's endpoint record for a NanoCore client process and its "
                "persistence (a .NET executable started from the user profile) and for outbound "
                "TCP from it."
            ),
            sources=(
                "https://github.com/nict-csl/NanoCoreRAT-Analysis",
                "https://unit42.paloaltonetworks.com/nanocorerat-behind-an-increase-in-tax-themed-phishing-e-mails/",
                "https://malpedia.caad.fkie.fraunhofer.de/details/win.nanocore",
            ),
        ),
        FamilyProfile(
            family="elf.shadowv2",
            name="ShadowV2 (Linux botnet)",
            client="native",
            c2_tls=None,
            c2_udp=None,
            background=(
                "Linux botnet malware for servers and devices. A payload_delivery listing is a "
                "server that hands out the binary or the script that fetches it."
            ),
            check=(
                "Find what the host downloaded from the indicator and whether it ran: shell "
                "history, new binaries or cron entries on the host."
            ),
            sources=("https://malpedia.caad.fkie.fraunhofer.de/details/elf.shadowv2",),
        ),
        FamilyProfile(
            family="js.clearfake",
            name="ClearFake",
            client="browser",
            c2_tls=None,
            c2_udp=None,
            background=(
                "JavaScript injected into compromised legitimate sites. It shows a fake browser "
                "update, and the real payload arrives afterwards from another address. The "
                "flagged domain is often the compromised site itself."
            ),
            check=(
                "Check the browser's download history and the endpoint record around the visit "
                "for a fake 'browser update' download and anything it started."
            ),
            sources=("https://malpedia.caad.fkie.fraunhofer.de/details/js.clearfake",),
        ),
        FamilyProfile(
            family="js.iclickfix",
            name="ClickFix-style lure",
            client="browser",
            c2_tls=None,
            c2_udp=None,
            background=(
                "A page that tricks the user into pasting and running a command (a fake CAPTCHA "
                "or 'fix this error' prompt). The visit itself is a small page load; the harm "
                "comes from the command the user runs."
            ),
            check=(
                "Check the endpoint record around the visit for PowerShell, mshta or cmd started "
                "from the Run dialog or a terminal, and for what that command downloaded."
            ),
            sources=("https://malpedia.caad.fkie.fraunhofer.de/details/js.iclickfix",),
        ),
    )
}


@dataclass(frozen=True, slots=True)
class FamilyBackground:
    """What a case report may say about a family: a name, a description and what to check."""

    family: str
    name: str
    background: str
    check: str
    sources: tuple[str, ...]
    channel: str | None = None
    """What the family's cited channel means for a contact nothing explains."""


# Families described for reports alone. They carry no decision-bearing field. On a ThreatFox case
# only the case report and the writer's family-name check read this table, so adding an entry
# changes no decision and no blind input. A family moves to FAMILIES only when a rule needs it,
# which starts a new evaluation. A case from another list has no evaluated blind input to protect,
# so its digest and case file can show the description too (`other_list_background`).
REPORT_FAMILIES: dict[str, FamilyBackground] = {
    entry.family: entry
    for entry in (
        FamilyBackground(
            family="win.asyncrat",
            name="AsyncRAT",
            background=(
                "Open-source .NET remote-access trojan, public since 2019 and used for remote "
                "commands, file transfer, keylogging, screen capture and credential theft. The "
                "victim connects out to the operator's server over a custom TCP protocol wrapped "
                "in TLS, often with a self-signed certificate."
            ),
            check=(
                "Check the host's endpoint record around the contact for a .NET client kept "
                "running by a scheduled task set to start at logon, or by a Run registry entry."
            ),
            sources=(
                "https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat",
                "https://censys.com/blog/asyncrat-c2-activity-at-internet-scale",
                "https://blog.qualys.com/vulnerabilities-threat-research/2022/08/16/asyncrat-c2-framework-overview-technical-analysis-and-detection",
            ),
            channel="AsyncRAT's channel is wrapped in TLS, so TLS on the contact cannot explain it",
        ),
        FamilyBackground(
            family="js.smartapesg",
            name="SmartApeSG",
            background=(
                "A campaign, also called ZPHP or HANEYMANEY, that injects script into hijacked "
                "legitimate websites. Visitors see a fake browser update or a fake 'verify you are "
                "human' page, and following it installs a remote-access tool, commonly NetSupport "
                "RAT."
            ),
            check=(
                "Check the browser's download history and the endpoint record around the visit "
                "for a fake browser-update download, for mshta or PowerShell started from the Run "
                "dialog, and for NetSupport's client32.exe."
            ),
            sources=(
                "https://malpedia.caad.fkie.fraunhofer.de/details/js.smartapesg",
                "https://www.threatdown.com/blog/smartapesg-06-11-2024/",
                "https://isc.sans.edu/diary/32474",
            ),
        ),
        FamilyBackground(
            family="php2shell",
            name="php2shell",
            background=(
                "Two critical flaws in PHP (CVE-2026-109618 and CVE-2026-109619) that can allow "
                "unauthenticated remote code execution, fixed in PHP 8.5.12, 8.4.27, 8.3.36 and "
                "8.2.35. Amazon lists addresses tied to exploitation attempts and warns that they "
                "include shared anonymization infrastructure not exclusive to this activity."
            ),
            check=(
                "Search the server's web logs at the contact times for POST requests with "
                "PHP_SESSION_UPLOAD_PROGRESS in form uploads, check for unexpected process "
                "execution or file changes, and confirm its PHP is a fixed version."
            ),
            sources=(
                "https://www.php.net/archive/2026.php#2026-10-21-5",
                "https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/",
                "https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/",
            ),
        ),
    )
}


@dataclass(frozen=True, slots=True)
class SharedNetwork:
    """A network whose addresses are shared by design, however few names campus saw on one. E4 and
    the blind case file read it, so a new entry starts a new evaluation. It never clears a visit to
    a flagged domain (K1) or a transfer (K5), and says nothing of what the network can carry: such
    a network can also proxy raw TCP (https://developers.cloudflare.com/spectrum/), so no protocol
    rule reads it."""

    asn: int
    name: str
    sources: tuple[str, ...]


SHARED_NETWORKS: dict[int, SharedNetwork] = {
    entry.asn: entry
    for entry in (
        SharedNetwork(
            asn=13335,
            name="Cloudflare",
            sources=(
                "https://www.peeringdb.com/asn/13335",
                "https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/",
                "https://blog.cloudflare.com/addressing-agility/",
            ),
        ),
    )
}


@dataclass(frozen=True, slots=True)
class Listing:
    """A published list of indicators, and where a feed's records keep what the list says. A new
    list is a new entry here, with its sources, and needs no new code."""

    key: str
    """What `--listing` names."""
    source: str
    """Who publishes the list, as a report names them."""
    indicator_field: str = "indicator"
    claim_field: str | None = None
    """The record's object holding `malware`, `threat_type` and `confidence`. None: the list says
    the same of every record, in the two fields below."""
    family: str = "unknown"
    threat_type: str = "unknown"
    address_only: bool = False
    """The list names addresses. A port in the record's indicator is only the port seen on the
    matched contact, so two ports on one address are one indicator."""
    inbound: bool = False
    """The list names addresses that connect in to their targets, so a TLS name on the contact is
    the campus host's own site."""
    sources: tuple[str, ...] = ()
    advisories: tuple[str, ...] = ()
    """The CVEs the list's addresses were seen exploiting, when its publisher names them. A list
    with any adds serving-address lines to its digests; no rule and no blind input reads it."""


THREATFOX = Listing(
    key="threatfox",
    source="ThreatFox",
    claim_field="threatfox",
    sources=("https://threatfox.abuse.ch/",),
)
LISTINGS: dict[str, Listing] = {
    entry.key: entry
    for entry in (
        THREATFOX,
        Listing(
            key="amazon-php2shell",
            source="Amazon Threat Intelligence",
            indicator_field="aws_indicator",
            family="php2shell",
            threat_type="exploit_source",
            address_only=True,
            inbound=True,
            sources=(
                "https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/",
            ),
            advisories=("CVE-2026-109618", "CVE-2026-109619"),
        ),
    )
}

SERVICES: tuple[ServiceProfile, ...] = (
    ServiceProfile(
        key="bore",
        name="bore (reverse TCP tunnel)",
        domains=("bore.pub",),
        client_ports=((7835, TCP),),
        exposes=(
            "the host runs a bore client: it publishes one of its own ports at bore.pub. A C2 "
            "client would instead connect to the tunnel's public port, not to 7835"
        ),
        sources=("https://github.com/ekzhang/bore",),
    ),
    ServiceProfile(
        key="cloudflared",
        name="Cloudflare Tunnel (cloudflared)",
        domains=("argotunnel.com", "cftunnel.com"),
        client_ports=((7844, TCP), (7844, UDP)),
        exposes=(
            "the host runs cloudflared: it publishes a local service through Cloudflare. Visitors "
            "reach published services on Cloudflare's addresses on 443, not on 7844"
        ),
        sources=(
            "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/"
            "deploy-tunnels/tunnel-with-firewall/",
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class SoftwareSignal:
    """A registered domain that belongs to one product, so a host's retained use of it says the
    product was in use there. Retained history hashes services per registered domain, so only a
    domain the product owns outright can be one; a browser visiting the same domain looks the same.
    Shown only: it describes the address, never classifies it."""

    key: str
    name: str
    domains: tuple[str, ...]
    meaning: str
    sources: tuple[str, ...]


SOFTWARE_SIGNALS: tuple[SoftwareSignal, ...] = (
    SoftwareSignal(
        key="windows-update",
        name="Windows Update",
        domains=("windowsupdate.com",),
        meaning="Windows downloads operating-system updates from it",
        sources=("https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints",),
    ),
    SoftwareSignal(
        key="xbox-live",
        name="Xbox Live",
        domains=("xboxlive.com",),
        meaning="Windows' Xbox services and games use it",
        sources=("https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints",),
    ),
    SoftwareSignal(
        key="microsoft-365",
        name="Microsoft 365 (SharePoint, OneDrive, Office)",
        domains=("sharepoint.com", "office.com"),
        meaning="Microsoft 365 apps and Office in a browser use it",
        sources=(
            "https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges",
        ),
    ),
    SoftwareSignal(
        key="chrome-update",
        name="Google Chrome updates",
        domains=("gvt1.com",),
        meaning="Chrome checks for and downloads its updates there",
        sources=("https://support.google.com/chrome/a/answer/6350036",),
    ),
    SoftwareSignal(
        key="crowdstrike",
        name="CrowdStrike Falcon sensor",
        domains=("cloudsink.net",),
        meaning="the Falcon endpoint sensor reports to CrowdStrike's cloud there",
        sources=(
            "https://www.dell.com/support/kbdoc/en-us/000177899/crowdstrike-falcon-sensor-system-requirements",
        ),
    ),
    SoftwareSignal(
        key="icloud",
        name="iCloud",
        domains=("icloud.com",),
        meaning="Apple devices use it for iCloud services",
        sources=("https://support.apple.com/en-us/101555",),
    ),
    SoftwareSignal(
        key="app-store",
        name="Apple App Store content",
        domains=("mzstatic.com",),
        meaning="Apple devices fetch App Store content from it",
        sources=("https://support.apple.com/en-us/101555",),
    ),
    SoftwareSignal(
        key="debian",
        name="Debian package archive",
        domains=("debian.org",),
        meaning="Debian systems fetch packages through deb.debian.org",
        sources=("https://deb.debian.org/",),
    ),
    SoftwareSignal(
        key="docker",
        name="Docker",
        domains=("docker.io", "docker.com"),
        meaning="Docker clients pull images and Docker Desktop updates from it",
        sources=("https://docs.docker.com/desktop/setup/allow-list/",),
    ),
    SoftwareSignal(
        key="remi-php",
        name="Remi's PHP repository",
        domains=("remirepo.net",),
        meaning="Fedora and Enterprise Linux servers get PHP packages from it",
        sources=("https://blog.remirepo.net/pages/English-FAQ",),
    ),
    SoftwareSignal(
        key="wordpress",
        name="WordPress.org",
        domains=("wordpress.org",),
        meaning=(
            "a WordPress installation checks api.wordpress.org for updates; a person reading "
            "wordpress.org looks the same"
        ),
        sources=("https://developer.wordpress.org/reference/functions/wp_version_check/",),
    ),
)


def family_profile(malware: str) -> FamilyProfile | None:
    return FAMILIES.get(malware.strip().lower())


def family_background(malware: str) -> FamilyBackground | None:
    """The cited description of a family, from its profile or else REPORT_FAMILIES."""
    key = malware.strip().lower()
    if (profile := FAMILIES.get(key)) is not None:
        return FamilyBackground(
            profile.family, profile.name, profile.background, profile.check, profile.sources
        )
    return REPORT_FAMILIES.get(key)


def other_list_background(source: str, malware: str) -> FamilyBackground | None:
    """The description a digest or case file may show: none on a ThreatFox case, whose case files
    are the evaluated blind input."""
    return family_background(malware) if source != THREATFOX.source else None


def listing_for(key: str) -> Listing:
    found = LISTINGS.get(key.strip().lower())
    if found is None:
        raise ValueError(f"unknown listing {key!r}: known ones are {', '.join(sorted(LISTINGS))}")
    return found


def is_unnamed_family(malware: str) -> bool:
    """ThreatFox's generic labels (`unknown`, `unknown_loader`, ...) name no family to describe."""
    key = malware.strip().lower()
    return key == "unknown" or key.startswith("unknown_")


def clean(name: str) -> str:
    return name.strip().lower().rstrip(".")


def under(name: str, domain: str) -> bool:
    """`name` is `domain` or one of its subdomains."""
    name, domain = clean(name), clean(domain)
    return bool(domain) and (name == domain or name.endswith(f".{domain}"))


def service_for(name: str) -> ServiceProfile | None:
    if not name:
        return None
    return next(
        (service for service in SERVICES if any(under(name, d) for d in service.domains)), None
    )


def tenant_domain(name: str) -> str | None:
    """The registrable name with the private suffix section on: `abc.github.io` stays itself."""
    result = _private_aware(clean(name))
    if not result.suffix or not result.domain:
        return None
    return f"{result.domain}.{result.suffix}"


@dataclass(frozen=True, slots=True)
class NameFacts:
    name: str
    registered: str | None
    """The registered domain retained history hashes (private suffixes off)."""
    tenant: str | None
    platform_tenant: bool
    """Under a private suffix: one tenant of a shared platform."""
    category: str | None
    """"ech", "dynamic DNS", "tunnel", "free hosting" or None."""
    label_length: int
    digit_ratio: float
    entropy: float

    @property
    def operator_controlled(self) -> bool:
        """A name an operator can register freely on someone else's domain."""
        return self.category in {"dynamic DNS", "tunnel"}


def name_facts(name: str) -> NameFacts:
    cleaned = clean(name)
    registered = registered_domain(cleaned)
    category = None
    if cleaned in ECH_OUTER_NAMES:
        category = "ech"
    elif any(under(cleaned, d) for d in DYNAMIC_DNS_DOMAINS):
        category = "dynamic DNS"
    elif any(under(cleaned, d) for d in TUNNEL_DOMAINS):
        category = "tunnel"
    elif any(under(cleaned, d) for d in FREE_HOSTING_DOMAINS):
        category = "free hosting"
    labels = [part for part in cleaned.split(".") if part]
    if labels and labels[0] == "www":
        labels = labels[1:]
    label = labels[0] if labels else ""
    return NameFacts(
        name=cleaned,
        registered=registered,
        tenant=tenant_domain(cleaned),
        platform_tenant=bool(_private_aware(cleaned).is_private),
        category=category,
        label_length=len(label),
        digit_ratio=sum(ch.isdigit() for ch in label) / len(label) if label else 0.0,
        entropy=_entropy(label),
    )


def is_platform(registered: str) -> bool:
    """A registered domain whose names belong to separate tenants or operators (github.io,
    workers.dev, duckdns.org, trycloudflare.com, ...): its popularity establishes none of them."""
    probe = name_facts(f"tenant.{clean(registered)}")
    return probe.platform_tenant or probe.category in {"free hosting", "dynamic DNS", "tunnel"}


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())
