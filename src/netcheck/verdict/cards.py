"""Turn raw check results into result cards."""

from __future__ import annotations

import enum
import ipaddress
from dataclasses import dataclass, field

from netcheck.addrpolicy import IPAddress
from netcheck.asn import AsnClasses, AsnInfo
from netcheck.reputation.abuseipdb import Abuse, AbuseResult
from netcheck.reputation.greynoise import Reputation, ReputationResult
from netcheck.reputation.internetdb import History, HistoryResult
from netcheck.scan.models import ExposureResult, PortResult
from netcheck.verdict.content import IspContent
from netcheck.verdict.model import Card, Status


@dataclass(frozen=True)
class PortInfo:
    label: str
    fix_key: str
    status: Status
    context: str


_ADMIN = "Usually a router or device login page, which should only be reachable from home."
_CAMERA = "Usually a camera or video recorder, one of the devices botnets hijack most."
_ON_PURPOSE = "Fine only if you meant to expose it."
W, B = Status.WARN, Status.BAD

PORTS: dict[int, PortInfo] = {
    21: PortInfo("FTP file sharing", "open_port", W, "FTP sends passwords unencrypted. " + _ON_PURPOSE),
    22: PortInfo("SSH remote login", "open_port", W, "Fine if you set it up yourself with key-based login."),
    23: PortInfo("Telnet", "telnet", B, "Unencrypted remote login, and a favourite botnet target."),
    80: PortInfo("web page", "router_admin_exposed", B, _ADMIN),
    81: PortInfo("web page (port 81)", "camera_dvr", W, _CAMERA),
    443: PortInfo("web page (HTTPS)", "router_admin_exposed", B, _ADMIN),
    445: PortInfo("Windows file sharing (SMB)", "smb", B, "Behind several major ransomware outbreaks."),
    554: PortInfo("camera stream (RTSP)", "camera_dvr", W, _CAMERA),
    631: PortInfo("printer (IPP)", "printer", W, "Anyone can send it print jobs or probe it."),
    1723: PortInfo("PPTP VPN", "open_port", W, "An outdated VPN protocol with known weaknesses."),
    1883: PortInfo("smart-home messaging (MQTT)", "open_port", W, "Without a password, anyone can read or send commands."),
    3389: PortInfo("Windows Remote Desktop", "rdp", B, "Constantly attacked by password-guessing bots."),
    5000: PortInfo("NAS or UPnP web interface", "open_port", W, "Often a Synology NAS. " + _ON_PURPOSE),
    5001: PortInfo("NAS web interface (HTTPS)", "open_port", W, "Often a Synology NAS. Keep it updated and use two-factor login."),
    5555: PortInfo("Android debugging (ADB)", "adb", B, "Lets anyone install apps, usually on a TV box. Botnets scan for it constantly."),
    5900: PortInfo("screen sharing (VNC)", "vnc", B, "Can let strangers see and control a computer."),
    7547: PortInfo("TR-069 ISP management", "tr069", B, "Used by some ISPs to manage routers, and mass-exploited."),
    8000: PortInfo("web interface (port 8000)", "camera_dvr", W, "Often a camera or home server. " + _ON_PURPOSE),
    8080: PortInfo("web page (port 8080)", "router_admin_exposed", B, _ADMIN),
    8291: PortInfo("MikroTik router management", "router_service", B, "Exposed MikroTik routers have been hijacked in large numbers."),
    8443: PortInfo("web page (port 8443)", "router_admin_exposed", B, _ADMIN),
    8888: PortInfo("web interface (port 8888)", "open_port", W, _ON_PURPOSE),
    9100: PortInfo("printer (raw printing)", "printer", W, "Anyone can print to it."),
    32400: PortInfo("Plex media server", "open_port", W, "Normal with Plex remote access. Keep Plex updated."),
    34567: PortInfo("video recorder service", "camera_dvr", B, _CAMERA),
    37215: PortInfo("Huawei router service", "router_service", B, "Exploited by the Mirai botnet."),
    37777: PortInfo("Dahua video recorder service", "camera_dvr", B, _CAMERA),
    49000: PortInfo("router management (TR-064)", "router_service", B, "Should never be reachable from the internet."),
    52869: PortInfo("Realtek router UPnP service", "router_service", B, "Mass-exploited by botnets."),
}  # fmt: skip

# If (nearly) every port answers, something in the path (a firewall, proxy or tarpit)
# is accepting everything and the per-port results don't mean much.
ALL_OPEN_THRESHOLD = 0.75

CANT_CHECK = [
    "devices inside your home",
    "your Wi-Fi password and encryption",
    "your router's settings and firmware",
    "infections that aren't attacking anyone",
]


def mask_ip(ip: IPAddress) -> str:
    if ip.version == 4:
        return ".".join(str(ip).split(".")[:3]) + ".x"
    net = ipaddress.IPv6Network(f"{ip}/48", strict=False)
    return f"{str(net.network_address).rstrip(':')}:…"


def family_label(version: int) -> str:
    return "IPv4" if version == 4 else "IPv6"


# --- exposure ----------------------------------------------------------------


class SkipReason(enum.Enum):
    HOSTING = "hosting"
    CGNAT = "cgnat"
    ERROR = "error"


@dataclass
class ExposureOutcome:
    version: int
    result: ExposureResult | None = None
    skipped: SkipReason | None = None
    asn: AsnInfo | None = None
    cgnat_asn: bool = False


def _port_fact(p: PortResult, info: PortInfo | None) -> str:
    label = info.label if info else "unknown service"
    fact = f"Port {p.port} is open: {label}."
    if p.server_header:
        fact += f" It identifies as: {p.server_header}."
    if p.tls_subject:
        fact += f" Certificate: {p.tls_subject}."
    return fact


def exposure_card(o: ExposureOutcome, content: IspContent, isp_slug: str) -> Card:
    fam = family_label(o.version)
    title = f"Open to the internet ({fam})"
    key = f"exposure_v{o.version}"

    if o.skipped is SkipReason.HOSTING:
        network = f" ({o.asn.name})" if o.asn else ""
        return Card(
            key,
            title,
            Status.UNKNOWN,
            "You seem to be on a VPN or cloud network, so we didn't scan it.",
            facts=[f"Your {fam} address belongs to a hosting/VPN provider{network}."],
            note="We'd be scanning the VPN's servers, not your home. Turn the VPN off and run it again.",
        )
    if o.skipped is SkipReason.CGNAT:
        return _cant_see(key, title, fam, carrier=True, probes=None)
    if o.skipped is SkipReason.ERROR or o.result is None:
        return Card(
            key,
            title,
            Status.UNKNOWN,
            "This scan failed, so we couldn't check it.",
            note="Try again in a few minutes.",
        )

    r = o.result
    open_ports = r.open_ports
    ssdp = r.ssdp is not None and r.ssdp.responded
    natpmp = r.natpmp is not None and r.natpmp.responded
    open_resolver = r.dns is not None and r.dns.recursion
    dns_port = r.dns is not None and r.dns.responded and not open_resolver

    if r.ports and len(open_ports) >= ALL_OPEN_THRESHOLD * len(r.ports):
        return Card(
            key,
            title,
            Status.UNKNOWN,
            "Something answers on almost every port, so we can't tell what's really exposed.",
            facts=[f"{len(open_ports)} of {len(r.ports)} ports accepted a connection."],
            note="Usually a firewall or proxy in front of your connection, common on work, school and hotel networks.",
        )

    if not open_ports and not ssdp and not natpmp and not open_resolver and not dns_port:
        if o.cgnat_asn or not r.any_response:
            return _cant_see(key, title, fam, carrier=o.cgnat_asn, probes=len(r.ports))
        if not r.complete:
            return Card(
                key,
                title,
                Status.UNKNOWN,
                "The scan ran out of time, so we can't give this a pass.",
                note="Try again in a few minutes.",
            )
        return Card(
            key,
            title,
            Status.GOOD,
            f"Nothing answered on the {len(r.ports)} common ports and services we tested.",
            note="We tested common risky ports, not all 65,535.",
        )

    facts: list[str] = []
    fix_keys: list[str] = []
    worst = Status.WARN
    for p in open_ports:
        info = PORTS.get(p.port)
        facts.append(_port_fact(p, info))
        if info:
            facts.append(info.context)
            fix_keys.append(info.fix_key)
            if info.status is Status.BAD:
                worst = Status.BAD
        else:
            fix_keys.append("open_port")
    if ssdp and r.ssdp is not None:
        worst = Status.BAD
        fix_keys.insert(0, "upnp_wan")
        fact = "Your router answers UPnP discovery requests from the internet."
        dev = r.ssdp.device
        if dev and (dev.manufacturer or dev.model):
            desc = " ".join(x for x in (dev.manufacturer, dev.model) if x)
            fact += f" It describes itself as: {desc}"
            fact += f" (firmware {dev.firmware})." if dev.firmware else "."
        elif r.ssdp.server_header:
            fact += f" It identifies as: {r.ssdp.server_header}."
        facts.insert(0, fact)
    if natpmp:
        worst = Status.BAD
        fix_keys.insert(0, "natpmp")
        facts.insert(0, "Your router answers NAT-PMP port-mapping requests from the internet.")
    if open_resolver:
        worst = Status.BAD
        fix_keys.insert(0, "open_resolver")
        facts.insert(
            0,
            'Your router answers DNS lookups for anyone (an "open DNS resolver"). Attackers use these to flood websites.',
        )
    elif dns_port:
        facts.append(
            "Something answers DNS on port 53 but refused our lookup. Not dangerous, but it doesn't need to be public."
        )

    n = len(open_ports) + int(ssdp) + int(natpmp) + int(open_resolver) + int(dns_port)
    headline = (
        f"{n} thing{'s' if n != 1 else ''} on your network can be reached from the internet"
        + (" - some of them are risky." if worst is Status.BAD else ".")
    )
    note = None if r.complete else "The scan ran out of time, so there may be more."
    return Card(
        key,
        title,
        worst,
        headline,
        facts=facts,
        steps=_steps(content, isp_slug, fix_keys),
        fix_keys=list(dict.fromkeys(fix_keys)),
        note=note,
    )


def _cant_see(key: str, title: str, fam: str, *, carrier: bool, probes: int | None) -> Card:
    if carrier:
        return Card(
            key,
            title,
            Status.QUIET,
            f"Your router is hidden behind your provider's network ({fam}).",
            facts=[
                "Your provider shares addresses between customers (carrier-grade NAT), so nobody on the internet can reach your router."
            ],
            note="That protects you from what this check looks for, but we couldn't test the router itself.",
            label="Hidden",
        )
    tried = f"{probes} common entry points" if probes else "common entry points"
    return Card(
        key,
        title,
        Status.QUIET,
        f"Nothing on your network answered us from the internet ({fam}).",
        facts=[
            f'We tried {tried} and got no reply at all, not even a "closed".',
            "That's how a well-protected home network usually looks: the router ignores strangers.",
        ],
        note="It isn't a guarantee: carrier-grade NAT looks the same, though that also keeps your router out of reach.",
        label="Nothing visible",
    )


def _steps(content: IspContent, isp_slug: str, keys: list[str]) -> list[str]:
    out: list[str] = []
    for k in dict.fromkeys(keys):
        for step in content.steps(isp_slug, k):
            if step not in out:
                out.append(step)
    return out


# --- botnet & abuse (GreyNoise + AbuseIPDB) ---------------------------------------


def _greynoise_fact(r: ReputationResult) -> str:
    if r.verdict is Reputation.CLEAN:
        return "GreyNoise: not seen scanning or attacking the internet."
    details = ", ".join(
        x
        for x in (
            f"classification: {r.classification}" if r.classification else None,
            f"associated with {r.name}" if r.name and r.name.lower() != "unknown" else None,
            f"last seen {r.last_seen}" if r.last_seen else None,
        )
        if x
    )
    what = (
        "belongs to a business service or VPN"
        if r.verdict is Reputation.BUSINESS_OR_VPN
        else "seen scanning or attacking the internet"
    )
    return f"GreyNoise: {what}" + (f" ({details})." if details else ".")


def _abuse_fact(r: AbuseResult) -> str:
    if r.verdict is Abuse.NO_REPORTS:
        if r.reports == 0:
            return "AbuseIPDB: no reports in the last 30 days."
        return f"AbuseIPDB: {r.reports} old or low-trust reports, rated 0/100."
    fact = (
        f"AbuseIPDB: {r.reports} report{'s' if r.reports != 1 else ''} from {r.reporters} "
        f"reporter{'s' if r.reporters != 1 else ''} in the last 30 days "
        f"(confidence {r.score}/100"
    )
    fact += f", most recent {r.last_reported})." if r.last_reported else ")."
    return fact


def botnet_card(
    gn: ReputationResult | None,
    ab: AbuseResult | None,
    *,
    abuse_enabled: bool,
    content: IspContent,
    isp_slug: str,
) -> Card:
    """One card for "has this address been attacking people?", from up to two sources.

    The card shows the worse of the answers we got; it's "couldn't check" only when
    no source answered.
    """
    title = "Botnet & abuse reports"
    key = "reputation"
    gn_ok = gn is not None and gn.verdict is not Reputation.UNKNOWN
    ab_ok = abuse_enabled and ab is not None and ab.verdict is not Abuse.UNKNOWN

    if not gn_ok and not ab_ok:
        ipv6_only = gn is not None and gn.reason == "ipv6_unsupported" and not abuse_enabled
        return Card(
            key,
            title,
            Status.UNKNOWN,
            "We couldn't check whether your address has been attacking other computers.",
            note=(
                "The reputation service only supports IPv4 addresses, and we couldn't see yours."
                if ipv6_only
                else "The reputation services didn't answer properly this time."
            ),
        )

    facts: list[str] = []
    status = Status.GOOD
    if gn_ok and gn is not None:
        facts.append(_greynoise_fact(gn))
        if gn.verdict is Reputation.SUSPICIOUS:
            status = Status.BAD
        elif gn.verdict is Reputation.BUSINESS_OR_VPN:
            status = Status.WARN
    if ab_ok and ab is not None:
        facts.append(_abuse_fact(ab))
        if ab.verdict is Abuse.SUSPICIOUS:
            status = Status.BAD
        elif ab.verdict is Abuse.LOW_CONFIDENCE and status is Status.GOOD:
            status = Status.WARN
        if ab.is_tor:
            facts.append(
                "Your address is a Tor exit node, which collects reports about other people's traffic."
            )

    notes = []
    if abuse_enabled and gn_ok != ab_ok:
        missing, used = ("GreyNoise", "AbuseIPDB") if ab_ok else ("AbuseIPDB", "GreyNoise")
        notes.append(f"{missing} didn't answer, so this is based on {used} alone.")

    if status is Status.BAD:
        notes.append(
            "On a shared connection (apartment, office, mobile data, VPN), it may be someone else on the same address."
        )
        return Card(
            key,
            title,
            Status.BAD,
            "Your address has been seen or reported attacking other computers.",
            facts=facts,
            steps=content.steps(isp_slug, "reputation_suspicious"),
            fix_keys=["reputation_suspicious"],
            note=" ".join(notes),
        )
    if status is Status.WARN:
        business = gn_ok and gn is not None and gn.verdict is Reputation.BUSINESS_OR_VPN
        notes.append(
            "If you're on a VPN or work network, this is about that network, not your home."
            if business
            else "Low-confidence reports are often about whoever had your address before you."
        )
        return Card(
            key,
            title,
            Status.WARN,
            "Your address belongs to a business service or VPN, not a typical home connection."
            if business
            else "Your address has a few low-confidence abuse reports.",
            facts=facts,
            note=" ".join(notes),
        )
    notes.append("This doesn't rule out a quiet infection that isn't attacking anyone.")
    return Card(
        key,
        title,
        Status.GOOD,
        "Your address hasn't been seen or reported attacking other computers.",
        facts=facts,
        note=" ".join(notes),
    )


# --- Shodan history -------------------------------------------------------------


def history_card(r: HistoryResult | None, content: IspContent, isp_slug: str) -> Card:
    title = "Seen from the internet before"
    key = "history"
    if r is None or r.verdict is History.UNKNOWN:
        note = (
            "This history only covers IPv4 addresses, and we couldn't see yours."
            if r is not None and r.reason == "ipv6_unsupported"
            else "Shodan didn't answer properly, so we couldn't check."
        )
        return Card(
            key, title, Status.UNKNOWN, "We couldn't check your address's history.", note=note
        )
    if r.verdict is History.NOTHING_SEEN:
        return Card(
            key,
            title,
            Status.GOOD,
            "Shodan hasn't recorded anything open on your address recently.",
            note="Shodan scans the internet about weekly and publishes what it finds.",
        )
    facts = []
    if r.ports:
        facts.append(
            "Ports Shodan found open recently: " + ", ".join(str(p) for p in r.ports) + "."
        )
    if r.vulns:
        shown = ", ".join(r.vulns[:8])
        more = f" and {len(r.vulns) - 8} more" if len(r.vulns) > 8 else ""
        facts.append(f"Known security flaws matched to software on your address: {shown}{more}.")
    if "compromised" in r.tags:
        facts.insert(0, "Shodan tagged your address as possibly compromised.")
    bad = bool(r.vulns) or "compromised" in r.tags
    keys = ["history_vulns"] if bad else ["open_port"]
    return Card(
        key,
        title,
        Status.BAD if bad else Status.WARN,
        "Shodan, a public search engine for devices, has seen things open on your address."
        + (" Some may have known security flaws." if r.vulns else ""),
        facts=facts,
        steps=_steps(content, isp_slug, keys),
        fix_keys=list(dict.fromkeys(keys)),
        note="Shodan's data is up to a week old and matches flaws by version, so some may be fixed. "
        "Anyone can look this up, including attackers.",
    )


# --- DNS -------------------------------------------------------------------------


class ResolverKind(enum.Enum):
    OWN_ISP = "own_isp"
    PUBLIC = "public"
    OTHER = "other"


@dataclass
class ResolverSighting:
    ip: IPAddress
    asn: AsnInfo | None
    kind: ResolverKind
    public_name: str | None = None


@dataclass
class DnsOutcome:
    token_sent: bool
    resolvers: list[ResolverSighting] = field(default_factory=list)
    error: bool = False


def classify_resolver(
    ip: IPAddress, info: AsnInfo | None, visitor_asns: set[int], classes: AsnClasses
) -> ResolverSighting:
    if info is not None and info.asn in visitor_asns:
        return ResolverSighting(ip, info, ResolverKind.OWN_ISP)
    if info is not None and info.asn in classes.public_resolvers:
        return ResolverSighting(ip, info, ResolverKind.PUBLIC, classes.public_resolvers[info.asn])
    return ResolverSighting(ip, info, ResolverKind.OTHER)


def dns_card(o: DnsOutcome, classes: AsnClasses, content: IspContent, isp_slug: str) -> Card:
    title = "DNS hijacking"
    key = "dns"
    if o.error:
        return Card(key, title, Status.UNKNOWN, "The DNS check failed, so we couldn't test it.")
    if not o.token_sent:
        return Card(
            key,
            title,
            Status.UNKNOWN,
            "We couldn't run the DNS check.",
            note="This check needs JavaScript enabled in your browser.",
        )
    if not o.resolvers:
        return Card(
            key,
            title,
            Status.UNKNOWN,
            "Your browser's test lookup never reached us, so we couldn't check your DNS.",
            note="An ad blocker, privacy extension or strict network filter can cause this.",
        )

    facts = [_resolver_fact(r) for r in o.resolvers]
    others = [r for r in o.resolvers if r.kind is ResolverKind.OTHER]
    if others:
        return Card(
            key,
            title,
            Status.BAD,
            "Your lookups go through a DNS server we don't recognise. Your router's DNS "
            "setting may have been changed.",
            facts=facts,
            steps=content.steps(isp_slug, "dns_suspicious"),
            fix_keys=["dns_suspicious"],
            note="It can be harmless: some workplaces, schools, VPNs and security "
            "products use their own DNS servers.",
        )
    if all(r.asn is not None and r.asn.asn in classes.doh_providers for r in o.resolvers):
        return Card(
            key,
            title,
            Status.QUIET,
            "Your lookups go to a trusted secure-DNS service, so a hijacked router setting "
            "wouldn't affect this browser.",
            facts=facts,
            note="Either your browser's secure DNS or a setting you chose; both are fine. "
            "Other devices at home may still use the router's setting, which we can't test.",
            label="Protected",
        )
    return Card(
        key,
        title,
        Status.GOOD,
        "Your lookups go through your provider or a well-known public DNS service.",
        facts=facts,
    )


def _resolver_fact(r: ResolverSighting) -> str:
    if r.kind is ResolverKind.OWN_ISP:
        who = "your internet provider"
    elif r.kind is ResolverKind.PUBLIC:
        who = r.public_name or "a public DNS service"
    else:
        who = r.asn.name if r.asn else "an unknown network"
    return f"DNS server {r.ip} ({who})."


# --- ISP-specific help -------------------------------------------------------------

# Which router how-to snippets help with each kind of fix.
HOWTO_TOPICS: dict[str, list[str]] = {
    "router_admin_exposed": ["remote_management"],
    "router_service": ["remote_management"],
    "telnet": ["remote_management", "port_forwarding"],
    "upnp_wan": ["upnp"],
    "natpmp": ["upnp"],
    "dns_suspicious": ["dns"],
    "reputation_suspicious": ["devices"],
    **{
        k: ["port_forwarding", "dmz"]
        for k in ("smb", "rdp", "vnc", "adb", "camera_dvr", "printer", "open_port", "history_vulns")
    },
}


def attach_isp_help(cards: list[Card], content: IspContent, isp_slug: str) -> None:
    """Add "On your <ISP> router:" instructions to cards that have fix steps."""
    isp = content.isp(isp_slug)
    if not isp.howto:
        return
    for c in cards:
        topics = dict.fromkeys(t for k in c.fix_keys for t in HOWTO_TOPICS.get(k, []))
        lines = [isp.howto[t] for t in topics if t in isp.howto]
        if lines:
            login = isp.howto.get("login")
            c.isp_help = ([login] if login else []) + lines
            c.isp_name = isp.name
