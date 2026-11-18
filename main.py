"""Write abuse-contacts.tsv, the abuse mailbox of every delegated ASN.

Takes the abuse mailbox from the RIPE database where it has one, then samples the
prefixes of every other delegated ASN, asks Abusix for the abuse contact of every
sample and keeps the mailbox most of them agree on.
"""

import datetime
import gzip
import ipaddress
import random
import re
import socket
import struct
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from threading import local

DELEGATED_URL = (
    "https://ftp.ripe.net/pub/stats/ripencc/nro-stats/latest/nro-delegated-stats")
APNIC_TABLE_URLS = ("https://thyme.apnic.net/current/data-raw-table",
                    "https://thyme.apnic.net/current/ipv6-raw-table")
ROUTEVIEWS_URL = "https://publicdata.caida.org/datasets/routing/{}/{:%Y/%m}/"
ROUTEVIEWS_TABLES = (("routeviews-prefix2as", "routeviews-rv2"),
                     ("routeviews6-prefix2as", "routeviews-rv6"))
RANGE_TABLE_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
RIPE_DUMP_URL = "https://ftp.ripe.net/ripe/dbase/split/ripe.db.{}.gz"
ABUSIX_ZONE = "abuse-contacts.abusix.zone"
ABUSIX_SERVER = "rbldns-geo.abusix.zone"
OUTPUT = "abuse-contacts.tsv"
SAMPLES = 8
THREADS = 128
TIMEOUT = 3

EMAIL = re.compile(r"[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}")
PLACEHOLDER_USERS = {"removed", "hmchanged", "noreply", "email", "na"}
REGISTRY_DOMAINS = {"apnic.net", "ripe.net", "arin.net", "lacnic.net", "afrinic.net"}

SERVERS = sorted({info[4][0] for info in socket.getaddrinfo(
    ABUSIX_SERVER, 53, socket.AF_INET, socket.SOCK_DGRAM)})
LOCAL = local()


def is_placeholder(email: str) -> bool:
    """Whether an address is a redaction, a filler value or a registry desk."""
    user, _, domain = email.partition("@")
    return (user.replace(".", "").replace("-", "").replace("_", "") in PLACEHOLDER_USERS
            or domain in REGISTRY_DOMAINS)


def sample(prefixes: list[tuple[int, str]]) -> list[str]:
    """An ASN's largest blocks, which are the ones it runs itself, and a spread
    over everything else, which is mostly space it has handed to customers."""
    half = SAMPLES // 2
    largest = sorted(prefixes)[:half]
    rest = [prefix for prefix in prefixes if prefix not in largest]
    if len(rest) > half:
        rest = [rest[step * len(rest) // half] for step in range(half)]
    return [address for _, address in largest + rest]


def delegated_asns() -> set[int]:
    """Every ASN a registry has handed out, routed or not."""
    with urllib.request.urlopen(DELEGATED_URL, timeout=60) as response:
        lines = response.read().decode(errors="replace").splitlines()
    asns: set[int] = set()
    for line in lines:
        parts = line.split("|")
        if len(parts) > 6 and parts[2] == "asn" and parts[6] in ("assigned", "allocated"):
            asns.update(range(int(parts[3]), int(parts[3]) + int(parts[4])))
    return asns


def latest_routeviews_file(folder: str, prefix: str) -> str:
    """The newest dump in this month's folder, or last month's early in the month."""
    today = datetime.date.today()
    for day in (today, today.replace(day=1) - datetime.timedelta(days=1)):
        url = ROUTEVIEWS_URL.format(folder, day)
        with urllib.request.urlopen(url, timeout=60) as response:
            listing = response.read().decode(errors="replace")
        names = re.findall(rf"{prefix}-\d{{8}}-\d{{4}}\.pfx2as\.gz", listing)
        if names:
            return url + max(names)
    raise RuntimeError(f"no {prefix} dump found")


def read_table(folder: str, prefix: str) -> list[tuple[int, int, str]]:
    """ASN, prefix length and start address of every prefix in a RouteViews dump,
    counting each origin of a prefix that has several."""
    url = latest_routeviews_file(folder, prefix)
    with urllib.request.urlopen(url, timeout=120) as response:
        table = gzip.decompress(response.read()).decode(errors="replace")
    rows = []
    for line in table.splitlines():
        address, length, origins = line.split("\t")
        rows.extend((int(asn), int(length), address)
                    for asn in re.findall(r"\d+", origins) if asn != "0")
    return rows


def read_apnic_table(url: str) -> list[tuple[int, int, str]]:
    """ASN, prefix length and start address of every prefix in one APNIC table."""
    with urllib.request.urlopen(url, timeout=60) as response:
        table = response.read().decode(errors="replace")
    rows = []
    for line in table.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit() and parts[1] != "0":
            address, _, length = parts[0].partition("/")
            rows.append((int(parts[1]), int(length), address))
    return rows


def read_range_table(url: str) -> list[tuple[int, int, str]]:
    """ASN, prefix length and start address of every routed address range."""
    request = urllib.request.Request(url, headers={"User-Agent": "asn-abuse"})
    with urllib.request.urlopen(request, timeout=120) as response:
        table = gzip.decompress(response.read()).decode(errors="replace")
    rows = []
    for line in table.splitlines():
        first, last, asn = line.split("\t")[:3]
        if asn.isdigit() and asn != "0":
            blocks = ipaddress.summarize_address_range(
                ipaddress.ip_address(first), ipaddress.ip_address(last))
            rows.extend((int(asn), block.prefixlen, str(block.network_address))
                        for block in blocks)
    return rows


def read_dump(name: str, keys: set[str]):
    """The wanted attributes of every object in a RIPE database dump."""
    with urllib.request.urlopen(RIPE_DUMP_URL.format(name), timeout=300) as response:
        text = gzip.decompress(response.read()).decode(errors="replace")
    for block in text.split("\n\n"):
        pairs = [line.split(":", 1) for line in block.splitlines() if ":" in line]
        yield [(key.lower(), value.strip()) for key, value in pairs
               if key.lower() in keys]


def first_value(attributes: list[tuple[str, str]], key: str) -> str | None:
    return next((value for name, value in attributes if name == key and value), None)


def ripe_mailboxes() -> dict[int, str]:
    """The abuse mailbox RIPE lists for an ASN, or for its organisation."""
    roles = {first_value(block, "nic-hdl"): first_value(block, "abuse-mailbox")
             for block in read_dump("role", {"nic-hdl", "abuse-mailbox"})}
    organisations = {}
    for block in read_dump("organisation", {"organisation", "abuse-c"}):
        mailbox = roles.get(first_value(block, "abuse-c"))
        if mailbox:
            organisations[first_value(block, "organisation")] = mailbox
    mailboxes = {}
    for block in read_dump("aut-num", {"aut-num", "org", "abuse-c"}):
        asn = first_value(block, "aut-num")
        mailbox = (roles.get(first_value(block, "abuse-c"))
                   or organisations.get(first_value(block, "org")))
        mailbox = (mailbox or "").lower()
        if asn and EMAIL.fullmatch(mailbox) and not is_placeholder(mailbox):
            mailboxes[int(asn.lower().removeprefix("as"))] = mailbox
    return mailboxes


def query_name(address: str) -> str:
    """The Abusix name for an address, nibble-reversed when it is IPv6."""
    if ":" in address:
        digits = ipaddress.IPv6Address(address).exploded.replace(":", "")
        return ".".join(reversed(digits)) + "." + ABUSIX_ZONE
    return ".".join(reversed(address.split("."))) + "." + ABUSIX_ZONE


def sampled_names() -> dict[int, list[str]]:
    """Query names per ASN, sampled separately for IPv4 and IPv6 because their
    prefix lengths are not comparable."""
    rows = [row for table in ROUTEVIEWS_TABLES for row in read_table(*table)]
    rows += [row for url in APNIC_TABLE_URLS for row in read_apnic_table(url)]
    rows += read_range_table(RANGE_TABLE_URL)
    prefixes: dict[tuple[int, bool], set[tuple[int, str]]] = {}
    for asn, length, address in rows:
        prefixes.setdefault((asn, ":" in address), set()).add((length, address))
    names: dict[int, list[str]] = {}
    for (asn, _), family_prefixes in prefixes.items():
        names.setdefault(asn, []).extend(map(query_name, sample(list(family_prefixes))))
    return names


def encode_query(query_id: int, name: str) -> bytes:
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    return header + labels + b"\x00" + struct.pack(">HH", 16, 1)


def skip_name(packet: bytes, at: int) -> int:
    while at < len(packet):
        length = packet[at]
        if length & 0xC0:
            return at + 2
        at += 1 + length
        if length == 0:
            return at
    return at


def decode_txt(packet: bytes, query_id: int) -> str | None:
    """The TXT records of a reply, or None when the server did not answer."""
    if len(packet) < 12 or struct.unpack_from(">H", packet)[0] != query_id:
        return None
    if packet[3] & 0x0F not in (0, 3):
        return None
    texts = []
    at = skip_name(packet, 12) + 4
    for _ in range(struct.unpack_from(">H", packet, 6)[0]):
        at = skip_name(packet, at)
        kind = struct.unpack_from(">H", packet, at)[0]
        length = struct.unpack_from(">H", packet, at + 8)[0]
        at += 10
        if kind == 16:
            texts.append(packet[at + 1:at + length].decode(errors="replace"))
        at += length
    return " ".join(texts)


def query_txt(name: str) -> str:
    """Ask the Abusix nameservers in turn until one of them answers."""
    if not hasattr(LOCAL, "socket"):
        LOCAL.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        LOCAL.socket.settimeout(TIMEOUT)
    for server in random.sample(SERVERS, len(SERVERS)):
        query_id = random.getrandbits(16)
        try:
            LOCAL.socket.sendto(encode_query(query_id, name), (server, 53))
            reply, _ = LOCAL.socket.recvfrom(1500)
            text = decode_txt(reply, query_id)
        except (OSError, struct.error):
            continue
        if text is not None:
            return text
    return ""


def abusix_votes(names: list[str]) -> Counter[str]:
    """Every mailbox Abusix names for an ASN's sampled prefixes, unfiltered."""
    votes: Counter[str] = Counter()
    for name in names:
        votes.update(EMAIL.findall(query_txt(name).lower()))
    return votes


def best_mailbox(votes: Counter[str]) -> str | None:
    """The mailbox most of an ASN's prefixes agree on, an abuse desk winning ties."""
    real = [(count, box.startswith("abuse"), box)
            for box, count in votes.items() if not is_placeholder(box)]
    return max(real)[2] if real else None


def build() -> None:
    universe = delegated_asns()
    targets = {asn: names for asn, names in sampled_names().items() if asn in universe}
    found = {asn: box for asn, box in ripe_mailboxes().items() if asn in universe}
    remaining = {asn: names for asn, names in targets.items() if asn not in found}
    print(f"{len(universe)} asns, {len(found)} from RIPE, {len(remaining)} for Abusix")
    with ThreadPoolExecutor(THREADS) as pool:
        votes = pool.map(abusix_votes, remaining.values())
        for asn, asn_votes in zip(remaining, votes, strict=True):
            found[asn] = best_mailbox(asn_votes)
    with open(OUTPUT, "w") as out:
        out.write("asn\tabuse_email\n")
        for asn in sorted(found):
            if found[asn]:
                out.write(f"{asn}\t{found[asn]}\n")


if __name__ == "__main__":
    build()
