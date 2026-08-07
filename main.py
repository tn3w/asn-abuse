"""Write abuse-contacts.tsv, the abuse mailbox of every routed autonomous system.

Samples the prefixes each ASN announces, asks Abusix for the abuse contact of
every sample, and keeps the mailbox most of them agree on.
"""

import random
import re
import socket
import struct
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from threading import local

PREFIX_TABLE_URL = "https://thyme.apnic.net/current/data-raw-table"
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


def sampled_prefixes() -> dict[int, list[str]]:
    """Sampled prefix start addresses per ASN, from the global routing table."""
    with urllib.request.urlopen(PREFIX_TABLE_URL, timeout=60) as response:
        table = response.read().decode(errors="replace")
    per_asn: dict[int, list[tuple[int, str]]] = {}
    for line in table.splitlines():
        prefix, _, asn = line.partition("\t")
        if asn.isdigit() and asn != "0":
            address, _, length = prefix.partition("/")
            per_asn.setdefault(int(asn), []).append((int(length), address))
    return {asn: sample(prefixes) for asn, prefixes in per_asn.items()}


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


def abusix_votes(addresses: list[str]) -> Counter[str]:
    """Every mailbox Abusix names for an ASN's sampled prefixes, unfiltered."""
    votes: Counter[str] = Counter()
    for address in addresses:
        name = ".".join(reversed(address.split("."))) + "." + ABUSIX_ZONE
        votes.update(EMAIL.findall(query_txt(name).lower()))
    return votes


def best_mailbox(votes: Counter[str]) -> str | None:
    """The mailbox most of an ASN's prefixes agree on, an abuse desk winning ties."""
    real = [(count, box.startswith("abuse"), box)
            for box, count in votes.items() if not is_placeholder(box)]
    return max(real)[2] if real else None


def build() -> None:
    targets = sampled_prefixes()
    with ThreadPoolExecutor(THREADS) as pool:
        found = dict(zip(targets, pool.map(abusix_votes, targets.values()), strict=True))
    with open(OUTPUT, "w") as out:
        out.write("asn\tabuse_email\n")
        for asn in sorted(found):
            mailbox = best_mailbox(found[asn])
            if mailbox:
                out.write(f"{asn}\t{mailbox}\n")


if __name__ == "__main__":
    build()
