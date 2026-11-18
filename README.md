# asn-abuse

Auto-updated TSV of abuse contacts for every routed ASN.

For full IP lookups (location, ASN, operator, abuse reputation) see
[iplore](https://github.com/tn3w/iplore).

**[Download abuse-contacts.tsv](https://github.com/tn3w/asn-abuse/releases/latest/download/abuse-contacts.tsv)**

```tsv
asn	abuse_email
13335	abuse@cloudflare.com
15169	network-abuse@google.com
3320	abuse@telekom.de
```

Over 70,000 of ~87,000 routed ASNs, IPv4 and IPv6. Rebuilt every Monday from
the global routing table, the RIPE database (about a third of all ASNs) and the
[Abusix](https://abusix.com/contact-db/) contact zone for the rest.

Build it yourself with `python3 main.py`, std library only, about two minutes.
