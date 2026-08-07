# asn-abuse

Auto-updated TSV of abuse contacts for every routed ASN.

**[Download abuse-contacts.tsv](https://github.com/tn3w/asn-abuse/releases/latest/download/abuse-contacts.tsv)**

```tsv
asn	abuse_email
13335	abuse@cloudflare.com
15169	network-abuse@google.com
3320	abuse@telekom.de
```

71,824 of 85,652 ASNs, IPv4 and IPv6. Rebuilt every Monday from the global
routing table and the [Abusix](https://abusix.com/contact-db/) contact zone.

Build it yourself with `python3 main.py`, std library only, about two minutes.
