# asn-abuse

Auto-updated TSV of abuse contacts for every routed ASN.

**[Download abuse-contacts.tsv](https://github.com/tn3w/asn-abuse/releases/latest/download/abuse-contacts.tsv)**

```tsv
asn	abuse_email
13335	abuse@cloudflare.com
15169	network-abuse@google.com
3320	abuse@telekom.de
```

65,521 of 78,411 ASNs. Rebuilt every Monday from the global routing table and
the [Abusix](https://abusix.com/contact-db/) contact zone.

Build it yourself with `python3 main.py`, std library only, about two minutes.
