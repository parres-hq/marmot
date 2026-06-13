# Host safety

Status: draft for internal review.

Several Marmot surfaces validate a URL whose host a client may reach over the network — encrypted-media `blossom-v1`
locators, encrypted-media blob endpoints, and the group avatar URL. A fetchable URL pointing at a private, internal, or
otherwise non-globally-reachable address is a server-side request forgery (SSRF) vector: the harm is the request
itself, which content authentication cannot neutralize. Some of these validations are also commit-validity rules that
every member re-runs, so they MUST be deterministic and identical across implementations or members fork.

This document pins one canonical **unsafe-host set** so every surface rejects the same hosts. Each surface states its own
`MUST`/`SHOULD` and any scheme or loopback exception; this document defines only the set they share.

## Unsafe hosts

A host is unsafe if it is any of:

- the name `localhost`, or any name whose final label is `localhost` (for example `foo.localhost`);
- an IPv4 literal inside any range in "Unsafe IPv4 ranges" below;
- an IPv6 literal inside any range in "Unsafe IPv6 ranges" below;
- an IPv4-mapped IPv6 address (`::ffff:0:0/96`) whose embedded IPv4 address is unsafe;
- any IPv6 address outside global unicast `2000::/3` that is not otherwise listed below. Only `2000::/3` carries
  globally-routable IPv6 today; addresses outside it (and not covered by another rule) are unallocated or special-use,
  so they are unsafe. The 6to4 (`2002::/16`) and Teredo (`2001:0000::/32`) transition prefixes are inside `2000::/3`
  but are rejected entirely (they tunnel to an embedded IPv4 endpoint), as listed below.

A surface that resolves a hostname to IP addresses before connecting MUST apply these checks to every resolved address,
not only to literals in the URL.

### Unsafe IPv4 ranges

These are the not-globally-reachable entries of the IANA IPv4 Special-Purpose Address Registry, plus multicast and
reserved space:

| Range | Name |
| --- | --- |
| `0.0.0.0/8` | this host / unspecified |
| `10.0.0.0/8` | private |
| `100.64.0.0/10` | shared address space (CGNAT) |
| `127.0.0.0/8` | loopback |
| `169.254.0.0/16` | link-local |
| `172.16.0.0/12` | private |
| `192.0.0.0/24` | IETF protocol assignments |
| `192.0.2.0/24` | documentation (TEST-NET-1) |
| `192.88.99.0/24` | 6to4 relay anycast (deprecated) |
| `192.168.0.0/16` | private |
| `198.18.0.0/15` | benchmarking |
| `198.51.100.0/24` | documentation (TEST-NET-2) |
| `203.0.113.0/24` | documentation (TEST-NET-3) |
| `224.0.0.0/4` | multicast |
| `240.0.0.0/4` | reserved (includes the `255.255.255.255` broadcast address) |

### Unsafe IPv6 ranges

These are the not-globally-reachable entries of the IANA IPv6 Special-Purpose Address Registry, plus multicast:

| Range | Name |
| --- | --- |
| `::1/128` | loopback |
| `::/128` | unspecified |
| `::ffff:0:0/96` | IPv4-mapped (check the embedded IPv4 address) |
| `2001:0000::/32` | Teredo (rejected entirely) |
| `2001:db8::/32` | documentation |
| `2002::/16` | 6to4 (rejected entirely) |
| `3fff::/20` | documentation ([RFC 9637](https://www.rfc-editor.org/rfc/rfc9637)) |
| `fc00::/7` | unique local (ULA) |
| `fe80::/10` | link-local unicast |
| `ff00::/8` | multicast |
| outside `2000::/3` | not global unicast (unallocated / special-use) |

## Use

A surface that validates a fetchable host against this set MUST reject (or invalidate, per that surface's disposition) a
host that matches any rule above. Surfaces that resolve hostnames MUST also reject when any resolved address matches.
The unsafe-host set is fixed protocol data, not local configuration, so a commit-validity check that uses it stays
identical for every member.

A surface MAY define a narrow, explicit dev/test exception for loopback (for example a local Blossom server), but only
through explicit configuration and never as a default. Such an exception is local fetch policy; it does not change the
unsafe-host set or commit-validity for other members.
