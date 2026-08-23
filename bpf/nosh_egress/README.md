# nosh-egress

`nosh-egress` is the first-party CO-RE cgroup egress policy backend. Its six
cgroup hooks are the sole allow/deny dataplane. The root-owned loader validates
the target cgroup, loads a strict reviewed policy manifest, pins maps and links
in bpffs, and emits identity-bound readiness plus final loss counters.

The evidence schema, map ABI, and program ABI are independently versioned at
`2`. Missing or
incompatible configuration fails closed. `SIGTERM` ends evidence collection
but does not detach policy; only `nosh-egress-loader detach --pin-root ...`
removes the exact pinned instance.

## Policy manifest v2

The loader consumes a deterministic tab-separated projection of the reviewed
`NoshEbpfEgressPolicy` JSON. It is not the signed review artifact itself.

```text
NOSH_EGRESS_POLICY_V2
resolver\t1.1.1.1
resolver\t8.8.8.8
containment\t10.240.0.1/32
containment\tfd42:6e6f:7368::1/128
cidr\t203.0.113.0/24\ttcp\t443\t1
cidr\t2001:db8::/32\ticmpv6\t0\t4\t128\tany
domain\texample.com\ttcp\t443\t2
domain\t*.example.net\tany\t0\t3
```

Every manifest must contain at least one exact `containment` endpoint. The
runtime supplies its actual platform-control endpoints (normally the selected
Docker bridge gateways); `/32` and `/128` are the only accepted prefixes.
The loader derives a stable `platform-endpoint:<address>` ID, hashes the
canonical containment set into the pinned identity, and emits the ID on every
containment denial. An optional explicit form,
`containment\t<stable-id>\t<exact-prefix>`, is also accepted. Broad RFC1918,
link-local, multicast, CGNAT, DNS, and DoT ranges are not hardcoded
containment invariants. `containmentDigest` is SHA-256 over each manifest-order
canonical record `<id>\t<canonical-address>/<32-or-128>\n`.

CIDRs must be canonical. Protocol is `any`, `tcp`, `udp`, `icmp`, or `icmpv6`;
ICMP rules require port zero. Optional trailing ICMP type and code selectors
follow the stable rule ID and each is `any` or an integer from 0 through 255.
Domain rules support exact names and `*.` suffix wildcards that match exactly
one label below the suffix; they may use only `any`, `tcp`, or `udp`. One DNS
question may match at most eight combined exact and wildcard transport rules;
both the compiler and manifest renderer reject a larger union before attach.

IPv4/IPv6 TCP, UDP, ICMP, and ICMPv6 are the fully parsed packet protocols.
Known-destination fragments, unsupported protocols, malformed transport
headers, jumbograms, AH gaps, and overlong non-routing extension chains are
coverage evidence: LEARN allows and records them, AUDIT allows with a
`would-deny` verdict, and ENFORCE denies. IPv4 options and IPv6 routing headers
can hide the ultimate destination and therefore remain backend denials in all
modes, as do packets whose network address cannot be recovered. Narrow,
intrinsic ICMPv6
exceptions admit only structurally valid Neighbor Solicitation/Advertisement
needed by the Docker bridge and inbound errors that quote a packet sourced by
the runner; these events are excluded from learned application policy.

UDP and single-segment, single-message TCP DNS A/AAAA correlation is bounded;
the complete bounded answer section is staged and validated before grants are
changed. Every positive-TTL validated answer for the observed question emits
a distinct `dns-answer` record retaining the question name, resolver, record
type, and answer address. TTL-zero and error-response answers do not grant;
grants are capped at 300 seconds, and
one-hop CNAME grants use the shorter CNAME/address TTL. Segmented or coalesced
TCP DNS follows the same mode-aware coverage behavior, so this implementation
does not advertise the full `tcpDns` capability yet. Unmatched queries are
still transaction-tracked in LEARN and AUDIT so their answers remain visible.
DNS-mediated grants are L3/L4 authorizations, not exact TLS hostname controls.
Direct DNS and DoT destinations are ordinary reviewable policy, not hidden
containment denies.

Decision records carry stable `decisionClass`, `reason`,
`enforcementApplied`, and `containmentId` fields. LEARN never applies candidate
policy: known ordinary destinations are observed and allowed. AUDIT reports
the reviewed policy outcome while allowing traffic. ENFORCE applies reviewed
default-deny policy. Exact platform containment and backend identity or hidden
destination failures remain enforced in every mode.
The only packet-level exception for a contained bridge gateway is strictly
validated IPv6 Neighbor Discovery or quoted ICMPv6 error delivery required to
reach other destinations; application traffic to the gateway remains denied.
