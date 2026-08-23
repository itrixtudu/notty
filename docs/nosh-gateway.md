# Nosh external gateway activation

`nosh-gateway` is the root-side activation boundary for reviewed network
policy. It does not learn policy and it does not accept an unsigned graph. It
accepts one hash-verified target leaf, its durable review approval, and a
short-lived deployment grant.

The default trust file is `/etc/nosh-gateway/trust.json`. It must be a regular,
root-owned, singly linked mode-0600 file below root-owned directories that are
not group- or world-writable. Its strict schema is
[`config/nosh-gateway/trust.schema.json`](../config/nosh-gateway/trust.schema.json).
The two key arrays must contain distinct Ed25519 public keys. Review keys have
only the `review-approval` role; deployment keys have only the
`gateway-deployment` role.

The trust file binds all host-specific values. Its audience must equal both the
signed review-approval audience and the short-lived deployment-grant audience:

- gateway audience and backend (`guard-nftables` or `gateway-iptables`);
- target identity/topology digest, compiler context digest, and capability
  digest;
- bootstrap active-grant-set digest;
- absolute executable paths, managed configuration paths, and exact dnsmasq
  systemd unit.

Both packet-filter targets require the reviewed target context to declare
`exclusiveFirewallOwnership: true`. The nftables artifact owns the
`inet/nosh_guard` base chains and their policies. The iptables artifact uses
`--noflush`, generation-specific `NG_*` chains, and signed Nosh comment
signatures; it never replaces built-in chains or flushes unrelated tables.

The first active-grant-set digest is an operator-generated SHA-256 value. Each
successful apply derives the next digest from the previous digest, grant
envelope, policy leaf, and nonce. Query the value for the next grant with:

```text
sudo nosh-gateway status
```

Transfer the leaf directory and the two envelope files into a private,
root-owned staging hierarchy. Then use:

```text
sudo nosh-gateway verify \
  --policy /var/lib/nosh-gateway/incoming/policy \
  --approval /var/lib/nosh-gateway/incoming/approval-envelope.dsse.json \
  --grant /var/lib/nosh-gateway/incoming/gateway-grant.dsse.json

sudo nosh-gateway diff \
  --policy /var/lib/nosh-gateway/incoming/policy \
  --approval /var/lib/nosh-gateway/incoming/approval-envelope.dsse.json \
  --grant /var/lib/nosh-gateway/incoming/gateway-grant.dsse.json

sudo nosh-gateway apply --yes \
  --policy /var/lib/nosh-gateway/incoming/policy \
  --approval /var/lib/nosh-gateway/incoming/approval-envelope.dsse.json \
  --grant /var/lib/nosh-gateway/incoming/gateway-grant.dsse.json
```

`diff` is read-only. It validates dnsmasq and packet-filter syntax with the
configured absolute executables, compares desired and installed configuration
hashes, and compares the bounded managed live-state projection. `apply` takes
an exclusive state lock and installs a higher-priority source quarantine before
writing or loading policy. Config files are replaced atomically without a
shell. The quarantine is removed only after the signed nftables ruleset, or the
signed iptables chains/infrastructure plus ipset schemas and static members,
match live state. The state and receipt bind that verified projection digest;
dynamic DNS members are the only intentionally variable values.

`status` recomputes the same backend-specific projection from the live host and
returns a nonzero status when an active ruleset is missing or has drifted. The
same check binds the installed dnsmasq configuration hash and requires the
configured managed DNS service to be active, so variable DNS set members cannot
be populated by an unreviewed resolver configuration. It also discovers Nosh
quarantine rules left by a crash before state persistence.
Failure retains the quarantine and records `quarantine-retained` in
`state.json`; a new grant cannot be applied until an operator investigates.

The iptables backend is intentionally explicit about its limitation: ipset,
iptables, dnsmasq, and conntrack do not share a transaction. The independent
raw-table quarantine is what keeps that sequence fail-closed.
