# nosh-dns evidence ABI

`evidence-v1.schema.json` is the versioned userspace ABI for the dedicated,
observe-only DNS collector. The collector handles complete UDP messages and
reassembled length-prefixed TCP messages and emits explicit final loss
counters. It is separate from `nosh_l4`: that gadget remains metadata-only and
does not inspect payloads. Consumers correlate DNS answers to L4 attempts by
run identity, destination address, TTL, and a bounded time window; an address
match alone is never an authorization.
