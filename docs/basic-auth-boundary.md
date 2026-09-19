# Basic authentication boundary

Nosh generates or accepts the human's Basic password on the host and derives
a randomly salted scrypt verifier using Python 3's standard library. Python 3
with scrypt support is required on the launcher host. The password is sent to
the helper over stdin, never as a helper argument. The application container
receives `NOTTY_BASIC_AUTH_VERIFIER`, not `NOTTY_BASIC_AUTH_PASSWORD`.
Nosh still displays the password to the operator; dry runs redact it.

The verifier format is `scrypt-v1:<16-byte salt hex>:<32-byte digest hex>`.
Parameters are fixed at N=16384, r=8, p=1. The verifier string cannot be used
as the Basic password. Operator-selected passwords should resist guessing:
anyone who obtains a verifier can attempt offline password guesses.

HTTP and WebSocket authentication share the same verifier validation. The
child environment filter strips all `NOTTY_BASIC_AUTH_*` settings from agents.
Direct server launches retain legacy plaintext-password configuration for
compatibility; those launches do not provide the Nosh verifier storage boundary.
Recreate existing containers to remove their previous plaintext environment.

This change protects stored container configuration, not server memory. Basic
requests necessarily deliver the submitted password to the authentication
process. Same-UID agents, ptrace-capable processes, container root, and host
Docker operators are not isolated from that process by this change. Separate
service identities or an isolated authentication gateway are still required
to protect credentials in flight from such processes. Do not claim full agent
credential isolation until that additional boundary is implemented and tested.

Keep browser publication on loopback by default. Non-loopback browser access
requires TLS at an appropriate authentication gateway, because Basic headers
carry the reusable password on each request.
