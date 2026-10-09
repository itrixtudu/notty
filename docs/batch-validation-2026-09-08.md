# One-rebuild UI validation

Rebuild once with `./scripts/build-nosh.sh`, then recreate/start the project container
using your normal Nosh workflow. Reload the browser to load the new UI assets.
The rebuild/restart/resume convenience wrapper remains deferred.

Automated validation in the development container: production build passed
with four existing authState tracing warnings; serialized Node suite passed
856 tests with one Docker-dependent skip. The shell profile security test
passed too. An initial suite run concurrent with the build hit three timing
failures; all passed when rerun serialized, without changing their assertions.

## Copy view and Collab layout

- Compare the live terminal and Select text view: font, size and line spacing
  should match. Check Unicode, long lines and scrolled output.
- Copy a selection and Copy all on HTTP; repeat on HTTPS if available. Paste
  into a scratch editor, not a live shell. Denied clipboard permission should
  leave manual copying available without sending terminal input.
- Resize dividers by dragging and keyboard; maximize/restore each pane and
  check the chats pop-out. Escape should close selection before restoring a
  maximized pane. Resizing should not restart the agent or jiggle the divider.

## OTP manager

- Create two short-lived test tokens. A blank TTL uses the configured default,
  not no-expiry; check no-expiry display only if a legacy no-expiry record is
  already present. Expand each
  History row using mouse and keyboard; verify Time, Event and Details columns.
- Leave one short token unused; consume the other using your usual test
  terminal workflow. Unused expiry and consumed input-access deadline must be
  different history events. Consumption is not proof of successful spawning.
- Verify countdowns reach zero without becoming negative. Check terminal input
  is gated after expiry; terminal renewal may use a different token and is not
  reconstructed by this metadata-only history.
- Switch tabs and return: status should reconcile. Refresh explicitly reloads
  server state and dismisses a newly revealed code; it does not renew a token.
- Close and reopen the dialog: plaintext codes and unfinished form values
  should be gone. Network tools should show no periodic OTP-manager requests
  while closed (other UI consumers may still request their own status).
- With network throttling, close/reopen while loading or minting. Old responses
  must not restore plaintext or overwrite a newer dashboard. A minted token
  whose response was dismissed may still exist server-side; inspect metadata
  before creating another.

## Existing Collab resume acceptance

- Check transcript toggle, quiet idle QA and explicit assignment wakeup.
- Resume an existing named task after container recreation; verify role UUIDs
  are preserved. Check multi-tab auto-resume does not create duplicate launches.
  See [Collab tasks](collab-tasks.md) for persistence prerequisites.

Full archived OTP terminal/command history, capability rotation, Interrupt/Halt,
network isolation and shared-user permissions remain separate open work.
The host release audit still requires Docker and a committed source snapshot;
this batch does not create a release tag or run privileged live security tests.
