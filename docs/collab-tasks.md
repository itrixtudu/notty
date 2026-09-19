# Collab tasks and terminal controls

Choose a **Conversation task** before launching. **New task** starts fresh Codex
conversations; launching an existing task resumes the saved conversation for each
role. Model and Think changes do not change that conversation. Duplicate role
identities and hosted Codex versus Codex/Ollama have separate entries. Other
agent harnesses keep their existing behavior.

The ignored `.notty/collab-resume.json` file is a private project-local index,
not a transcript. Keep the mounted Codex home and its session history: the index
alone cannot restore a conversation. Only new task launches are tracked; older
resume-picker entries are not imported. Capture retries for about one minute and
shows capturing, saved, or failed. Missing or unverifiable history blocks launch
instead of silently creating a new conversation. Stop and launch the same task
again to retry discovery after a capture timeout.

After three successful manual resumes, an opt-in checkbox enables automatic
resume when the main Collab page opens. It never runs from the chats pop-out.
Uncheck it to disable it. New tasks turn automatic resume off. Automatic resume
reuses saved launch choices, but does not repeat old kickoff instructions.

The index is written atomically with owner-only file permissions. A newly created
`.notty` directory is owner-only. Existing `.notty` configuration directories may
remain readable, but must be owned by the launching user and not writable by
other users. Symlinks, hard-linked index files, malformed state, and concurrent
writes fail closed. A crash-left `collab-resume.json.lock` requires inspection
before removal; do not remove a lock while the Collab daemon is writing.

## Pane controls

- **Transcript** sends Ctrl+T to that Codex pane. Browser Ctrl+T remains New Tab.
  The button toggles Codex's transcript; it does not claim to know its current state.
- **Select text / Copy** opens a read-only snapshot of the displayed buffer and
  available scrollback. Expand Codex's transcript first to include hidden details.
  Snapshots retain at most 10,000 lines / 1 MiB and indicate truncation.
- Select text normally, then use **Copy selection** or **Copy all**. Clipboard
  failure leaves selectable text available for the browser's Copy command.
- Escape leaves selection first; another Escape restores a maximized pane.

Startup guidance now registers the role, checks pending assignments once, and
waits quietly. QA role guidance is not an implicit request to explore the repo.
This is an orchestration rule, not a new execution sandbox. An unavailable MCP
service should produce one failure, not repeated source investigation. The
one-off `scripts/call-tool.js` helper requires a Collab identity (`--agent NAME`,
or matching `COLLAB_AGENT_ID` and `COLLAB_MCP_URL`) and registers it on each
connection before invoking the requested tool.

Codex's message that Spark ignores `priority` concerns its service tier, not the
QA role or task priority. It is separate from idle startup behavior; this change
does not rewrite global Codex configuration.

## Browser acceptance checks

After rebuilding/recreating the app container, verify Transcript, selection,
copy over HTTP and HTTPS, Escape ordering, and maximize/restore in both windows.
Launch a new named task with no kickoff instructions and check that every role
registers and becomes quiet. Send one assignment, stop, and relaunch that task:
the recorded role UUIDs should stay the same. Then create a second task and
confirm it gets fresh conversations. Live model and browser acceptance remain
separate from deterministic tests.
