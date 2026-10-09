# Bubble Bai for the Codex terminal pet

This package installs the small animated pet in the lower-right corner of Codex's terminal UI.

**Bubble Bai has only been tested in Kitty terminal. Support in other terminals is unverified.**

**Disclaimer:** Using Codex with Kitty, pets, and voice is an escape hatch
outside the coverage of the eBPF run profile. Do not treat host terminal, pet,
or voice integrations as contained or fully monitored by that profile.

From the Notty checkout, run `sh bubble-bai-codex/install.sh`, or accept the
optional installation offered by `nosh init --step setup` after launcher setup.
The wizard defaults to No. For a standalone archive, use:

```sh
tar -xzf bubble-bai-codex-pet.tgz
cd bubble-bai-codex
sh install.sh
```

The installer creates `${CODEX_HOME:-$HOME/.codex}/pets/bubble-bai/` with `pet.json` and `spritesheet.png`. It works as the current user, requires no `sudo`, and refuses to overwrite a different existing pet. Re-running the same installer is safe.

Open `/pets` in Codex and select **Bubble Bai**. Restart Codex if the picker was already open. The nine-row atlas is `1536x1872`, with transparent `192x208` cells. `validation.json` contains the sprite-sheet check result.

This is for Codex's built-in terminal pet renderer. It does not need `kitten icat`, a Kitty socket, or a shell process to keep the animation alive.
