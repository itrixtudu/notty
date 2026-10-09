# Durdraw Interface Notes (Observed)
Notes By: c0d3x 'ar3s0l gh05t' ru73z - 2026

These notes are based on hands-on use inside the TUI plus a quick skim of
`durdraw.1`; they are not a full manual.

## Quick Keymap (Most Used)
- Menu: `m` | Help: `esc-h` | Quit: `esc-q`
- Save: `esc-s` | Open: `esc-o` | New/Clear: `esc-C`
- Color picker: `tab`/`esc-c` | Next FG color: `esc-up`
- Quick menus: File `esc-m` or `esc-f`, Anim `esc-a`, Mouse Tools `esc-t`
- Open/Save: also `ctrl-o` / `ctrl-w` (legacy shortcuts still active)
- Frames: `esc-j`/`esc-k` prev/next | `esc-n` clone | `esc-N` append | `esc-p` play
- Blocks: `F1`-`F10` (or `esc-1` to `esc-0`) insert common block/dot chars

## Command-line (durdraw.1 skim)
- Usage: `durdraw [options] [filename]` (loads `.dur` or ASCII)
- Play-only: `-p/--play FILE...`, `-x/--times N` to loop, `--startup` or `-w/--wait`
- Colors: `--256color`, `--16color`, `-b/--blackbg`
- Canvas: `-W/--width`, `-H/--height`, `-m/--max`
- UI: `--nomouse`, `--cursor block|underscore|pipe`, `--notheme`, `--theme FILE`
- Encoding/export: `--cp437`, `--export-ansi`, `-u/--undosize`, `-V/--version`

## Layout and status
- The canvas is the main area; there is a right border and a bottom status strip.
- The status strip shows frame info (F:x/y), FPS, delay (D), range (R), playback controls,
  canvas size (e.g., [80x23]), FG/BG palettes, and cursor position (x,y).
- The FG/BG palettes show the current color with an "X" marker.
- The status strip also shows the current draw-character group (e.g., "(1/21)");
  switching character sets updates this count and the F1-F10 preview.

## Drawing basics
- Typing characters draws them directly to the canvas.
- Newlines move the cursor to the next row while continuing to draw.
- Arrow keys move the cursor around the canvas.
- Characters overwrite what is already on the canvas; when recoloring or retouching
  text, retype the full word/line and add trailing spaces to clear leftovers.

## Menu and help
- Press `m` to open the menu (the menu bar shows [Menu] [Anim] [Move] with hotkeys).
- Menu entries and shortcuts observed:
  - New/Clear: `esc-C`
  - Open: `esc-o`
  - Save: `esc-s`
  - Info/Sauce: `esc-i`
  - Color Picker: `tab` (also `esc-c` listed in help)
  - Viewer Mode: `esc-V`
  - Help: `esc-h`
  - Quit: `esc-q`
  - Edit/Settings appear as submenus in the menu list.
- The help screen is scrollable (Up/Down, PgUp/PgDn, Home/End, mouse wheel).
  Press Enter or Esc to exit help.
- Clear prompt: `esc-C` asks "Are you sure you want to clear the canvas? (Y/N)".
- `esc-o` opens a file browser; use arrows to select and Enter to open. The browser
  shows the current folder path and file info at the bottom. Type to search within
  the list; Esc clears the search or exits the picker. If there are unsaved changes,
  it prompts for confirmation before loading another file.

## Animation and frames
- Animation hotkeys from help:
  - Next frame: `esc-k`
  - Previous frame: `esc-j`
  - Play/stop: `esc-p`
  - Clone frame: `esc-n`
  - Append empty frame: `esc-N`
- The status strip shows frame count and playback range (e.g., F:1/2 and R:1-2).
- From help (not tested): `esc-g` goes to a frame, `esc-+`/`esc--` adjust FPS,
  `esc-R` sets the playback/edit range, and edits during playback apply to
  the current range.

## Colors and draw characters
- Color picker: `tab` (or `esc-c`) brings up a foreground/background selector.
- `esc-up` cycles to the next foreground color; `esc-left`/`esc-right` also cycle.
- In the picker: arrow keys or `h/j/k/l` move; Enter/Tab confirms; Esc cancels.
- Function keys (F1-F10) insert common block characters; the help text lists
  light/medium/dark shade, full block, upper/lower half block, left/right half block,
  filled square, and dot.
- `esc-1` to `esc-0` mirror F1-F10.
- The bottom status bar shows the current F1-F10 glyphs for the active set, so you
  can preview what those keys will insert.
- From help (not tested): `esc-down`/`esc-left`/`esc-right` also affect colors, and
  `esc-[` / `esc-]` switch character groups.
  
## Color workflow (fast shading)
- Set color with `tab`/`esc-c`, then draw directly for linework or touch-ups.
- Use `esc-l` to recolor a single character under the cursor.
- Use `esc-L` to replace one color with another across the frame or playback range.
- For blocks: `esc-K` select an area, press Enter, then choose `l` (Color) to recolor
  the whole selection in one pass.
- Quick shading recipe: base color pass, then a lighter highlight on top-facing edges,
  then a darker pass for underside/shadow. Keep highlight strokes sparse.
- Block shading tip: lay in mass with F1-F3 shade blocks, then swap to linework
  chars for edges and details.

## Mouse tools and selection
- Mouse Tools menu (`esc-t`) includes Move, Draw, Paint, Color, Erase, Eyedrop.
- `esc-l` colors the character under the cursor with current FG/BG.
- `esc-L` replaces the color under the cursor across the frame or playback range.
- Selection mode: `esc-K` starts a rectangular selection; move with arrows, Enter to apply.
  Actions: Copy, Cut, Delete, Fill, Color, Flip X/Y, New Brush, Copy to all frames.

## Saving and export
- `esc-s` opens a save prompt.
- Format choices shown: DUR, ANSI, ANSIMATION, ASCII, MIRC, JSON, HTML, PNG, GIF.
- After choosing a format, it prompts for a filename.
- A "*Saved* (Press any key to continue)" message appears on success.
- ANSI export prompts for encoding (CP437 or UTF-8) before the filename.
- Overwrite confirmation appears if the target file already exists; press `y` to
  overwrite or `n` to cancel, and the save will not complete until you answer.
- ASCII export strips color; use ANSI export when you need color.
- If ANSI looks mangled in another viewer, try CP437 export and a CP437-capable viewer.
- CP437 is safest for block/shade characters in ANSI.

## Misc
- Mouse reporting appears to be enabled by default (not tested for drawing).
- From help (not tested): brushes use a selection (Shift+arrows or `esc-K`), `b` to
  create, and `esc-t` -> Paint mode to draw with the brush.
