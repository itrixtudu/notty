# Klock Fractal Lock Screen

ANSI fractal lock screen with banners, fire palette, and optional splash art. Defaults to lockscreen mode with a Julia fractal backdrop and an auto-selected fallback unlock code.

## Build

```sh
gcc main.c -lm -o klock
```

## Usage

```sh
./klock [options] [splash.ans]
```

Key options:
- `--lockscreen` (default) or `--no-lockscreen`
- Fractals: `--mandelbrot`, `--julia`, `--fire`, `--acidwarp`
- Palettes: `--palette rainbow|fire|gray|plasma|neon`
- Geometry: `--geo polar|twirl|sine|fold|feedback`
- Glyphs: `--glyph-set ascii|blocks|braille|ogham`, `--glyph-map " .:-=+*#%@"`
- Banner: `--banner "TEXT"`, `--banner-mode overlay|mask|cutout`, `--banner-top|--banner-center|--banner-bottom`
- Fire layout: `--fire-bottom`, `--fire-hybrid`
- Sizing: `--width N`, `--height N`, `--zoom Z`, `--speed S`
- Splash art: `--splash file.ans`
- Timeout: `--timeout N`
- Help: `--help`

## Unlock Codes

- If `UNLOCK_CODE` is set, only that value unlocks.
- If unset, one of `meow`, `m3ow`, `me0w`, `m30w` is chosen at random for the session.
- Wrong codes trigger a small ANSI kitty face. Control keys (Ctrl+C/Z/D) and signals are ignored; use an external `kill -9` to terminate.

## Notes

- Default mode is lockscreen with Julia fractal and rainbow palette.
- `--acidwarp` enables color rotation and defaults geometry to twirl unless overridden.
- Use `--no-lockscreen` to run the art loop and exit with `q`/`ESC`.***
