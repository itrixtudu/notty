// ─────────────────────────────────────────────────────────────
//  KLOCK FRACTAL ENGINE — PART 1: CORE FRAMEWORK + CLI PARSER
//  (C) 2025 Kross — AcidWarp++ Engine
// ─────────────────────────────────────────────────────────────

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>
#include <math.h>
#include <ctype.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <stdint.h>

// forward declarations for later parts
void render_frame();
void render_banner_overlay();
void run_lockscreen();
static void show_help(const char *self);

// ─────────────────────────────────────────────────────────────
//   UTF-8 / Unicode helpers
// ─────────────────────────────────────────────────────────────

// Returns the number of bytes in the UTF-8 codepoint starting at *s
static int utf8_len(const unsigned char *s) {
    if (*s < 0x80) return 1;
    if ((*s >> 5) == 0x6) return 2;
    if ((*s >> 4) == 0xE) return 3;
    if ((*s >> 3) == 0x1E) return 4;
    return 1; // fallback
}

// count characters (grapheme count)
static int utf8_strlen(const char *s) {
    int count = 0;
    while (*s) {
        s += utf8_len((unsigned char*)s);
        count++;
    }
    return count;
}

// copy a single UTF-8 grapheme into buf
static int utf8_copy_char(char *buf, const char *src) {
    int n = utf8_len((unsigned char*)src);
    for (int i = 0; i < n; i++)
        buf[i] = src[i];
    buf[n] = 0;
    return n;
}

// decode a single UTF-8 codepoint; returns byte length consumed
static int utf8_decode(const char *s, uint32_t *out) {
    const unsigned char *p = (const unsigned char*)s;
    int len = utf8_len(p);
    uint32_t cp = 0;
    switch (len) {
        case 1: cp = p[0]; break;
        case 2: cp = ((p[0] & 0x1F) << 6) | (p[1] & 0x3F); break;
        case 3: cp = ((p[0] & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F); break;
        case 4: cp = ((p[0] & 0x07) << 18) | ((p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F); break;
        default: cp = p[0]; break;
    }
    if (out) *out = cp;
    return len;
}

static int is_emoji_codepoint(uint32_t cp) {
    if (cp >= 0x1F300 && cp <= 0x1FAFF) return 1; // Misc Symbols and Pictographs → Supplemental Symbols and Pictographs
    if (cp >= 0x2600 && cp <= 0x27BF) return 1;   // Misc symbols
    if (cp >= 0x1F900 && cp <= 0x1F9FF) return 1; // Supplemental Symbols and Pictographs
    if (cp == 0x2728 || cp == 0x2764 || cp == 0x1F525) return 1; // sparkle, heart, fire
    return 0;
}

#define MAX_EMOJI_MAP 16

typedef struct {
    uint32_t cp;
    char replacement[8];
} EmojiMapEntry;

static EmojiMapEntry emoji_map[MAX_EMOJI_MAP];
static int emoji_map_count;

static void add_emoji_map(uint32_t cp, const char *replacement) {
    for (int i = 0; i < emoji_map_count; i++) {
        if (emoji_map[i].cp == cp) {
            strncpy(emoji_map[i].replacement, replacement, sizeof(emoji_map[i].replacement) - 1);
            emoji_map[i].replacement[sizeof(emoji_map[i].replacement) - 1] = 0;
            return;
        }
    }
    if (emoji_map_count >= MAX_EMOJI_MAP) return;
    emoji_map[emoji_map_count].cp = cp;
    strncpy(emoji_map[emoji_map_count].replacement, replacement, sizeof(emoji_map[emoji_map_count].replacement) - 1);
    emoji_map[emoji_map_count].replacement[sizeof(emoji_map[emoji_map_count].replacement) - 1] = 0;
    emoji_map_count++;
}

static const char* emoji_lookup(uint32_t cp) {
    for (int i = 0; i < emoji_map_count; i++) {
        if (emoji_map[i].cp == cp) return emoji_map[i].replacement;
    }
    return "?";
}

static void reset_emoji_map(void) {
    emoji_map_count = 0;
    add_emoji_map(0x1F525, "@");   // 🔥
    add_emoji_map(0x1F33F, "/");   // 🌿
    add_emoji_map(0x1F480, "[]");  // 💀
    add_emoji_map(0x1F300, "~");   // 🌀
    add_emoji_map(0x2B50, "*");    // ⭐
    add_emoji_map(0x1FA90, "()");  // 🪐
}

static int parse_emoji_map_arg(const char *arg) {
    const char *eq = strchr(arg, '=');
    if (!eq || eq == arg || !*(eq + 1)) return 0;
    uint32_t cp = 0;
    utf8_decode(arg, &cp);
    add_emoji_map(cp, eq + 1);
    return 1;
}

// ─────────────────────────────────────────────────────────────
//   Terminal control
// ─────────────────────────────────────────────────────────────

static struct termios old_tio;
static int alt_screen_enabled;
static int effects_initialized;

static void restore_tio() {
    tcsetattr(STDIN_FILENO, TCSANOW, &old_tio);
}

static void exit_alt_screen(void) {
    if (!alt_screen_enabled) return;
    printf("\033[?1049l");
    fflush(stdout);
    alt_screen_enabled = 0;
}

static void enter_alt_screen(void) {
    if (alt_screen_enabled) return;
    printf("\033[?1049h");
    fflush(stdout);
    alt_screen_enabled = 1;
}

static void raw_mode() {
    struct termios new_tio;
    tcgetattr(STDIN_FILENO, &old_tio);
    atexit(exit_alt_screen);
    atexit(restore_tio);

    new_tio = old_tio;
    new_tio.c_lflag &= ~(ICANON | ECHO | ISIG);
    new_tio.c_cc[VMIN] = 0;
    new_tio.c_cc[VTIME] = 0;

    tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);
}

// harden against ctrl+c / ctrl+z / hangups; requires SIGKILL to terminate
static void install_signal_guards() {
    signal(SIGINT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
}

// get terminal size
static void get_terminal_size(int *w, int *h) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        *w = ws.ws_col;
        // reduce by two rows to avoid scrollback jitter at the bottom edge
        *h = ws.ws_row > 2 ? ws.ws_row - 2 : (ws.ws_row > 1 ? ws.ws_row - 1 : ws.ws_row);
    } else {
        *w = 120;
        *h = 40;
    }
}

// ─────────────────────────────────────────────────────────────
//   CONFIG STRUCT — all user-selected options live here
// ─────────────────────────────────────────────────────────────

typedef struct {
    int use_mandelbrot;
    int use_julia;
    int use_fire;
    int use_acidwarp;

    int palette_mode;      // 0=rainbow 1=fire 2=gray 3=plasma 4=neon
    int geo_mode;          // 0=none 1=polar 2=twirl 3=sine 4=fold 5=feedback

    int drift;
    int rotate_colors;
    int warp;

    int fire_layout;       // 0=full 1=bottom 2=hybrid

    int width;
    int height;
    double zoom;
    double speed;

    int glyph_mode;        // ascii / blocks / braille / ogham / emoji
    char glyph_map[128];
    char glyph_expr[256];

    char banner[512];
    int banner_mode;       // mask / overlay / cutout
    int banner_pos;        // top / center / bottom

    int ogham_rain;
    int sigil_curtains;

    int feedback_simple;   // optional classic scale pulse

    int prompt_on_bottom;
    int dark;
    int dim;
    int user_palette;

    int lockscreen;        // lockscreen mode flag
    int timeout;
    char splash_path[256];
} EngineConfig;

static EngineConfig cfg;
static int show_help_flag;
static const char *fallback_codes[] = {"meow", "m3ow", "me0w", "m30w"};
static const int fallback_codes_count = 4;
static const char *selected_fallback_code;
static char glyph_expr_table[64][16];
static int glyph_expr_count;

// ─────────────────────────────────────────────────────────────
//   Default configuration
// ─────────────────────────────────────────────────────────────

static void init_config() {
    memset(&cfg, 0, sizeof(cfg));

    cfg.zoom = 0.015;
    cfg.speed = 0.04;
    cfg.drift = 1;

    cfg.palette_mode = 0;     // rainbow
    cfg.geo_mode = 0;         // none
    cfg.glyph_mode = 0;       // ascii
    cfg.user_palette = 0;

    strcpy(cfg.glyph_map, " .:-=+*#%@");

    cfg.fire_layout = 0;      // full
    cfg.banner_mode = 1;      // overlay
    cfg.banner_pos = 1;       // center

    cfg.ogham_rain = 0;
    cfg.sigil_curtains = 0;
    cfg.feedback_simple = 0;

    cfg.prompt_on_bottom = 0;
    cfg.dark = 0;
    cfg.dim = 0;

    cfg.timeout = 12;
    cfg.splash_path[0] = '\0';
    cfg.lockscreen = 1;       // default to lockscreen

    glyph_expr_count = 0;
    reset_emoji_map();
    effects_initialized = 0;
}

// ─────────────────────────────────────────────────────────────
//   CLI parser
// ─────────────────────────────────────────────────────────────

static void parse_args(int argc, char **argv) {

    for (int i = 1; i < argc; i++) {

        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            show_help_flag = 1;
            continue;
        }

        // fractal modes
        if (!strcmp(argv[i], "--mandelbrot")) { cfg.use_mandelbrot = 1; continue; }
        if (!strcmp(argv[i], "--julia"))       { cfg.use_julia = 1; continue; }
        if (!strcmp(argv[i], "--fire"))        { cfg.use_fire = 1; if (!cfg.user_palette) cfg.palette_mode = 1; continue; }
        if (!strcmp(argv[i], "--acidwarp"))    { cfg.use_acidwarp = 1; continue; }

        // palettes
        if (!strcmp(argv[i], "--palette")) {
            if (i+1 < argc) {
                i++;
                if (!strcmp(argv[i], "rainbow")) cfg.palette_mode = 0;
                else if (!strcmp(argv[i], "fire")) cfg.palette_mode = 1;
                else if (!strcmp(argv[i], "gray") || !strcmp(argv[i], "grayscale")) cfg.palette_mode = 2;
                else if (!strcmp(argv[i], "plasma")) cfg.palette_mode = 3;
                else if (!strcmp(argv[i], "neon")) cfg.palette_mode = 4;
                cfg.user_palette = 1;
            }
            continue;
        }

        // geometry
        if (!strcmp(argv[i], "--geo")) {
            if (i+1 < argc) {
                i++;
                if (!strcmp(argv[i], "polar")) cfg.geo_mode = 1;
                else if (!strcmp(argv[i], "twirl")) cfg.geo_mode = 2;
                else if (!strcmp(argv[i], "sine")) cfg.geo_mode = 3;
                else if (!strcmp(argv[i], "fold")) cfg.geo_mode = 4;
                else if (!strcmp(argv[i], "feedback")) cfg.geo_mode = 5;
            }
            continue;
        }

        // animation flags
        if (!strcmp(argv[i], "--drift"))      { cfg.drift = 1; continue; }
        if (!strcmp(argv[i], "--no-drift"))   { cfg.drift = 0; continue; }
        if (!strcmp(argv[i], "--rotate"))     { cfg.rotate_colors = 1; continue; }
        if (!strcmp(argv[i], "--warp"))       { cfg.warp = 1; continue; }
        if (!strcmp(argv[i], "--fire-full"))   { cfg.use_fire = 1; cfg.fire_layout = 0; continue; }
        if (!strcmp(argv[i], "--fire-bottom")) { cfg.use_fire = 1; cfg.fire_layout = 1; continue; }
        if (!strcmp(argv[i], "--fire-hybrid")) { cfg.use_fire = 1; cfg.fire_layout = 2; continue; }
        if (!strcmp(argv[i], "--ogham-rain")) { cfg.ogham_rain = 1; continue; }
        if (!strcmp(argv[i], "--sigil-curtains")) { cfg.sigil_curtains = 1; continue; }
        if (!strcmp(argv[i], "--feedback-classic")) { cfg.feedback_simple = 1; continue; }

        // banner
        if (!strcmp(argv[i], "--banner")) {
            if (i+1 < argc) { i++; strncpy(cfg.banner, argv[i], sizeof(cfg.banner)-1); cfg.banner[sizeof(cfg.banner)-1] = 0; }
            continue;
        }

        if (!strcmp(argv[i], "--banner-mode")) {
            if (i+1 < argc) {
                i++;
                if (!strcmp(argv[i], "overlay")) cfg.banner_mode = 1;
                else if (!strcmp(argv[i], "mask")) cfg.banner_mode = 2;
                else if (!strcmp(argv[i], "cutout")) cfg.banner_mode = 3;
            }
            continue;
        }

        if (!strcmp(argv[i], "--banner-top"))    { cfg.banner_pos = 0; continue; }
        if (!strcmp(argv[i], "--banner-center")) { cfg.banner_pos = 1; continue; }
        if (!strcmp(argv[i], "--banner-bottom")) { cfg.banner_pos = 2; continue; }

        // glyph sets
        if (!strcmp(argv[i], "--glyph-set")) {
            if (i+1 < argc) {
                i++;
                if (!strcmp(argv[i], "ascii")) cfg.glyph_mode = 0;
                else if (!strcmp(argv[i], "blocks")) cfg.glyph_mode = 1;
                else if (!strcmp(argv[i], "braille")) cfg.glyph_mode = 2;
                else if (!strcmp(argv[i], "ogham")) cfg.glyph_mode = 3;
                else if (!strcmp(argv[i], "emoji")) cfg.glyph_mode = 4;
            }
            continue;
        }

        // single glyph override
        if (!strcmp(argv[i], "--glyph")) {
            if (i+1 < argc) {
                char tmp[8];
                utf8_copy_char(tmp, argv[++i]);
                strncpy(cfg.glyph_map, tmp, sizeof(cfg.glyph_map)-1);
                cfg.glyph_map[sizeof(cfg.glyph_map)-1] = 0;
            }
            continue;
        }

        // glyph maps
        if (!strcmp(argv[i], "--glyph-map")) {
            if (i+1 < argc) { i++; strncpy(cfg.glyph_map, argv[i], sizeof(cfg.glyph_map)-1); cfg.glyph_map[sizeof(cfg.glyph_map)-1] = 0; }
            continue;
        }

        if (!strcmp(argv[i], "--glyph-expr")) {
            if (i+1 < argc) {
                i++;
                strncpy(cfg.glyph_expr, argv[i], sizeof(cfg.glyph_expr)-1);
                cfg.glyph_expr[sizeof(cfg.glyph_expr)-1] = 0;
            }
            continue;
        }

        if (!strcmp(argv[i], "--glyph-emoji")) {
            if (i+1 < argc) {
                i++;
                strncpy(cfg.glyph_expr, argv[i], sizeof(cfg.glyph_expr)-1);
                cfg.glyph_expr[sizeof(cfg.glyph_expr)-1] = 0;
                cfg.glyph_mode = 4;
            }
            continue;
        }

        if (!strcmp(argv[i], "--emoji-map")) {
            if (i+1 < argc) { i++; parse_emoji_map_arg(argv[i]); }
            continue;
        }

        // dimensions
        if (!strcmp(argv[i], "--width")) {
            if (i+1 < argc) { cfg.width = atoi(argv[++i]); }
            continue;
        }
        if (!strcmp(argv[i], "--height")) {
            if (i+1 < argc) { cfg.height = atoi(argv[++i]); }
            continue;
        }

        // zoom
        if (!strcmp(argv[i], "--zoom")) {
            if (i+1 < argc) { cfg.zoom = atof(argv[++i]); }
            continue;
        }

        // speed
        if (!strcmp(argv[i], "--speed")) {
            if (i+1 < argc) { cfg.speed = atof(argv[++i]); }
            continue;
        }

        // timeout
        if (!strcmp(argv[i], "--timeout")) {
            if (i+1 < argc) { cfg.timeout = atoi(argv[++i]); }
            continue;
        }

        // lockscreen presentation
        if (!strcmp(argv[i], "--prompt-on-bottom")) { cfg.prompt_on_bottom = 1; continue; }
        if (!strcmp(argv[i], "--dark")) { cfg.dark = 1; continue; }
        if (!strcmp(argv[i], "--dim")) { cfg.dim = 1; continue; }

        // lockscreen mode
        if (!strcmp(argv[i], "--lockscreen")) {
            cfg.lockscreen = 1;
            continue;
        }
        if (!strcmp(argv[i], "--no-lockscreen")) {
            cfg.lockscreen = 0;
            continue;
        }

        // splash art path (fallback positional)
        if (!strcmp(argv[i], "--splash")) {
            if (i+1 < argc) { i++; strncpy(cfg.splash_path, argv[i], sizeof(cfg.splash_path)-1); cfg.splash_path[sizeof(cfg.splash_path)-1] = 0; }
            continue;
        }

        // fallback positional argument for splash art
        if (cfg.splash_path[0] == '\0') {
            strncpy(cfg.splash_path, argv[i], sizeof(cfg.splash_path)-1);
            cfg.splash_path[sizeof(cfg.splash_path)-1] = 0;
        }
    }
}

static void build_glyph_expr_table(void) {
    glyph_expr_count = 0;
    const char *p = cfg.glyph_expr;
    while (*p && glyph_expr_count < (int)(sizeof(glyph_expr_table) / sizeof(glyph_expr_table[0]))) {
        uint32_t cp = 0;
        int n = utf8_decode(p, &cp);
        if (n <= 0) break;

        if (is_emoji_codepoint(cp)) {
            const char *rep = emoji_lookup(cp);
            strncpy(glyph_expr_table[glyph_expr_count], rep, sizeof(glyph_expr_table[0]) - 1);
            glyph_expr_table[glyph_expr_count][sizeof(glyph_expr_table[0]) - 1] = 0;
        } else {
            if (n >= (int)sizeof(glyph_expr_table[0])) n = (int)sizeof(glyph_expr_table[0]) - 1;
            memcpy(glyph_expr_table[glyph_expr_count], p, n);
            glyph_expr_table[glyph_expr_count][n] = 0;
        }

        glyph_expr_count++;
        p += n;
    }
}

static void finalize_config(void) {
    if (cfg.use_fire && !cfg.user_palette) {
        cfg.palette_mode = 1; // fire palette by default when fire mode is on
    }

    if (cfg.glyph_expr[0] == '\0' && cfg.glyph_mode == 4) {
        strncpy(cfg.glyph_expr, "🔥🌿💀🌀⭐🪐", sizeof(cfg.glyph_expr) - 1);
        cfg.glyph_expr[sizeof(cfg.glyph_expr) - 1] = 0;
    }

    if (cfg.glyph_expr[0]) {
        build_glyph_expr_table();
    } else {
        glyph_expr_count = 0;
    }
}

// ─────────────────────────────────────────────────────────────
//   MAIN ENTRY
// ─────────────────────────────────────────────────────────────

int main(int argc, char **argv) {
    init_config();
    parse_args(argc, argv);
    finalize_config();

    srand((unsigned)(time(NULL) ^ getpid()));

    if (show_help_flag) {
        show_help(argv[0]);
        return 0;
    }

    if (!cfg.use_mandelbrot && !cfg.use_julia && !cfg.use_fire && !cfg.use_acidwarp && cfg.splash_path[0] == '\0') {
        cfg.use_julia = 1; // friendly default
    }

    if (cfg.use_acidwarp) {
        cfg.rotate_colors = 1;
        cfg.geo_mode = cfg.geo_mode ? cfg.geo_mode : 2; // twirl feels right
    }

    // determine terminal geometry
    if (cfg.lockscreen && (cfg.width == 0 || cfg.height == 0)) {
        // fixed, stable geometry for lockscreen (your preference)
        cfg.width = 120;
        cfg.height = 40;
    } else if (!cfg.lockscreen && (cfg.width == 0 || cfg.height == 0)) {
        // auto-detect for standalone
        get_terminal_size(&cfg.width, &cfg.height);
    }

    raw_mode();
    install_signal_guards();

    if (cfg.lockscreen) {
        run_lockscreen();
    } else {
        render_frame(); // standalone fractal engine
    }

    return 0;
}

// ─────────────────────────────────────────────────────────────
//   FILE LOADING (optional splash art)
// ─────────────────────────────────────────────────────────────

static char *splash_art;

static char* load_file(const char *path) {
    struct stat st;
    if (stat(path, &st) < 0) return NULL;

    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    char *buf = malloc(st.st_size + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    size_t n = fread(buf, 1, st.st_size, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

static void ensure_splash_loaded(void) {
    if (splash_art || cfg.splash_path[0] == '\0') return;
    splash_art = load_file(cfg.splash_path);
}

static const char* selected_unlock_code(int *from_env) {
    const char *env = getenv("UNLOCK_CODE");
    if (env && env[0]) {
        if (from_env) *from_env = 1;
        return env;
    }
    if (!selected_fallback_code) {
        selected_fallback_code = fallback_codes[rand() % fallback_codes_count];
    }
    if (from_env) *from_env = 0;
    return selected_fallback_code;
}

// ─────────────────────────────────────────────────────────────
//   HELP
// ─────────────────────────────────────────────────────────────

static void show_help(const char *self) {
    printf(
        "Usage: %s [options] [splash.ans]\n"
        "\n"
        "Fractals: --mandelbrot | --julia | --fire | --acidwarp\n"
        "Palettes: --palette rainbow|fire|gray|grayscale|plasma|neon\n"
        "Geometry: --geo polar|twirl|sine|fold|feedback\n"
        "Glyphs:   --glyph-set ascii|blocks|braille|ogham|emoji\n"
        "          --glyph <char> --glyph-map \" .:-=+*#%%@\"\n"
        "          --glyph-expr UTF8 --glyph-emoji <emoji> --emoji-map \"🔥=#\"\n"
        "Banner:   --banner \"text\" [--banner-mode overlay|mask|cutout]\n"
        "          --banner-top|--banner-center|--banner-bottom\n"
        "Sizing:   --width N --height N --zoom Z --speed S\n"
        "Fire:     --fire-full | --fire-bottom | --fire-hybrid\n"
        "Effects:  --ogham-rain --sigil-curtains --feedback-classic\n"
        "Lock:     --lockscreen [--timeout N] --prompt-on-bottom --dark --dim | --no-lockscreen\n"
        "General:  --drift|--no-drift --rotate --warp --splash file.ans\n"
        "Flags are additive; defaults favor Julia fractal with rainbow palette.\n",
        self
    );
}

// ─────────────────────────────────────────────────────────────
//   COLOR + PALETTE
// ─────────────────────────────────────────────────────────────

typedef struct {
    int r;
    int g;
    int b;
} RGB;

static void rotate_color(RGB *c, int shift) {
    int s = shift % 256;
    c->r = (c->r + s) % 256;
    c->g = (c->g + (s * 2 / 3)) % 256;
    c->b = (c->b + (s / 2)) % 256;
}

static int clamp255(int v) {
    if (v < 0) return 0;
    if (v > 255) return 255;
    return v;
}

static void palette_color(int iter, int maxIter, RGB *out, double phase) {
    double t = (double)iter / (double)maxIter;
    if (t > 1.0) t = 1.0;

    switch (cfg.palette_mode) {
        case 1: { // fire
            out->r = 255;
            out->g = (int)(180 + t * 75);
            if (out->g > 255) out->g = 255;
            out->b = (int)(t * 80);
            break;
        }
        case 2: { // grayscale
            int v = (int)(t * 255);
            out->r = out->g = out->b = v;
            break;
        }
        case 3: { // plasma
            out->r = (int)(128 + 127 * sin(6.28318 * (t + phase * 0.02)));
            out->g = (int)(128 + 127 * sin(6.28318 * (t + 0.33 + phase * 0.025)));
            out->b = (int)(128 + 127 * sin(6.28318 * (t + 0.66 + phase * 0.03)));
            break;
        }
        case 4: { // neon
            out->r = (int)(100 + 155 * fabs(sin(phase * 0.4 + t * 4)));
            out->g = (int)(255 * fabs(sin(phase * 0.5 + t * 3)));
            out->b = (int)(200 + 55 * sin(phase * 0.6 + t * 5));
            if (out->r > 255) out->r = 255;
            if (out->g > 255) out->g = 255;
            if (out->b > 255) out->b = 255;
            break;
        }
        default: { // rainbow
            out->r = (int)(128 + 127 * sin(6.28318 * (t + phase * 0.02)));
            out->g = (int)(128 + 127 * sin(6.28318 * (t + 0.33 + phase * 0.02)));
            out->b = (int)(128 + 127 * sin(6.28318 * (t + 0.66 + phase * 0.02)));
            break;
        }
    }

    if (iter >= maxIter) {
        out->r = out->g = out->b = 0;
    }

    if (cfg.rotate_colors) {
        rotate_color(out, (int)(phase * 50));
    }
}

// ─────────────────────────────────────────────────────────────
//   GEOMETRY TRANSFORMS
// ─────────────────────────────────────────────────────────────

static void apply_geo(double *x, double *y, double t) {
    switch (cfg.geo_mode) {
        case 1: { // polar
            double r = hypot(*x, *y);
            double a = atan2(*y, *x) + sin(t * 0.5) * 0.5;
            *x = cos(a) * r;
            *y = sin(a) * r;
            break;
        }
        case 2: { // twirl
            double r = hypot(*x, *y);
            double a = atan2(*y, *x) + r * 1.2 + t * 0.4;
            *x = cos(a) * r;
            *y = sin(a) * r;
            break;
        }
        case 3: { // sine
            *x += sin(*y * 3 + t) * 0.25;
            *y += cos(*x * 3 + t) * 0.25;
            break;
        }
        case 4: { // fold
            *x = fabs(*x);
            *y = fabs(*y);
            break;
        }
        case 5: { // feedback
            if (cfg.feedback_simple) {
                double scale = 1.0 + 0.25 * sin(t * 0.7);
                *x *= scale;
                *y *= scale;
            } else {
                *x += sin(t + *x) * 0.02;
                *y += cos(t + *y) * 0.02;
            }
            break;
        }
        default:
            break;
    }
}

// ─────────────────────────────────────────────────────────────
//   FRACTALS
// ─────────────────────────────────────────────────────────────

static int mandelbrot_iter(double x0, double y0, int maxIter) {
    double x = 0.0, y = 0.0;
    int iter = 0;
    while ((x * x + y * y) <= 4.0 && iter < maxIter) {
        double xt = x * x - y * y + x0;
        y = 2 * x * y + y0;
        x = xt;
        iter++;
    }
    return iter;
}

static int julia_iter(double x, double y, double cx, double cy, int maxIter) {
    int iter = 0;
    while ((x * x + y * y) <= 4.0 && iter < maxIter) {
        double xt = x * x - y * y + cx;
        y = 2 * x * y + cy;
        x = xt;
        iter++;
    }
    return iter;
}

static int sample_fractal(double x, double y, int maxIter, double t) {
    if (cfg.warp) {
        x += sin(t * 0.3 + y * 1.2) * 0.3;
        y += cos(t * 0.2 + x * 1.2) * 0.3;
    }

    apply_geo(&x, &y, t);

    if (cfg.use_fire) {
        double cx = -0.4 + 0.05 * sin(t * 0.9);
        double cy = 0.6 + 0.1 * cos(t * 0.6);
        return julia_iter(x, y, cx, cy, maxIter);
    }

    if (cfg.use_julia) {
        double cx = -0.7 + 0.2 * sin(t * 0.4);
        double cy = 0.27015 + 0.2 * cos(t * 0.31);
        return julia_iter(x, y, cx, cy, maxIter);
    }

    return mandelbrot_iter(x, y, maxIter);
}

// ─────────────────────────────────────────────────────────────
//   GLYPHS
// ─────────────────────────────────────────────────────────────

static void codepoint_to_utf8(uint32_t cp, char *out) {
    if (cp <= 0x7F) {
        out[0] = (char)cp;
        out[1] = 0;
    } else if (cp <= 0x7FF) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        out[2] = 0;
    } else if (cp <= 0xFFFF) {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        out[3] = 0;
    } else {
        out[0] = (char)(0xF0 | (cp >> 18));
        out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[3] = (char)(0x80 | (cp & 0x3F));
        out[4] = 0;
    }
}

static const char* glyph_for(int iter, int maxIter, char *tmp) {
    if (iter >= maxIter) {
        tmp[0] = ' ';
        tmp[1] = 0;
        return tmp;
    }

    if (glyph_expr_count > 0) {
        int idx = iter % glyph_expr_count;
        strncpy(tmp, glyph_expr_table[idx], 15);
        tmp[15] = 0;
        return tmp;
    }

    switch (cfg.glyph_mode) {
        case 1: { // blocks
            const char *blocks[] = {" ", ".", ":", "-", "+", "*", "#", "@", NULL};
            int len = 0;
            while (blocks[len]) len++;
            int idx = (int)((double)iter / maxIter * (len - 1));
            if (idx < 0) idx = 0;
            if (idx >= len) idx = len - 1;
            strncpy(tmp, blocks[idx], 3);
            tmp[3] = 0;
            return tmp;
        }
        case 2: { // braille-ish
            uint32_t cp = 0x2800 + (iter % 64);
            codepoint_to_utf8(cp, tmp);
            return tmp;
        }
        case 3: { // ogham runes (escaped UTF-8)
            static const uint32_t ogham_codes[] = {0x1681, 0x1682, 0x1683, 0x1684, 0x1685, 0x1686, 0x1687, 0x169B};
            int len = sizeof(ogham_codes) / sizeof(ogham_codes[0]);
            int idx = (int)((double)iter / maxIter * (len - 1));
            if (idx < 0) idx = 0;
            if (idx >= len) idx = len - 1;
            codepoint_to_utf8(ogham_codes[idx], tmp);
            return tmp;
        }
        default: { // ascii map
            int map_len = (int)strlen(cfg.glyph_map);
            if (map_len == 0) {
                cfg.glyph_map[0] = ' ';
                cfg.glyph_map[1] = '#';
                cfg.glyph_map[2] = 0;
                map_len = 2;
            }
            int idx = (int)((double)iter / maxIter * (map_len - 1));
            if (idx < 0) idx = 0;
            if (idx >= map_len) idx = map_len - 1;
            tmp[0] = cfg.glyph_map[idx];
            tmp[1] = 0;
            return tmp;
        }
    }
}

static int banner_char_at(const char *src, int index, char *out) {
    const char *p = src;
    int i = 0;
    while (*p) {
        int n = utf8_len((const unsigned char*)p);
        if (i == index) {
            for (int j = 0; j < n; j++) out[j] = p[j];
            out[n] = 0;
            return n;
        }
        p += n;
        i++;
    }
    out[0] = 0;
    return 0;
}

static void show_kitty_face(void) {
    printf("\033[2J\033[H");
    printf("\033[38;2;255;192;203m /\\_/\\\033[0m\n");
    printf("\033[38;2;255;160;122m( o.o )\033[0m\n");
    printf("\033[38;2;255;215;0m > ^ <  wrong code!\033[0m\n\n");
    fflush(stdout);
    usleep(450000);
}

// ─────────────────────────────────────────────────────────────
//   EFFECTS: OGHAM RAIN + SIGIL CURTAINS
// ─────────────────────────────────────────────────────────────

static const char *ogham_glyphs[] = {
    "ᚁ","ᚂ","ᚃ","ᚄ","ᚅ","ᚆ","ᚇ","ᚈ","ᚉ","ᚊ",
    "ᚋ","ᚌ","ᚍ","ᚎ","ᚏ","ᚐ","ᚑ","ᚒ","ᚓ","ᚔ",
    "ᚕ","ᚖ","ᚗ","ᚘ","ᚙ","ᚚ"
};
static const int ogham_count = 26;

typedef struct {
    int x;
    double y;
    const char *glyph;
    double speed;
    int active;
} OghamDrop;

typedef struct {
    int x;
    int height;
    int active;
    const char *glyphSequence[16];
    int seqLen;
} SigilColumn;

#define MAX_DROPS 64
#define MAX_SIGIL_COLUMNS 16

static OghamDrop drops[MAX_DROPS];
static SigilColumn sigils[MAX_SIGIL_COLUMNS];

static void init_effects(void) {
    if (effects_initialized) return;
    effects_initialized = 1;
    for (int i = 0; i < MAX_DROPS; i++) drops[i].active = 0;
    for (int i = 0; i < MAX_SIGIL_COLUMNS; i++) sigils[i].active = 0;
}

static void ogham_launch_drop(void) {
    for (int i = 0; i < MAX_DROPS; i++) {
        if (!drops[i].active) {
            drops[i].active = 1;
            drops[i].x = rand() % (cfg.width ? cfg.width : 80);
            drops[i].y = 0.0;
            drops[i].glyph = ogham_glyphs[rand() % ogham_count];
            drops[i].speed = 0.35 + (rand() % 100) / 220.0;
            return;
        }
    }
}

static void ogham_rain_update(int h) {
    for (int i = 0; i < MAX_DROPS; i++) {
        if (!drops[i].active) continue;
        drops[i].y += drops[i].speed;
        if ((int)drops[i].y >= h) drops[i].active = 0;
    }
}

static void ogham_rain_render_layer(void) {
    for (int i = 0; i < MAX_DROPS; i++) {
        if (!drops[i].active) continue;
        int py = (int)drops[i].y;
        if (py < 0 || py >= cfg.height) continue;
        printf("\033[%d;%dH\033[38;2;200;255;200m%s", py + 1, drops[i].x + 1, drops[i].glyph);
    }
}

static void sigil_launch_column(void) {
    for (int i = 0; i < MAX_SIGIL_COLUMNS; i++) {
        if (!sigils[i].active) {
            sigils[i].active = 1;
            sigils[i].x = rand() % (cfg.width ? cfg.width : 80);
            sigils[i].height = 3 + rand() % ((cfg.height ? cfg.height : 20) / 2 + 1);
            sigils[i].seqLen = 6;
            for (int j = 0; j < sigils[i].seqLen; j++) {
                sigils[i].glyphSequence[j] = ogham_glyphs[rand() % ogham_count];
            }
            return;
        }
    }
}

static void sigil_curtains_render_layer(void) {
    for (int i = 0; i < MAX_SIGIL_COLUMNS; i++) {
        if (!sigils[i].active) continue;
        int col = sigils[i].x;
        for (int j = 0; j < sigils[i].height; j++) {
            const char *g = sigils[i].glyphSequence[j % sigils[i].seqLen];
            printf("\033[%d;%dH\033[38;2;180;180;255m%s", j + 1, col + 1, g);
        }
    }
}

static void render_effect_layers(void) {
    if (!cfg.ogham_rain && !cfg.sigil_curtains) return;
    init_effects();
    if (cfg.ogham_rain && (rand() % 10 == 0)) ogham_launch_drop();
    if (cfg.sigil_curtains && (rand() % 60 == 0)) sigil_launch_column();
    if (cfg.ogham_rain) ogham_rain_update(cfg.height);
    if (cfg.ogham_rain) ogham_rain_render_layer();
    if (cfg.sigil_curtains) sigil_curtains_render_layer();
}

// ─────────────────────────────────────────────────────────────
//   DRAW
// ─────────────────────────────────────────────────────────────

static int banner_row_position(void) {
    if (!cfg.banner[0]) return -1;
    if (cfg.banner_pos == 0) return 2;
    if (cfg.banner_pos == 2) return cfg.height - 3;
    return cfg.height / 2;
}

static void draw_scene(double phase, int pulse, const char *status, const char *input_mask) {
    if (splash_art && !cfg.use_mandelbrot && !cfg.use_julia && !cfg.use_fire && !cfg.use_acidwarp) {
        printf("\033[2J\033[H");
        printf("\033[%dm", 31 + (pulse % 6));
        printf("%s\033[0m\n", splash_art);
        if (cfg.prompt_on_bottom && (status || input_mask)) {
            int row = cfg.height ? cfg.height : 40;
            printf("\033[%d;1H", row + 1);
        }
        if (status) printf("%s\n", status);
        if (input_mask) printf("%s\n", input_mask);
        fflush(stdout);
        return;
    }

    int maxIter = cfg.use_fire ? 110 : 96;
    int w = cfg.width;
    int h = cfg.height;
    int banner_len = utf8_strlen(cfg.banner);
    int banner_row = banner_row_position();
    int banner_start = banner_len ? (w - banner_len) / 2 : 0;

    printf("\033[H");

    for (int py = 0; py < h; py++) {
        for (int px = 0; px < w; px++) {
            double x = (px - w / 2.0) * cfg.zoom;
            double y = (py - h / 2.0) * cfg.zoom;

            if (cfg.use_fire) {
                if (cfg.fire_layout == 1) { // bottom only
                    y = (py - (h * 0.7)) * cfg.zoom * 2.2;
                } else if (cfg.fire_layout == 2) { // hybrid
                    double mix = (double)py / h;
                    y = (py - h / 2.0) * cfg.zoom * (0.8 + 0.6 * mix);
                }
            }

            if (cfg.drift) {
                x += sin(phase * 0.35) * 0.35;
                y += cos(phase * 0.28) * 0.35;
            }

            int it = sample_fractal(x, y, maxIter, phase);
            RGB color;
            if (cfg.use_fire && cfg.fire_layout == 2) { // hybrid: rainbow up top, fire down low
                RGB fireColor, rainbowColor;
                int current_palette = cfg.palette_mode;
                cfg.palette_mode = 1;
                palette_color(it, maxIter, &fireColor, phase);
                cfg.palette_mode = 0;
                palette_color(it, maxIter, &rainbowColor, phase);
                cfg.palette_mode = current_palette;
                double mix = (double)py / (double)h;
                color.r = (int)(rainbowColor.r * (1.0 - mix) + fireColor.r * mix);
                color.g = (int)(rainbowColor.g * (1.0 - mix) + fireColor.g * mix);
                color.b = (int)(rainbowColor.b * (1.0 - mix) + fireColor.b * mix);
            } else {
                palette_color(it, maxIter, &color, phase);
            }

            if (cfg.use_fire) {
                int flicker = (int)(fabs(sin(phase * 4.3 + px * 0.03 + py * 0.021)) * 45);
                color.r = clamp255(color.r + flicker);
                color.g = clamp255(color.g + flicker / 2);
                color.b = clamp255(color.b);
            }

            if (cfg.dim) {
                color.r = (int)(color.r * 0.7);
                color.g = (int)(color.g * 0.7);
                color.b = (int)(color.b * 0.7);
            }

            if (cfg.dark) {
                color.r = (int)(color.r * 0.5);
                color.g = (int)(color.g * 0.5);
                color.b = (int)(color.b * 0.5);
            }

            char glyph_buf[16];
            const char *glyph = glyph_for(it, maxIter, glyph_buf);

            if (banner_len && py == banner_row && px >= banner_start && px < banner_start + banner_len) {
                char bch[8];
                banner_char_at(cfg.banner, px - banner_start, bch);
                if (cfg.banner_mode == 1) { // overlay
                    color.r = 255; color.g = 255; color.b = 245;
                    glyph = bch[0] ? bch : " ";
                } else if (cfg.banner_mode == 2) { // mask
                    color.r = color.g = color.b = 0;
                    glyph = " ";
                } else if (cfg.banner_mode == 3) { // cutout
                    glyph = bch[0] ? bch : glyph;
                    color.r = color.r + 40 > 255 ? 255 : color.r + 40;
                    color.g = color.g + 40 > 255 ? 255 : color.g + 40;
                    color.b = color.b + 40 > 255 ? 255 : color.b + 40;
                }
            }

            printf("\033[38;2;%d;%d;%dm%s", color.r, color.g, color.b, glyph);
        }
        printf("\033[0m\n");
    }

    render_effect_layers();

    if ((cfg.prompt_on_bottom || cfg.ogham_rain || cfg.sigil_curtains) && (status || input_mask)) {
        printf("\033[%d;1H", h + 1);
    }
    if (status) printf("%s\n", status);
    if (input_mask) printf("%s\n", input_mask);
    fflush(stdout);
}

// ─────────────────────────────────────────────────────────────
//   PUBLIC ENTRYPOINTS
// ─────────────────────────────────────────────────────────────

void render_banner_overlay() {
    ensure_splash_loaded();
    enter_alt_screen();
    if (cfg.dark) printf("\033[48;2;0;0;0m");
    draw_scene(0.0, 0, NULL, NULL);
}

void render_frame() {
    ensure_splash_loaded();
    enter_alt_screen();
    double phase = 0.0;
    int pulse = 0;
    printf("\033[?25l\033[2J");
    if (cfg.dark) printf("\033[48;2;0;0;0m");

    for (;;) {
        const char *status = "\033[37m[q] quit\033[0m";
        draw_scene(phase, pulse, status, NULL);
        phase += cfg.speed;
        pulse++;
        usleep(45000);

        char c;
        if (read(STDIN_FILENO, &c, 1) > 0) {
            if (c == 3 || c == 4 || c == 26) continue; // ignore ctrl+c/d/z
            if (c == 'q' || c == 'Q' || c == 27) {
                break;
            }
        }
    }

    printf("\033[0m\033[?25h\n");
    exit_alt_screen();
}

void run_lockscreen() {
    ensure_splash_loaded();
    enter_alt_screen();
    int unlock_from_env = 0;
    const char *unlock = selected_unlock_code(&unlock_from_env);
    (void)unlock_from_env;

    char input[256];
    int pulse = 0;
    double phase = 0.0;

    printf("\033[?25l\033[2J");
    if (cfg.dark) printf("\033[48;2;0;0;0m");

    for (;;) {
        memset(input, 0, sizeof(input));
        int pos = 0;
        time_t start = time(NULL);

        for (;;) {
            char status_line[256];
            snprintf(status_line, sizeof(status_line),
                "\033[37m[ ENTER to unlock | ESC to reset | timeout %ds ]\033[0m",
                cfg.timeout);

            char mask_buf[256];
            if (pos > (int)sizeof(mask_buf) - 1) pos = (int)sizeof(mask_buf) - 1;
            memset(mask_buf, '*', pos);
            mask_buf[pos] = 0;

            char input_line[320];
            snprintf(input_line, sizeof(input_line), "\033[36mcode:\033[0m %s", mask_buf);

            draw_scene(phase, pulse, status_line, input_line);

            phase += cfg.speed;
            pulse++;
            usleep(90000);

            char c;
            if (read(STDIN_FILENO, &c, 1) > 0) {
                if (c == 3 || c == 4 || c == 26) continue; // ignore ctrl+c/d/z
                if (c == 27) {
                    break; // reset attempt
                }
                if (c == '\n') {
                    if (strcmp(input, unlock) == 0) {
                        printf("\033[2J\033[H\033[32mAccess granted.\033[0m\n");
                        printf("\033[?25h");
                        fflush(stdout);
                        return;
                    }
                    show_kitty_face();
                    break; // wrong → reset
                }
                if (pos < (int)sizeof(input) - 1) {
                    input[pos++] = c;
                }
            }

            if (time(NULL) - start > cfg.timeout) {
                break;
            }
        }
    }
    exit_alt_screen();
}
