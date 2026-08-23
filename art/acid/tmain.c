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

int iteration_limit; // will be set by config in main engine
double time_tick;    // animation timer

// Forward: cfg struct comes from Part 1
EngineConfig cfg;


// forward declarations for later parts
void render_frame();
void render_banner_overlay();
void run_lockscreen();

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

// ─────────────────────────────────────────────────────────────
//   Terminal control
// ─────────────────────────────────────────────────────────────

static struct termios old_tio;

static void restore_tio() {
    tcsetattr(STDIN_FILENO, TCSANOW, &old_tio);
}

static void raw_mode() {
    struct termios new_tio;
    tcgetattr(STDIN_FILENO, &old_tio);
    atexit(restore_tio);

    new_tio = old_tio;
    new_tio.c_lflag &= ~(ICANON | ECHO);
    new_tio.c_cc[VMIN] = 0;
    new_tio.c_cc[VTIME] = 0;

    tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);
}

// get terminal size
static void get_terminal_size(int *w, int *h) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        *w = ws.ws_col;
        *h = ws.ws_row;
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

    int glyph_mode;        // ascii / blocks / braille / ogham
    char glyph_map[128];
    char glyph_expr[256];

    char banner[512];
    int banner_mode;       // mask / overlay / cutout
    int banner_pos;        // top / center / bottom

    int lockscreen;        // lockscreen mode flag
    int timeout;
} EngineConfig;

static EngineConfig cfg;

// ─────────────────────────────────────────────────────────────
//   Default configuration
// ─────────────────────────────────────────────────────────────

static void init_config() {
    memset(&cfg, 0, sizeof(cfg));

    cfg.zoom = 0.015;
    cfg.speed = 0.04;

    cfg.palette_mode = 0;     // rainbow
    cfg.geo_mode = 0;         // none
    cfg.glyph_mode = 0;       // ascii

    strcpy(cfg.glyph_map, " .:-=+*#%@");

    cfg.fire_layout = 0;      // full
    cfg.banner_mode = 1;      // overlay
    cfg.banner_pos = 1;       // center

    cfg.timeout = 12;
}

// ─────────────────────────────────────────────────────────────
//   CLI parser
// ─────────────────────────────────────────────────────────────

static void parse_args(int argc, char **argv) {

    for (int i = 1; i < argc; i++) {

        // fractal modes
        if (!strcmp(argv[i], "--mandelbrot")) { cfg.use_mandelbrot = 1; continue; }
        if (!strcmp(argv[i], "--julia"))       { cfg.use_julia = 1; continue; }
        if (!strcmp(argv[i], "--fire"))        { cfg.use_fire = 1; continue; }
        if (!strcmp(argv[i], "--acidwarp"))    { cfg.use_acidwarp = 1; continue; }

        // palettes
        if (!strcmp(argv[i], "--palette")) {
            if (i+1 < argc) {
                i++;
                if (!strcmp(argv[i], "rainbow")) cfg.palette_mode = 0;
                else if (!strcmp(argv[i], "fire")) cfg.palette_mode = 1;
                else if (!strcmp(argv[i], "gray")) cfg.palette_mode = 2;
                else if (!strcmp(argv[i], "plasma")) cfg.palette_mode = 3;
                else if (!strcmp(argv[i], "neon")) cfg.palette_mode = 4;
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

        // banner
        if (!strcmp(argv[i], "--banner")) {
            if (i+1 < argc) { i++; strncpy(cfg.banner, argv[i], sizeof(cfg.banner)-1); }
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
            }
            continue;
        }

        // glyph maps
        if (!strcmp(argv[i], "--glyph-map")) {
            if (i+1 < argc) { i++; strncpy(cfg.glyph_map, argv[i], sizeof(cfg.glyph_map)-1); }
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

        // lockscreen mode
        if (!strcmp(argv[i], "--lockscreen")) {
            cfg.lockscreen = 1;
            continue;
        }
    }
}

// ─────────────────────────────────────────────────────────────
//   MAIN ENTRY
// ─────────────────────────────────────────────────────────────

int main(int argc, char **argv) {
    init_config();
    parse_args(argc, argv);

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

    if (cfg.lockscreen) {
        run_lockscreen();
    } else {
        render_frame(); // standalone fractal engine
    }

    return 0;
}
// ─────────────────────────────────────────────────────────────
//   FRACTAL CORE FUNCTIONS
// ─────────────────────────────────────────────────────────────

int fractal_mandelbrot(double x0, double y0) {
    double x = 0, y = 0;
    int it = 0;
    while (x*x + y*y <= 4 && it < iteration_limit) {
        double xt = x*x - y*y + x0;
        y = 2*x*y + y0;
        x = xt;
        it++;
    }
    return it;
}

int fractal_julia(double x, double y, double cx, double cy) {
    int it = 0;
    while (x*x + y*y <= 4 && it < iteration_limit) {
        double xt = x*x - y*y + cx;
        y = 2*x*y + cy;
        x = xt;
        it++;
    }
    return it;
}

// ─────────────────────────────────────────────────────────────
//   FIRE FRACTAL VARIANT (Julia-driven)
// ─────────────────────────────────────────────────────────────

int fractal_fire(double x, double y) {
    double cx = -0.7 + sin(time_tick * 1.2) * 0.05;
    double cy =  0.27 + cos(time_tick * 1.5) * 0.05;
    return fractal_julia(x, y, cx, cy);
}

// ─────────────────────────────────────────────────────────────
//   GEOMETRY TRANSFORMS
// ─────────────────────────────────────────────────────────────
// These modify (x,y) before fractal sampling.

void geo_polar(double *x, double *y) {
    double r = sqrt((*x)*(*x) + (*y)*(*y));
    double a = atan2(*y, *x);
    a += time_tick * 0.4;
    *x = r * cos(a);
    *y = r * sin(a);
}

void geo_twirl(double *x, double *y) {
    double a = time_tick * 0.6;
    double xx = *x * cos(a) - *y * sin(a);
    double yy = *x * sin(a) + *y * cos(a);
    *x = xx;
    *y = yy;
}

void geo_sine(double *x, double *y) {
    *x += sin((*y)*5 + time_tick) * 0.1;
    *y += cos((*x)*5 + time_tick) * 0.1;
}

void geo_fold(double *x, double *y) {
    *x = fabs(*x);
    *y = fabs(*y);
}

// Feedback geometry uses prior frame — placeholder
// (Full implementation will come after frame buffers exist)
void geo_feedback(double *x, double *y) {
    *x += sin(time_tick + *x) * 0.02;
    *y += cos(time_tick + *y) * 0.02;
}

// Apply chosen geometry
void apply_geometry(double *x, double *y) {
    switch (cfg.geo_mode) {
        case 1: geo_polar(x, y); break;
        case 2: geo_twirl(x, y); break;
        case 3: geo_sine(x, y); break;
        case 4: geo_fold(x, y); break;
        case 5: geo_feedback(x, y); break;
        default: break;
    }
}

// ─────────────────────────────────────────────────────────────
//   PALETTE ROTATION (AcidWarp-style)
// ─────────────────────────────────────────────────────────────
// Color is computed in Part 3, but rotation belongs to engine.

int rotate_palette_index(int base) {
    if (!cfg.rotate_colors) return base;
    return (base + ((int)(time_tick * 20))) % 256;
}

// ─────────────────────────────────────────────────────────────
//   FRACTAL SAMPLE PIPELINE
// ─────────────────────────────────────────────────────────────
// Returns fractal iteration count for given pixel

int sample_fractal(double x, double y) {
    apply_geometry(&x, &y);

    if (cfg.use_fire)     return fractal_fire(x, y);
    if (cfg.use_mandelbrot) return fractal_mandelbrot(x, y);
    if (cfg.use_julia)    {
        double cx = -0.7 + (cfg.drift ? sin(time_tick * 0.2) * 0.1 : 0);
        double cy =  0.27 + (cfg.drift ? cos(time_tick * 0.3) * 0.1 : 0);
        return fractal_julia(x, y, cx, cy);
    }

    return fractal_mandelbrot(x, y);
}

// ─────────────────────────────────────────────────────────────
//   FRAME RENDERER (BACKGROUND ONLY)
// ─────────────────────────────────────────────────────────────
// Part 3 handles glyph + color mapping.
// Part 4 handles banners + lockscreen.

extern void apply_palette_and_glyph(int it, int x, int y);
/*
void render_frame() {
    printf("[2J[H");

    for (int py = 0; py < cfg.height; py++) {
        for (int px = 0; px < cfg.width; px++) {
            double x = (px - cfg.width/2.0) * cfg.zoom;
            double y = (py - cfg.height/2.0) * cfg.zoom;

            int it = sample_fractal(x, y);

            apply_palette_and_glyph(it, px, py);
        }
        printf(" ");
    }

    fflush(stdout);
}
*/

// ─────────────────────────────────────────────────────────────
//  PART 3 — PALETTE + GLYPH SYSTEMS
// ─────────────────────────────────────────────────────────────

// Forward declarations
typedef struct { int r, g, b; } RGB;

// ─────────────────────────────────────────────────────────────
//  PALETTES
// ─────────────────────────────────────────────────────────────

// Rainbow gradient (HSV-like approx)
RGB palette_rainbow(int it, int max) {
    float t = (float)it / max;
    int r = (int)(sin(6.2831 * t) * 127 + 128);
    int g = (int)(sin(6.2831 * t + 2.094) * 127 + 128);
    int b = (int)(sin(6.2831 * t + 4.188) * 127 + 128);
    return (RGB){r,g,b};
}

// Fire palette (BBS 196→202→208→214→220→226→231)
RGB palette_fire(int it, int max) {
    if (it >= max) return (RGB){0,0,0};
    float t = (float)it / max;
    int r = 255;
    int g = (int)(t * 255);
    int b = (int)(t * 80);
    return (RGB){r,g,b};
}

// Grayscale
RGB palette_gray(int it, int max) {
    int v = (int)(255.0 * it / max);
    return (RGB){v,v,v};
}

// Plasma
RGB palette_plasma(int it, int max) {
    float t = (float)it / max;
    int r = (int)(255 * fabs(sin(t * 3.14)));
    int g = (int)(255 * fabs(sin(t * 6.28)));
    int b = (int)(255 * fabs(cos(t * 4.71)));
    return (RGB){r,g,b};
}

// Neon
RGB palette_neon(int it, int max) {
    float t = (float)it / max;
    int r = (int)(255 * pow(t, 0.2));
    int g = (int)(255 * pow(t, 0.4));
    int b = (int)(255 * pow(t, 0.8));
    return (RGB){r,g,b};
}

RGB get_palette_color(int it, int max) {
    switch (cfg.palette_mode) {
        case 0: return palette_rainbow(it, max);
        case 1: return palette_fire(it, max);
        case 2: return palette_gray(it, max);
        case 3: return palette_plasma(it, max);
        case 4: return palette_neon(it, max);
    }
    return palette_rainbow(it, max);
}

// ─────────────────────────────────────────────────────────────
//  GLYPH SETS
// ─────────────────────────────────────────────────────────────

static const char *ogham_glyphs[] = {
    "ᚁ","ᚂ","ᚃ","ᚄ","ᚅ","ᚆ","ᚇ","ᚈ","ᚉ","ᚊ",
    "ᚋ","ᚌ","ᚍ","ᚎ","ᚏ","ᚐ","ᚑ","ᚒ","ᚓ","ᚔ",
    "ᚕ","ᚖ","ᚗ","ᚘ","ᚙ","ᚚ"
};
static const int ogham_count = 26;

char glyph_ascii(int it) {
    int len = strlen(cfg.glyph_map);
    return cfg.glyph_map[it % len];
}

const char *glyph_ogham(int it) {
    return ogham_glyphs[it % ogham_count];
}

// Block characters
typedef struct { const char *g; } GStr;
GStr blocks[] = {
    {"░"},{"▒"},{"▓"},{"█"}
};

// Braille matrix (256 glyphs) simplified
char braille_from_iters(int it) {
    int b = it & 0xFF;
    return 0x80 + b;
}

// ─────────────────────────────────────────────────────────────
//  APPLY PALETTE + GLYPH
// ─────────────────────────────────────────────────────────────

void apply_palette_and_glyph(int it, int px, int py) {
    RGB c = get_palette_color(it, iteration_limit);
    printf("\033[38;2;%d;%d;%dm", c.r, c.g, c.b);

    switch (cfg.glyph_mode) {
        case 0: // ascii
            putchar(glyph_ascii(it));
            break;
        case 1: // blocks
            printf("%s", blocks[it % 4].g);
            break;
        case 2: // braille
            putchar(braille_from_iters(it));
            break;
        case 3: // ogham
            printf("%s", glyph_ogham(it));
            break;
    }
}

// ─────────────────────────────────────────────────────────────
//  PART 4 — BANNER SYSTEM + LOCKSCREEN INTEGRATION
// ─────────────────────────────────────────────────────────────

// Forward declarations
extern int sample_fractal(double x, double y);
extern RGB get_palette_color(int it, int max);
extern void apply_palette_and_glyph(int it, int x, int y);
extern double time_tick;

// ─────────────────────────────────────────────────────────────
//  BANNER RENDERING
// ─────────────────────────────────────────────────────────────
// Banner can be overlay, mask, or cutout.
// cfg.banner holds UTF-8 Ogham or normal text.

// Measure banner width in graphemes
int banner_width() {
    return utf8_strlen(cfg.banner);
}

// Print a single banner character at position
void banner_put(const char *ch, int px, int py) {
    printf("[%d;%dH%s", py+1, px+1, ch);
}

// Render banner glyph with ANSI white
void banner_overlay_render(int row) {
    int bw = banner_width();
    int start = (cfg.width - bw) / 2;

    const char *s = cfg.banner;
    for (int i = 0, px = start; i < bw; i++, px++) {
        char tmp[8];
        int n = utf8_copy_char(tmp, s);
        s += n;
        printf("[38;2;255;255;255m");
        banner_put(tmp, px, row);
    }
}

// Mask mode: banner blocks fractal, uses black
void banner_mask_render(int row) {
    int bw = banner_width();
    int start = (cfg.width - bw) / 2;

    const char *s = cfg.banner;
    for (int i = 0, px = start; i < bw; i++, px++) {
        char tmp[8];
        int n = utf8_copy_char(tmp, s);
        s += n;
        printf("[48;2;0;0;0m[38;2;0;0;0m");
        banner_put(tmp, px, row);
        printf("[0m");
    }
}

// Cutout: fractal shows inside letters, background masked
void banner_cutout_render(int row) {
    int bw = banner_width();
    int start = (cfg.width - bw) / 2;

    const char *s = cfg.banner;
    for (int i = 0, px = start; i < bw; i++, px++) {
        char tmp[8]; int n = utf8_copy_char(tmp, s); s += n;
        printf("\033[38;2;255;255;255m");
        banner_put(tmp, px, row);
    }
}

// Dispatch
void render_banner_layer() {
    if (strlen(cfg.banner) == 0) return;

    int row = cfg.height / 2;
    if (cfg.banner_pos == 0) row = 1;
    if (cfg.banner_pos == 2) row = cfg.height - 2;

    switch (cfg.banner_mode) {
        case 1: banner_overlay_render(row); break;
        case 2: banner_mask_render(row); break;
        case 3: banner_cutout_render(row); break;
    }
}

// ─────────────────────────────────────────────────────────────
//  MAIN RENDER LOOP (ANIMATED BACKGROUND + OPTIONAL BANNER)
// ─────────────────────────────────────────────────────────────

void render_animated_background() {
    printf("\033[2J\033[H");

    for (int py = 0; py < cfg.height; py++) {
        for (int px = 0; px < cfg.width; px++) {
            double x = (px - cfg.width/2.0) * cfg.zoom;
            double y = (py - cfg.height/2.0) * cfg.zoom;

            int it = sample_fractal(x, y);
            apply_palette_and_glyph(it, px, py);
        }
        printf("\n");
    }
    fflush(stdout);
}

void render_frame() {
    render_animated_background();
    render_banner_layer();
}

// ─────────────────────────────────────────────────────────────
//  LOCKSCREEN MODE
// ─────────────────────────────────────────────────────────────
// Uses fractal as background + banner + unlock input

void run_lockscreen() {
    char buf[256] = {0};
    int pos = 0;
    time_t start = time(NULL);

    for (;;) {
        time_tick = (double)(clock() % 1000000) / CLOCKS_PER_SEC;
        render_frame();

        usleep(100000);

        char c;
        if (read(STDIN_FILENO, &c, 1) > 0) {
            if (c == 27) break; // ESC
            if (c == ' ') {
                const char *unlock = getenv("UNLOCK_CODE");
                if (!unlock) unlock = "";
                if (strcmp(buf, unlock) == 0) {
                    printf("\033[2J\033[H\033[32mAccess granted.\033[0m\n");
                    return;
                }
                pos = 0;
                buf[0] = 0;
                continue;
            }

            if (pos < 255) buf[pos++] = c;
            buf[pos] = 0;
        }

        if (time(NULL) - start > cfg.timeout) break;
    }
}


// ─────────────────────────────────────────────────────────────
//  PART 5 — ADVANCED EFFECTS (OGHAM RAIN, SIGIL CURTAINS, BLENDING)
// ─────────────────────────────────────────────────────────────

// This section adds optional effects that can be toggled or expanded.
// They do not affect lockscreen stability and can be run in standalone mode.

extern void render_animated_background();

// ─────────────────────────────────────────────────────────────
//  OGHAM RAIN — dripping glyphs from the top
// ─────────────────────────────────────────────────────────────

typedef struct {
    int x;
    int y;
    const char *glyph;
    int active;
    float speed;
} OghamDrop;

#define MAX_DROPS 64
static OghamDrop drops[MAX_DROPS];

void ogham_rain_init() {
    for (int i = 0; i < MAX_DROPS; i++) drops[i].active = 0;
}

void ogham_launch_drop() {
    for (int i = 0; i < MAX_DROPS; i++) {
        if (!drops[i].active) {
            drops[i].active = 1;
            drops[i].x = rand() % cfg.width;
            drops[i].y = 0;
            drops[i].glyph = ogham_glyphs[rand() % ogham_count];
            drops[i].speed = 0.3 + (rand() % 100) / 200.0;
            return;
        }
    }
}

void ogham_rain_update() {
    for (int i = 0; i < MAX_DROPS; i++) {
        if (drops[i].active) {
            drops[i].y += drops[i].speed;
            if (drops[i].y >= cfg.height) {
                drops[i].active = 0;
            }
        }
    }
}

void ogham_rain_render_layer() {
    for (int i = 0; i < MAX_DROPS; i++) {
        if (!drops[i].active) continue;
        int py = (int)drops[i].y;
        if (py < 0 || py >= cfg.height) continue;
        printf("\033[%d;%dH\033[38;2;200;255;200m%s", py+1, drops[i].x+1, drops[i].glyph);
    }
}

// ─────────────────────────────────────────────────────────────
//  SIGIL CURTAINS — vertical streams of symbols
// ─────────────────────────────────────────────────────────────

typedef struct {
    int x;
    int height;
    int active;
    const char *glyphSequence[16];
    int seqLen;
} SigilColumn;

#define MAX_SIGIL_COLUMNS 16
static SigilColumn sigils[MAX_SIGIL_COLUMNS];

void sigil_curtains_init() {
    for (int i = 0; i < MAX_SIGIL_COLUMNS; i++) {
        sigils[i].active = 0;
    }
}

void sigil_launch_column() {
    for (int i = 0; i < MAX_SIGIL_COLUMNS; i++) {
        if (!sigils[i].active) {
            sigils[i].active = 1;
            sigils[i].x = rand() % cfg.width;
            sigils[i].height = 3 + rand() % (cfg.height / 2);
            sigils[i].seqLen = 6;
            for (int j = 0; j < sigils[i].seqLen; j++) {
                sigils[i].glyphSequence[j] = ogham_glyphs[rand() % ogham_count];
            }
            return;
        }
    }
}

void sigil_curtains_render_layer() {
    for (int i = 0; i < MAX_SIGIL_COLUMNS; i++) {
        if (!sigils[i].active) continue;
        int col = sigils[i].x;
        for (int j = 0; j < sigils[i].height; j++) {
            const char *g = sigils[i].glyphSequence[j % sigils[i].seqLen];
            printf("\033[%d;%dH\033[38;2;180;180;255m%s", j+1, col+1, g);
        }
    }
}

// ─────────────────────────────────────────────────────────────
//  LAYERED RENDERER (BACKGROUND + OGHAM RAIN + CURTAINS)
// ─────────────────────────────────────────────────────────────

void render_multilayer() {
    render_animated_background();
    ogham_rain_render_layer();
    sigil_curtains_render_layer();
    render_banner_layer();
    fflush(stdout);
}

// ─────────────────────────────────────────────────────────────
//  MULTI-EFFECT LOOP
// ─────────────────────────────────────────────────────────────

void run_effects() {
    ogham_rain_init();
    sigil_curtains_init();

    while (1) {
        time_tick = (double)(clock() % 1000000) / CLOCKS_PER_SEC;

        if (rand() % 10 == 0) ogham_launch_drop();
        if (rand() % 60 == 0) sigil_launch_column();

        ogham_rain_update();

        render_multilayer();
        usleep(90000);
    }
}
