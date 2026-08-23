#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <math.h>

//
// ──────────────────────────────────────────────────────────
//   RAW MODE HANDLING
// ──────────────────────────────────────────────────────────
//

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

//
// ──────────────────────────────────────────────────────────
//   FILE LOADING
// ──────────────────────────────────────────────────────────
//

static char* load_file(const char *path) {
    struct stat st;
    if (stat(path, &st) < 0) return NULL;

    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    char *buf = malloc(st.st_size + 1);
    fread(buf, 1, st.st_size, f);
    buf[st.st_size] = '\0';
    fclose(f);
    return buf;
}

//
// ──────────────────────────────────────────────────────────
//   ANSI FIRE PALETTE (RED → YELLOW → WHITE)
// ──────────────────────────────────────────────────────────
//

static inline void fire_color(int iters, int max) {
    float t = (float)iters / max;

    // Red → Yellow → White
    int r = 255;
    int g = (int)(t * 255);
    int b = (int)(t * 80);

    printf("\033[38;2;%d;%d;%dm", r, g, b);
}

//
// ──────────────────────────────────────────────────────────
//   FRACTAL GENERATION (MANDELBROT & JULIA)
// ──────────────────────────────────────────────────────────
//

// Mandelbrot formula
static int mandelbrot(double x0, double y0, int maxIter) {
    double x = 0, y = 0;
    int iter = 0;
    while (x*x + y*y <= 4 && iter < maxIter) {
        double xt = x*x - y*y + x0;
        y = 2*x*y + y0;
        x = xt;
        iter++;
    }
    return iter;
}

// Julia formula
static int julia(double x, double y, int maxIter, double cx, double cy) {
    int iter = 0;
    while (x*x + y*y <= 4 && iter < maxIter) {
        double xt = x*x - y*y + cx;
        y = 2*x*y + cy;
        x = xt;
        iter++;
    }
    return iter;
}

//
// ──────────────────────────────────────────────────────────
//   FRACTAL RENDERING
// ──────────────────────────────────────────────────────────
//

static void draw_fractal(int useJulia) {
    printf("\033[2J\033[H");

    int maxIter = 80;
    int width = 90;
    int height = 40;

    double cx = -0.7;   // Julia constants
    double cy = 0.27015;

    for (int py = 0; py < height; py++) {
        double y = (py - height/2.0) * 0.035;

        for (int px = 0; px < width; px++) {
            double x = (px - width/2.0) * 0.035;

            int it = useJulia
                ? julia(x, y, maxIter, cx, cy)
                : mandelbrot(x, y, maxIter);

            fire_color(it, maxIter);

            putchar(it == maxIter ? ' ' : '#');
        }
        printf("\033[0m\n");
    }

    printf("\n\033[37m[ press ENTER to unlock | ESC to cancel ]\033[0m\n");
}

//
// ──────────────────────────────────────────────────────────
//   STATIC ANSI ART RENDERING
// ──────────────────────────────────────────────────────────
//

static void draw_art(const char *art, int pulse) {
    printf("\033[2J\033[H");
    printf("\033[%dm", 30 + (pulse % 7));
    printf("%s\033[0m", art);
    printf("\n\n\033[37m[ press ENTER to unlock | ESC to cancel ]\033[0m\n");
}


//
// ──────────────────────────────────────────────────────────
//   HELP MENU
// ──────────────────────────────────────────────────────────
//
static void show_help(const char *self) {
    printf(
        "Usage: %s [options] [splash.ans]\n"
        "\n"
        "Options:\n"
        "  --help           Show this help\n"
        "  --mandelbrot     Use animated Mandelbrot fractal\n"
        "  --julia          Use animated Julia fractal (fire palette)\n"
        "\n"
        "If a .ans file is provided, that art is shown instead.\n"
        "Unlock code is read from UNLOCK_CODE environment variable.\n"
        "\n",
        self
    );
}

//
// ──────────────────────────────────────────────────────────
//   MAIN
// ──────────────────────────────────────────────────────────
//

int main(int argc, char **argv) {
    int useFractal = 0;
    int useJulia = 0;
    const char *file = NULL;

    // Argument parsing
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--help")) {
            show_help(argv[0]);
            return 0;
        }
        if (!strcmp(argv[i], "--mandelbrot")) {
            useFractal = 1;
            useJulia = 0;
        }
        else if (!strcmp(argv[i], "--julia")) {
            useFractal = 1;
            useJulia = 1;
        }
        else {
            file = argv[i];
        }
    }

    const char *unlock = getenv("UNLOCK_CODE");
    if (!unlock) unlock = "";

    raw_mode();
    char input[256];

    char *art = NULL;
    if (file && !useFractal)
        art = load_file(file);

    for (;;) {
        memset(input, 0, sizeof(input));
        int pos = 0;
        time_t start = time(NULL);

        for (;;) {
            if (useFractal)
                draw_fractal(useJulia);
            else
                draw_art(art, pos);

            usleep(100000);

            char c;
            if (read(STDIN_FILENO, &c, 1) > 0) {
                if (c == 27) break;            // ESC resets
                if (c == '\n') {
                    if (strcmp(input, unlock) == 0) {
                        printf("\033[2J\033[H\033[32mAccess granted.\033[0m\n");
                        free(art);
                        return 0;
                    }
                    break;
                }
                if (pos < 255) input[pos++] = c;
            }

            if (time(NULL) - start > 12)
                break;
        }
    }

    free(art);
    return 0;
}

