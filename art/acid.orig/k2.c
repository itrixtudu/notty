#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

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

static void print_help(const char *prog) {
    printf(
        "Usage: %s <splash.ans>\n"
        "\n"
        "A minimal ANSI splash screen + unlock gate.\n"
        "Displays an ANSI art file, cycles subtle colors,\n"
        "and requires a secret unlock code before proceeding.\n"
        "\n"
        "Arguments:\n"
        "  splash.ans       Path to ANSI/ASCII art file to display.\n"
        "\n"
        "Environment Variables:\n"
        "  UNLOCK_CODE      The expected code. Default: empty string.\n"
        "\n"
        "Controls:\n"
        "  ENTER            Submit unlock code.\n"
        "  ESC              Reset & re-show art.\n"
        "\n"
        "Behavior:\n"
        "  • Raw mode input (no echo)\n"
        "  • Pulsing color cycle\n"
        "  • 12-second inactivity timeout\n"
        "  • No file writes; unlock evaluated in-memory\n"
        "\n",
        prog
    );
}

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

static void draw_art(const char *art, int pulse) {
    printf("\033[2J\033[H");                   // clear screen
    printf("\033[%dm", 30 + (pulse % 8));     // subtle color cycle
    printf("%s\033[0m", art);
    printf("\n\n\033[37m[ press ENTER to unlock | ESC to cancel ]\033[0m\n");
    fflush(stdout);
}

int main(int argc, char **argv) {

    // --- Help flags ---------------------------------------------------------
    if (argc >= 2 && 
        (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        print_help(argv[0]);
        return 0;
    }

    // --- Require splash file ------------------------------------------------
    if (argc < 2) {
        fprintf(stderr, "Usage: %s splash.ans\n", argv[0]);
        return 1;
    }

    const char *unlock = getenv("UNLOCK_CODE");
    if (!unlock) unlock = "";  // fallback empty

    char *art = load_file(argv[1]);
    if (!art) {
        fprintf(stderr, "Error: could not read splash: %s\n", argv[1]);
        return 1;
    }

    // --- Enter lock mode ----------------------------------------------------
    raw_mode();
    char buf[256];

    for (;;) {
        memset(buf, 0, sizeof(buf));
        int pos = 0;
        int pulse = 0;
        time_t start = time(NULL);

        for (;;) {
            draw_art(art, pulse++);
            usleep(120000);

            char c;
            ssize_t n = read(STDIN_FILENO, &c, 1);

            if (n > 0) {
                if (c == 27) {        // ESC → reset lock
                    break;
                }
                if (c == '\n') {      // ENTER
                    if (strcmp(buf, unlock) == 0) {
                        printf("\033[2J\033[H\033[32mAccess granted.\033[0m\n");
                        free(art);
                        return 0;
                    }
                    break;            // wrong code → reset
                }
                if (pos < (int)sizeof(buf) - 1) {
                    buf[pos++] = c;
                }
            }

            if (time(NULL) - start > 12)
                break;  // timeout → restart
        }
    }

    free(art);
    return 0;
}

