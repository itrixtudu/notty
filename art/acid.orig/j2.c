#include <stdio.h>
#include <math.h>
#include <unistd.h>

#define W 120
#define H 40
#define MAX 64

int julia(double x, double y, double cx, double cy) {
    int it = 0;
    while (x*x + y*y < 4 && it < MAX) {
        double xt = x*x - y*y + cx;
        y = 2*x*y + cy;
        x = xt;
        it++;
    }
    return it;
}

void draw_frame(double cx, double cy, double zoom) {
    printf("\033[H"); // cursor home

    for (int j = 0; j < H; j++) {
        for (int i = 0; i < W; i++) {

            double x0 = (i - W / 2) * zoom;
            double y0 = (j - H / 2) * zoom;

            int it = julia(x0, y0, cx, cy);

            int color = (it * 8) % 256;
            printf("\033[38;5;%dm", color);
            putchar(it == MAX ? '@' : '.');
        }
        printf("\n");
    }
}

int main() {
    printf("\033[2J");

    double cx = -0.7;
    double cy = 0.27015;
    double zoom = 0.015;

    for (;;) {
        draw_frame(cx, cy, zoom);

        // animate the Julia seed slightly
        cx += 0.0015;
        cy += 0.0009;

        usleep(40000);
    }
}

