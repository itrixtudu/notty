#include <stdio.h>
#include <math.h>
#include <unistd.h>

#define W 120
#define H 40
#define MAX 64

double palette_shift = 0.0;

//double cx = sin(t * 0.03) * 0.7;
//double cy = cos(t * 0.05) * 0.7;

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

int mand(double x0, double y0) {
    double x = 0, y = 0;
    int it = 0;
    while (x*x + y*y < 4 && it < MAX) {
        double xt = x*x - y*y + x0;
        y = 2*x*y + y0;
        x = xt;
        it++;
    }
    return it;
}

void draw_frame(double cx, double cy, double zoom) {
    printf("\033[H");  // cursor home
    for (int j = 0; j < H; j++) {
        for (int i = 0; i < W; i++) {

            double x0 = cx + (i - W/2) * zoom;
            double y0 = cy + (j - H/2) * zoom;

            int it = mand(x0, y0);
    //        int it = julia(x0, y0);

            int color = (int)((it + palette_shift)) % 256;
            printf("\033[38;5;%dm", color);

            putchar(it == MAX ? '@' : '.');
        }
        printf("\n");
    }
}

int main() {
    printf("\033[2J"); // clear
    double zoom = 0.015;
    double cx = -0.7, cy = 0.0;

    for (;;) {
        draw_frame(cx, cy, zoom);
        palette_shift += 1.5;
        usleep(30000); // 30ms per frame
    }

    return 0;
}

