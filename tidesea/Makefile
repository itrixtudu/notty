CC = cc
CFLAGS = -std=c17 -Wall -Wextra -Wpedantic -O2

.PHONY: all run clean

all: hello

hello: hello.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

run: hello
	./hello

clean:
	rm -f hello
