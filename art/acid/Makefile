
# Rebuilt with gcc main.c -lm -o klock. Now only an external kill -9 (e.g., from root in the container) can terminate it.
# yea I'm not writing a make file a 6:42am - so gpt 5.1 was a peach and wrote one for me after I slept
# still mild internal bleeding, I hope this isn't the last creation I make before I klock out :P  

CC=gcc
CFLAGS=-Wall -Wextra -O2
LDLIBS=-lm

TARGET=klock
SRC=main.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDLIBS)

clean:
	rm -f $(TARGET)
