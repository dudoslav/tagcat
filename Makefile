tagcat: tagcat.c
	$(CC) $(CFLAGS) -o tagcat tagcat.c

all: tagcat

CFLAGS=--std=c99 -Wall -Wextra -pedantic
