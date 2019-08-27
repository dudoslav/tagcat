CFLAGS=-std=c99 -Wall -Wextra -pedantic

all: tagcat

install: all
	install -m 755 -s -D tagcat ${DESTDIR}${PREFIX}/usr/bin/tagcat

tagcat: tagcat.c
	$(CC) $(CFLAGS) -o tagcat tagcat.c

