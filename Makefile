#!/usr/bin/make -f

CC=gcc
CFLAGS=-Wall -g
LDFLAGS=
#LD=ld

TARGETS=ndisc

all: $(TARGETS)

$(TARGETS): %: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

.PHONY: clean all

