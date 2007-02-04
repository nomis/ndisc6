CC = gcc -std=gnu99
CFLAGS = -g -O0 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 -DHAVE_CONFIG_H=1 -I.
TARGETS = ezirad
ezirad_SOURCES = ezirad.c sys_netlink.c ezirad.h

LIBNL_1_CFLAGS = $(shell pkg-config --cflags libnl-1)
LIBNL_1_LDFLAGS = $(shell pkg-config --libs libnl-1)
CFLAGS += $(LIBNL_1_CFLAGS)
LDFLAGS += $(LIBNL_1_LDFLAGS)

all: $(TARGETS)

mostlyclean:
	rm -f *.o $(TARGETS)

ezirad: $(filter %.o, $(ezirad_SOURCES:%.c=%.o))

clean: mostlyclean

.PHONY: all clean mostlyclean

