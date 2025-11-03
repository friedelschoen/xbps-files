CC      = cc
CFLAGS  = -std=gnu99 -Wall -Wextra -O2 -g
LDFLAGS =
TARGETS = xbps-provides xbps-provides-db
HEADERS = arg.h
PREFIX  = /usr/local
PKGS 	= libgit2 libxbps

CFLAGS += $(shell pkg-config --cflags $(PKGS))
LDFLAGS += $(shell pkg-config --libs $(PKGS))

all: $(TARGETS) $(MANUALS)

%: %.c $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

compile_flags.txt:
	echo $(CFLAGS) | tr ' ' '\n' > $@

clean:
	rm -f $(TARGETS) $(MANUALS) compile_flags.txt

install: $(TARGETS) $(MANUALS)
	install -d $(PREFIX)/bin
	install -m 0755 $(TARGETS) $(PREFIX)/bin
