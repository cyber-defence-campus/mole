# Compiler (cross-compile with `CC=arm-linux-gcc EXT=.linux-armv7 make`) and compiler flags
CC     ?= gcc
CFLAGS ?= -Wall -O3 -g -fno-builtin -U_FORTIFY_SOURCE
EXT    ?=

# Source and binary files
SOURCES = $(wildcard *.c)
BINARIES = $(SOURCES:.c=$(EXT))

# Ensure bin/ directory exists
$(shell mkdir -p bin)

# Prevent make from confusing targets `all` and `clean` with a file name
.PHONY: all clean

# Build all binaries by default
all: $(BINARIES)

# Compile each source file into a binary
%$(EXT): %.c
	$(CC) $(CFLAGS) $< -o bin/$@

# Remove binaries
clean:
	rm -f $(addprefix bin/,$(BINARIES))