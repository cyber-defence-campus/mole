# Compiler (cross-compile with `CC=arm-linux-gcc make`) and compiler flags
CC    ?= gcc
CFLAGS = -Wall -O3 -fno-builtin

# Source and binary files (in the current directory)
SOURCES = $(wildcard *.c)
BINARIES = $(SOURCES:.c=)

# Prevent make from confusing targets `all` and `clean` with a file name
.PHONY: all clean

# Build all binaries by default
all: $(BINARIES)

# Compile each source file into a binary
%: %.c
	$(CC) $(CFLAGS) $< -o $@.elf

# Remove binaries
clean:
	rm -f $(BINARIES)