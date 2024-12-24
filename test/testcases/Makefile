# Compiler (cross-compile with `CC=arm-linux-gcc make`) and compiler flags
CC    ?= gcc
CFLAGS = -Wall -O3 -fno-builtin -fno-optimize-sibling-calls

# Source and binary files (in the current directory)
SOURCES = $(wildcard *.c)
BINARIES = $(SOURCES:.c=.elf)

# Prevent make from confusing targets `all` and `clean` with a file name
.PHONY: all clean

# Build all binaries by default
all: $(BINARIES)

# Compile each source file into a binary with .elf extension
%.elf: %.c
	$(CC) $(CFLAGS) $< -o $@

# Remove binaries
clean:
	rm -f $(BINARIES)