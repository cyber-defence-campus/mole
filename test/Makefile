# Compilation settings (cross-compile with `CC=arm-linux-gcc EXT=.linux-armv7 make`)
CC      ?= gcc
CFLAGS  ?= -Wall -O3 -g -fno-builtin -U_FORTIFY_SOURCE
EXT     ?=

# Directories
SRC_DIR := ./src
BIN_DIR := ./bin

# Files
SRC_FILES := $(wildcard $(SRC_DIR)/*.c)
BIN_FILES := $(patsubst $(SRC_DIR)/%.c, $(BIN_DIR)/%$(EXT), $(SRC_FILES))

# Ensure directory bin/ exists
$(shell mkdir -p bin)

# Default target
all: $(BIN_FILES)

# Compile all other targets
$(BIN_DIR)/%$(EXT): $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -o $@ $<

# Remove binaries
clean:
	rm -rf $(BIN_DIR)

# Compile a single program
$(notdir $(basename $(SRC_FILES))): %: $(BIN_DIR)/%$(EXT)

# Prevent make from confusing targets with a file names
.PHONY: all $(notdir $(basename $(SRC_FILES))) clean