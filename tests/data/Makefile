# Compilation settings (cross-compile with `CC=arm-linux-gcc CXX=arm-linux-g++ EXT=.linux-armv7 make`)
CC      	?= gcc
CXX			?= g++
CFLAGS  	?= -Wall -O3 -g -fno-builtin -U_FORTIFY_SOURCE
CXXFLAGS	?= -Wall -O3 -g -fno-builtin -U_FORTIFY_SOURCE
EXT     	?=

# Directories
SRC_DIR := src
BIN_DIR := bin

# Files
C_SRC_FILES   := $(wildcard $(SRC_DIR)/*.c)
C_BIN_FILES   := $(patsubst $(SRC_DIR)/%.c, $(BIN_DIR)/%$(EXT), $(C_SRC_FILES))
CPP_SRC_FILES := $(wildcard $(SRC_DIR)/*.cpp)
CPP_BIN_FILES := $(patsubst $(SRC_DIR)/%.cpp, $(BIN_DIR)/%$(EXT), $(CPP_SRC_FILES))

# Ensure directory bin/ exists
$(shell mkdir -p bin)

# Default target
all: $(C_BIN_FILES) $(CPP_BIN_FILES)

# Compile .c files
$(BIN_DIR)/%$(EXT): $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -o $@ $<

# Compile .cpp files
$(BIN_DIR)/%$(EXT): $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

# Remove binaries
clean:
	rm -rf $(BIN_DIR)

# Compile a single program
$(notdir $(basename $(C_SRC_FILES) $(CPP_SRC_FILES))): %: $(BIN_DIR)/%$(EXT)

# Prevent make from confusing targets with a file names
.PHONY: all $(notdir $(basename $(C_SRC_FILES) $(CPP_SRC_FILES))) clean