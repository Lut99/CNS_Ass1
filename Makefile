# GUESSWORD - MAKEFILE
#   by HACKER_HANDLE
#
# A Makefile to simplify compilation (and subsequent cleanup) of guessword.c.
#

### CONSTANTS ###
GCC := gcc
GCC_ARGS := -O2 -Wall -Wextra -std=c11

SRC := .
BIN := bin
OBJ := $(BIN)/obj

### INPUT ###
ifdef DEBUG
GCC_ARGS += -g -DDEBUG
endif

### PHONY RULES ###
.PHONY: default all clean guessword test
default: all

all: guessword test
clean:
	find $(BIN) -type f -executable -delete
	rm -f $(OBJ)/*.o

### DIRECTORY RULES ###
$(BIN):
	mkdir -p $@
$(OBJ): $(BIN)
	mkdir -p $@

### COMPILATION RULES ###

# Normal guessword
$(OBJ)/guessword.o: $(SRC)/guessword.c | $(OBJ)
	$(GCC) $(GCC_ARGS) -o $@ -c $<
$(BIN)/guessword.out: $(OBJ)/guessword.o | $(BIN)
	$(GCC) $(GCC_ARGS) -pthread -o $@ $^ -lcrypt -lpthread
guessword: $(BIN)/guessword.out

# Guessword using the assignment's requirements
$(BIN)/guessword: $(SRC)/guessword.c | $(BIN)
	gcc -O3 -Wall -Wextra -pthread -o $@ $< -lcrypt -lpthread
test: $(BIN)/guessword
