EXE = miner
CC = gcc

SRC =
SRC += ocl.c
SRC += main.c

HEADERS = $(wildcard *.h)

LIBS = -lcurl -ljansson -lOpenCL

OBJS = $(patsubst %.c,%.o,$(SRC))
BUILD_OBJS = $(patsubst %.c,build/%.o,$(SRC))
BUILD_DIR = build

FLAGS = -g -Wall -Wextra -D CL_TARGET_OPENCL_VERSION=300

all: $(BUILD_DIR) $(EXE) 

$(EXE): $(BUILD_OBJS)
	$(CC) $^ $(FLAGS) $(LIBS) -o $@

build/%.o: %.c $(HEADERS)
	$(CC) -c $(FLAGS) $<
	mv $*.o build/$*.o

run: $(EXE)
	./$(EXE)

$(BUILD_DIR):
	mkdir -p $@

.PHONY: clean
clean:
	$(RM) *.o
	$(RM) *.out
	$(RM) -r build
	$(RM) $(EXE)

