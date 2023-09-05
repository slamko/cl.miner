EXE = miner
CC = gcc

SRC =
SRC += ocl.c
SRC += main.c

HEADERS = $(wildcard *.h)

LIBS = -lcurl -ljansson -lOpenCL

OBJS = $(patsubst %.c,%.o,$(SRC))
BUILD_OBJS = $(patsubst %.c,build/%.o,$(SRC))

FLAGS = -g -Wall -Wextra -D CL_TARGET_OPENCL_VERSION=300

all: $(EXE)

$(EXE): $(BUILD_OBJS)
	$(CC) $^ $(FLAGS) $(LIBS) -o $@

$(BUILD_OBJS): $(SRC) $(HEADERS)
	mkdir -p build
	$(CC) -c $(FLAGS) $(SRC)
	mv $(OBJS) build

run: $(EXE)
	./$(EXE)

.PHONY: clean
clean:
	$(RM) -f *.o
	$(RM) -f *.out

