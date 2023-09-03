EXE = miner
CC = gcc

SRC =
SRC += ocl.c
SRC += main.c

LIBS = -lcurl -ljansson -lOpenCL

OBJS = $(patsubst %.c,%.o,$(SRC))
BUILD_OBJS = $(patsubst %.c,build/%.o,$(SRC))

FLAGS = -D CL_TARGET_OPENCL_VERSION=300

all: $(EXE)

$(EXE): $(BUILD_OBJS)
	$(CC) $^ $(FLAGS) $(LIBS) -o $@

$(BUILD_OBJS): $(SRC)
	mkdir -p build
	$(CC) -c $(FLAGS) $^
	mv $(OBJS) build

run: $(EXE)
	./$(EXE)

.PHONY: clean
clean:
	$(RM) -f *.o
	$(RM) -f *.out

