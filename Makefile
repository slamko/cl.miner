EXE = miner
CC = gcc
SRC_DIR = src

SRC =
SRC += $(SRC_DIR)/ocl.c
SRC += $(SRC_DIR)/util.c
SRC += $(SRC_DIR)/rpc.c
SRC += $(SRC_DIR)/bip.c
SRC += $(SRC_DIR)/main.c

HEADERS = $(wildcard $(SRC_DIR)/*.h)

LIBS = -lcurl -ljansson -lOpenCL

BUILD_OBJS = $(patsubst $(SRC_DIR)/%.c,build/%.o,$(SRC))
BUILD_DIR = build

FLAGS = -g -Wall -Wextra -D CL_TARGET_OPENCL_VERSION=300

all: $(BUILD_DIR) $(EXE) 

$(EXE): $(BUILD_OBJS)
	$(CC) $^ $(FLAGS) $(LIBS) -o $@

build/%.o: src/%.c $(HEADERS)
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

