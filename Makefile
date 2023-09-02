EXE = miner

SRC =
SRC += main.c

LIBS = -lcurl

OBJS = $(patsubst %.c,%.o,$(SRC))
BUILD_OBJS = $(patsubst %.c,build/%.o,$(SRC))

all: $(EXE)

$(EXE): $(BUILD_OBJS)
	gcc $^ $(LIBS) -o $@

$(BUILD_OBJS): $(SRC)
	mkdir -p build
	gcc -c $^
	mv $(OBJS) build

run: $(EXE)
	./$(EXE)

.PHONY: clean
clean:
	$(RM) -f *.o
	$(RM) -f *.out

