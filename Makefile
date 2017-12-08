
BLAKE2_dir = BLAKE2/sse
BLAKE2_imp = blake2b.c
TEST_dir = test/

CC         = gcc
CFLAGS     = -O3 -march=native

all: basicSolver basicSolver-opt

basicSolver: basicSolver.c
	$(CC) -std=c99 -I$(BLAKE2_dir) $(CFLAGS) -o $@ $< $(BLAKE2_dir)/$(BLAKE2_imp)

basicSolver-opt: basicSolver-opt.c
	$(CC) -std=c99 -I$(BLAKE2_dir) -I$(TEST_dir) $(CFLAGS) -o $@ $< $(BLAKE2_dir)/$(BLAKE2_imp) test/bucket_sort.c

clean:
	-rm -f basicSolver basicSolver-opt
