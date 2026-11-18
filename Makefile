CC      ?= gcc
NVCC    ?= nvcc
CFLAGS  := -O3 -std=c99 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Iinclude
LDFLAGS := -lssl -lcrypto -lm -lpthread

CUDA_GENCODE ?= \
  -gencode arch=compute_75,code=sm_75 \
  -gencode arch=compute_80,code=sm_80 \
  -gencode arch=compute_86,code=sm_86 \
  -gencode arch=compute_89,code=sm_89 \
  -gencode arch=compute_90a,code=sm_90a \
  -gencode arch=compute_100a,code=sm_100a \
  -gencode arch=compute_120a,code=sm_120a

CORE_SRCS := src/miner_common.c src/miner_net.c src/xelis_hash_v3_ref.c src/xelis_v3_oracle.c

.PHONY: all cuda cpu clean test

all: cuda

cuda:
	$(NVCC) -O3 -DUSE_CUDA -Iinclude $(CUDA_GENCODE) -Xptxas -v -Xcompiler "-O3" \
		src/main.c $(CORE_SRCS) src/xelis_v3_kernel.cu -o xelis-v3-miner $(LDFLAGS)
	$(NVCC) -O3 -DUSE_CUDA -Iinclude $(CUDA_GENCODE) -Xptxas -v -Xcompiler "-O3" \
		src/hashgen_main.c $(CORE_SRCS) src/xelis_v3_kernel.cu -o xelis-v3-hashgen $(LDFLAGS)

cpu:
	$(CC) $(CFLAGS) src/main.c $(CORE_SRCS) -o xelis-v3-miner-cpu $(LDFLAGS)
	$(CC) $(CFLAGS) src/hashgen_main.c $(CORE_SRCS) -o xelis-v3-hashgen-cpu $(LDFLAGS)

test: cpu
	./xelis-v3-miner-cpu --selftest
	./xelis-v3-hashgen-cpu --selftest
	./xelis-v3-hashgen-cpu --generate --diff 32 --count 2 --json
	$(CC) $(CFLAGS) tests/test_oracle_and_protocols.c $(CORE_SRCS) -o build/test_oracle_and_protocols $(LDFLAGS)
	./build/test_oracle_and_protocols

clean:
	rm -f xelis-v3-miner xelis-v3-miner-cpu xelis-v3-hashgen xelis-v3-hashgen-cpu build/test_oracle_and_protocols
