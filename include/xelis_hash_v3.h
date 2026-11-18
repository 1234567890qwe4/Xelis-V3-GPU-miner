#ifndef XELIS_HASH_V3_H
#define XELIS_HASH_V3_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XELIS_INPUT_LEN   112
#define XELIS_HASH_SIZE   32
#define XELIS_MEMSIZE     (531 * 128)           /* 67,968 uint64_t */
#define XELIS_OUTPUT_SIZE (XELIS_MEMSIZE * 8)   /* 543,744 bytes (~531 KiB) */
#define XELIS_BUFSIZE     (XELIS_MEMSIZE / 2)   /* 33,984 uint64_t */
#define XELIS_ITERS       2

/* Compute BLAKE3 32-byte digest (used for Xelis MinerWork block_hash) */
void xelis_blake3_hash(const uint8_t *input, size_t len, uint8_t output[32]);

/* Compute XelisHash V3 on CPU (requires caller-allocated scratchpad of XELIS_MEMSIZE uint64_t) */
void xelis_hash_v3_cpu(const uint8_t input[XELIS_INPUT_LEN],
                       uint8_t hash[XELIS_HASH_SIZE],
                       uint64_t scratch[XELIS_MEMSIZE]);

/* Verify CPU implementation against official v3.rs test vectors (returns 0 on pass) */
int xelis_hash_v3_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* XELIS_HASH_V3_H */
