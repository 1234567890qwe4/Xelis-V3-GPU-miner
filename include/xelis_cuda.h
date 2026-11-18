#ifndef XELIS_CUDA_H
#define XELIS_CUDA_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int      device_id;
    char     name[256];
    int      sm_major;
    int      sm_minor;
    int      sm_count;
    size_t   total_vram;
    size_t   free_vram;
    uint32_t grid_blocks;
    uint32_t block_threads;
    uint64_t *d_scratchpads;
    uint8_t  *d_work;
    uint8_t  *d_target;
    uint64_t *d_found_nonce;
    uint8_t  *d_found_hash;
    int      *d_found_flag;
} xelis_cuda_ctx_t;

int  xelis_cuda_init(xelis_cuda_ctx_t *ctx, int gpu_id, int blocks, int threads_per_block);
void xelis_cuda_free(xelis_cuda_ctx_t *ctx);

/* Run one batch of nonces starting at start_nonce. Returns 1 if solution found, 0 if not, <0 on error */
int  xelis_cuda_mine_batch(xelis_cuda_ctx_t *ctx,
                           const uint8_t work112[112],
                           const uint8_t target_be[32],
                           uint64_t start_nonce,
                           uint64_t *out_nonce,
                           uint8_t out_hash[32],
                           uint32_t *out_hashes_done);

/* Run GPU self-test against official v3.rs test vectors (returns 0 on pass) */
int  xelis_cuda_selftest(int gpu_id);

#ifdef __cplusplus
}
#endif

#endif /* XELIS_CUDA_H */
