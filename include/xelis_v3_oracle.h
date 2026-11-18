#ifndef XELIS_V3_ORACLE_H
#define XELIS_V3_ORACLE_H

#include <stdint.h>
#include <stddef.h>

#ifdef USE_CUDA
  #include "xelis_cuda.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int      use_gpu;
    int      cpu_verify;
    int      gpu_id;
    int      blocks;
    int      threads_per_block;
    uint64_t *cpu_scratch;
#ifdef USE_CUDA
    xelis_cuda_ctx_t cuda_ctx;
    int      cuda_ready;
#endif
} xelis_oracle_t;

typedef struct {
    uint64_t nonce;
    uint8_t  pow_hash[32];
    uint8_t  block_hash[32];
    uint8_t  solved_work[112];
    uint64_t hashes_evaluated;
} xelis_oracle_result_t;

/* Initialize the Xelis-V3 Hash Generator / Equivalent Oracle (CPU or CUDA GPU).
 * Returns 0 on success, <0 on failure. */
int xelis_oracle_init(xelis_oracle_t *oracle,
                      int use_gpu,
                      int gpu_id,
                      int blocks,
                      int threads_per_block,
                      int cpu_verify);

/* Free all host/device resources held by the oracle. */
void xelis_oracle_free(xelis_oracle_t *oracle);

/* Compute the exact Xelis-V3 PoW hash and BLAKE3 block hash for a 112-byte MinerWork.
 * If nonce != UINT64_MAX, injects big-endian nonce at bytes [40..47] first.
 * Returns 0 on success, <0 on error. */
int xelis_oracle_hash(xelis_oracle_t *oracle,
                      const uint8_t work112[112],
                      uint64_t nonce,
                      uint8_t out_pow_hash[32],
                      uint8_t out_block_hash[32],
                      uint8_t out_solved_work[112]);

/* Generate a legal nonce whose Xelis-V3 PoW hash meets target_be (pow_hash <= target_be).
 * Evaluates continuously from start_nonce until found (or max_attempts reached if > 0).
 * Returns 1 when a legal nonce is generated, 0 if max_attempts exhausted, <0 on error. */
int xelis_oracle_generate_legal_nonce(xelis_oracle_t *oracle,
                                      const uint8_t base_work112[112],
                                      const uint8_t target_be[32],
                                      uint64_t start_nonce,
                                      uint64_t max_attempts,
                                      xelis_oracle_result_t *out_res);

/* Independently verify a generated oracle result against Xelis-V3 consensus rules:
 * - solved_work[40..47] == big-endian res->nonce
 * - XelisHashV3(solved_work) == res->pow_hash
 * - pow_hash <= target_be
 * - BLAKE3(solved_work) == res->block_hash
 * Returns 0 if valid, <0 if invalid. */
int xelis_oracle_branch_verify(const xelis_oracle_result_t *res,
                               const uint8_t target_be[32]);

#ifdef __cplusplus
}
#endif

#endif /* XELIS_V3_ORACLE_H */
