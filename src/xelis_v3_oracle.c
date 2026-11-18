#include "xelis_v3_oracle.h"
#include "xelis_hash_v3.h"
#include "miner_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int xelis_oracle_init(xelis_oracle_t *oracle,
                      int use_gpu,
                      int gpu_id,
                      int blocks,
                      int threads_per_block,
                      int cpu_verify) {
    if (!oracle) return -1;
    memset(oracle, 0, sizeof(*oracle));
    oracle->use_gpu = use_gpu;
    oracle->gpu_id = gpu_id;
    oracle->blocks = blocks;
    oracle->threads_per_block = (threads_per_block > 0) ? threads_per_block : 64;
    oracle->cpu_verify = cpu_verify;

    oracle->cpu_scratch = (uint64_t *)calloc(XELIS_MEMSIZE, sizeof(uint64_t));
    if (!oracle->cpu_scratch) return -1;

#ifdef USE_CUDA
    if (use_gpu) {
        if (xelis_cuda_init(&oracle->cuda_ctx, gpu_id, blocks, oracle->threads_per_block) == 0) {
            oracle->cuda_ready = 1;
        } else {
            fprintf(stderr, "[ORACLE] CUDA init failed on GPU %d, using pure-C CPU oracle\n", gpu_id);
            oracle->use_gpu = 0;
        }
    }
#else
    oracle->use_gpu = 0;
#endif
    return 0;
}

void xelis_oracle_free(xelis_oracle_t *oracle) {
    if (!oracle) return;
#ifdef USE_CUDA
    if (oracle->cuda_ready) {
        xelis_cuda_free(&oracle->cuda_ctx);
        oracle->cuda_ready = 0;
    }
#endif
    if (oracle->cpu_scratch) {
        free(oracle->cpu_scratch);
        oracle->cpu_scratch = NULL;
    }
    memset(oracle, 0, sizeof(*oracle));
}

int xelis_oracle_hash(xelis_oracle_t *oracle,
                      const uint8_t work112[112],
                      uint64_t nonce,
                      uint8_t out_pow_hash[32],
                      uint8_t out_block_hash[32],
                      uint8_t out_solved_work[112]) {
    if (!oracle || !oracle->cpu_scratch || !work112 || !out_pow_hash) return -1;

    uint8_t local_work[112];
    memcpy(local_work, work112, 112);
    if (nonce != UINT64_MAX) {
        for (int k = 0; k < 8; k++) {
            local_work[40 + k] = (uint8_t)(nonce >> (56 - k * 8));
        }
    }

    xelis_hash_v3_cpu(local_work, out_pow_hash, oracle->cpu_scratch);
    if (out_block_hash) {
        xelis_blake3_hash(local_work, 112, out_block_hash);
    }
    if (out_solved_work) {
        memcpy(out_solved_work, local_work, 112);
    }
    return 0;
}

int xelis_oracle_generate_legal_nonce(xelis_oracle_t *oracle,
                                      const uint8_t base_work112[112],
                                      const uint8_t target_be[32],
                                      uint64_t start_nonce,
                                      uint64_t max_attempts,
                                      xelis_oracle_result_t *out_res) {
    if (!oracle || !oracle->cpu_scratch || !base_work112 || !target_be || !out_res) return -1;

    uint64_t cur_nonce = start_nonce;
    uint64_t evaluated = 0;

    while (max_attempts == 0 || evaluated < max_attempts) {
#ifdef USE_CUDA
        if (oracle->use_gpu && oracle->cuda_ready) {
            uint64_t found_nonce = 0;
            uint8_t found_hash[32];
            uint32_t batch_done = 0;
            int rc = xelis_cuda_mine_batch(&oracle->cuda_ctx,
                                           base_work112,
                                           target_be,
                                           cur_nonce,
                                           &found_nonce,
                                           found_hash,
                                           &batch_done);
            if (rc < 0) return -1;
            evaluated += batch_done;
            cur_nonce += batch_done;

            if (rc == 1) {
                uint8_t solved[112];
                memcpy(solved, base_work112, 112);
                for (int k = 0; k < 8; k++) {
                    solved[40 + k] = (uint8_t)(found_nonce >> (56 - k * 8));
                }

                if (oracle->cpu_verify) {
                    uint8_t verify_hash[32];
                    xelis_hash_v3_cpu(solved, verify_hash, oracle->cpu_scratch);
                    if (memcmp(verify_hash, found_hash, 32) != 0 ||
                        !hash_meets_target(verify_hash, target_be)) {
                        fprintf(stderr, "[ORACLE] GPU/CPU verification mismatch on nonce %llu, continuing...\n",
                                (unsigned long long)found_nonce);
                        continue;
                    }
                }

                out_res->nonce = found_nonce;
                memcpy(out_res->pow_hash, found_hash, 32);
                memcpy(out_res->solved_work, solved, 112);
                xelis_blake3_hash(solved, 112, out_res->block_hash);
                out_res->hashes_evaluated = evaluated;
                return 1;
            }
            continue;
        }
#endif
        uint8_t work[112];
        uint8_t pow_hash[32];
        memcpy(work, base_work112, 112);
        for (int k = 0; k < 8; k++) {
            work[40 + k] = (uint8_t)(cur_nonce >> (56 - k * 8));
        }

        xelis_hash_v3_cpu(work, pow_hash, oracle->cpu_scratch);
        evaluated++;

        if (hash_meets_target(pow_hash, target_be)) {
            out_res->nonce = cur_nonce;
            memcpy(out_res->pow_hash, pow_hash, 32);
            memcpy(out_res->solved_work, work, 112);
            xelis_blake3_hash(work, 112, out_res->block_hash);
            out_res->hashes_evaluated = evaluated;
            return 1;
        }
        cur_nonce++;
    }

    out_res->hashes_evaluated = evaluated;
    return 0;
}

int xelis_oracle_branch_verify(const xelis_oracle_result_t *res,
                               const uint8_t target_be[32]) {
    if (!res || !target_be) return -1;

    uint64_t embedded_nonce = 0;
    for (int k = 0; k < 8; k++) {
        embedded_nonce = (embedded_nonce << 8) | res->solved_work[40 + k];
    }
    if (embedded_nonce != res->nonce) return -2;

    uint64_t *scratch = (uint64_t *)calloc(XELIS_MEMSIZE, sizeof(uint64_t));
    if (!scratch) return -1;

    uint8_t expected_pow[32];
    xelis_hash_v3_cpu(res->solved_work, expected_pow, scratch);
    free(scratch);

    if (memcmp(expected_pow, res->pow_hash, 32) != 0) return -3;
    if (!hash_meets_target(expected_pow, target_be)) return -4;

    uint8_t expected_block[32];
    xelis_blake3_hash(res->solved_work, 112, expected_block);
    if (memcmp(expected_block, res->block_hash, 32) != 0) return -5;

    return 0;
}
