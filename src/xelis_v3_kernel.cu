#include "xelis_cuda.h"
#include "xelis_hash_v3.h"
#include <cuda_runtime.h>
#include <stdio.h>
#include <string.h>

/* =========================================================================
 * Pure-C 4-Thread Sub-Warp Cooperative XelisHash V3 Engine (sm_75..sm_120a)
 * - 4 threads per hash instance (`Grid=368x64`, 5,888 instances = 23,552
 *   coop-threads under 2.98 GiB VRAM) -> zero duplicate Stage 1/Stage 4 ALU
 *   work and half the SHFL/WARPSYNC issue overhead of 8-thread mode!
 * - Native 32-bit hardware SHF funnel-shift 64-bit rotations
 * - Vectorized 128-bit (uint4) coalesced loads in Stage 4 BLAKE3 Merkle Tree
 * - Zero-overhead by-value `xelis_kparams_t` + non-blocking CUDA stream
 * ========================================================================= */
typedef struct {
    uint8_t work[112];
    uint8_t target_be[32];
} xelis_kparams_t;

__device__ __forceinline__ uint32_t dev_rotr32(uint32_t x, uint32_t n) {
    return __funnelshift_r(x, x, n);
}

__device__ __forceinline__ uint32_t dev_rotl32(uint32_t x, uint32_t n) {
    return __funnelshift_l(x, x, n);
}

__device__ __forceinline__ uint32_t dev_rotr32_16(uint32_t x) {
    return __byte_perm(x, 0u, 0x1032u);
}

__device__ __forceinline__ uint32_t dev_rotr32_8(uint32_t x) {
    return __byte_perm(x, 0u, 0x0321u);
}

__device__ __forceinline__ uint32_t dev_rotl32_8(uint32_t x) {
    return __byte_perm(x, 0u, 0x2103u);
}

/* Native 32-bit hardware SHF.L funnel-shift 64-bit rotation (branchless) */
__device__ __forceinline__ uint64_t dev_rotl64(uint64_t x, uint32_t r) {
    uint32_t s = r & 63u;
    uint32_t lo = (uint32_t)x;
    uint32_t hi = (uint32_t)(x >> 32);
    uint32_t a = (s & 32u) ? hi : lo;
    uint32_t b = (s & 32u) ? lo : hi;
    uint32_t s5 = s & 31u;
    uint32_t new_lo = __funnelshift_l(b, a, s5);
    uint32_t new_hi = __funnelshift_l(a, b, s5);
    return ((uint64_t)new_hi << 32) | new_lo;
}

/* Native 32-bit hardware SHF.R funnel-shift 64-bit rotation (branchless) */
__device__ __forceinline__ uint64_t dev_rotr64(uint64_t x, uint32_t r) {
    uint32_t s = r & 63u;
    uint32_t lo = (uint32_t)x;
    uint32_t hi = (uint32_t)(x >> 32);
    uint32_t a = (s & 32u) ? hi : lo;
    uint32_t b = (s & 32u) ? lo : hi;
    uint32_t s5 = s & 31u;
    uint32_t new_lo = __funnelshift_r(a, b, s5);
    uint32_t new_hi = __funnelshift_r(b, a, s5);
    return ((uint64_t)new_hi << 32) | new_lo;
}

__device__ __forceinline__ uint64_t shfl_u64(uint64_t v, int src_lane) {
    uint32_t lo = __shfl_sync(0xFFFFFFFFu, (uint32_t)v, src_lane, 4);
    uint32_t hi = __shfl_sync(0xFFFFFFFFu, (uint32_t)(v >> 32), src_lane, 4);
    return ((uint64_t)hi << 32) | lo;
}

/* =========================================================================
 * O(1) Portable Fast 128-bit Unsigned Arithmetic (Pure C, Force-Inlined)
 * ========================================================================= */
typedef struct {
    uint64_t hi;
    uint64_t lo;
} dev_u128_t;

__device__ __forceinline__ dev_u128_t dev_u128(uint64_t hi, uint64_t lo) {
    dev_u128_t v;
    v.hi = hi;
    v.lo = lo;
    return v;
}

__device__ __forceinline__ int dev_u128_gt(dev_u128_t a, dev_u128_t b) {
    return (a.hi > b.hi) || (a.hi == b.hi && a.lo > b.lo);
}

__device__ __forceinline__ int dev_u128_ge(dev_u128_t a, dev_u128_t b) {
    return (a.hi > b.hi) || (a.hi == b.hi && a.lo >= b.lo);
}

__device__ __forceinline__ dev_u128_t dev_u128_sub(dev_u128_t a, dev_u128_t b) {
    dev_u128_t r;
    r.lo = a.lo - b.lo;
    r.hi = a.hi - b.hi - (a.lo < b.lo ? 1ULL : 0ULL);
    return r;
}

__device__ __forceinline__ void dev_divrem_u128_u64(uint64_t hi, uint64_t lo, uint64_t d,
                                                    uint64_t *out_q_lo, uint64_t *out_rem) {
    if (hi == 0) {
        if (out_q_lo) *out_q_lo = lo / d;
        if (out_rem)  *out_rem  = lo % d;
        return;
    }
    uint64_t r = hi % d;
    if (r == 0) {
        if (out_q_lo) *out_q_lo = lo / d;
        if (out_rem)  *out_rem  = lo % d;
        return;
    }
    uint64_t q = 0;
    for (int b = 0; b < 64; b++) {
        uint64_t r_ovf = r >> 63;
        r = (r << 1) | (lo >> 63);
        lo <<= 1;
        q <<= 1;
        if (r_ovf || r >= d) {
            r -= d;
            q |= 1ULL;
        }
    }
    if (out_q_lo) *out_q_lo = q;
    if (out_rem)  *out_rem  = r;
}

__device__ __forceinline__ uint64_t dev_u128_rem64(uint64_t hi, uint64_t lo, uint64_t d) {
    uint64_t rem = 0;
    dev_divrem_u128_u64(hi, lo, d, NULL, &rem);
    return rem;
}

__device__ __forceinline__ uint64_t dev_u128_div64_lo(uint64_t hi, uint64_t lo, uint64_t d) {
    uint64_t q = 0;
    dev_divrem_u128_u64(hi, lo, d, &q, NULL);
    return q;
}

__device__ __forceinline__ void dev_u128_divmod128(dev_u128_t num, dev_u128_t den,
                                                   uint64_t *out_q_lo, dev_u128_t *out_rem) {
    if (den.hi == 0) {
        uint64_t q = 0, rem = 0;
        dev_divrem_u128_u64(num.hi, num.lo, den.lo, out_q_lo ? &q : NULL, out_rem ? &rem : NULL);
        if (out_q_lo) *out_q_lo = q;
        if (out_rem) { out_rem->hi = 0; out_rem->lo = rem; }
        return;
    }
    if (dev_u128_gt(den, num)) {
        if (out_q_lo) *out_q_lo = 0;
        if (out_rem) *out_rem = num;
        return;
    }
    dev_u128_t rem = dev_u128(0, num.hi);
    uint64_t q = 0;
    for (int b = 0; b < 64; b++) {
        rem.hi = (rem.hi << 1) | (rem.lo >> 63);
        rem.lo = (rem.lo << 1) | (num.lo >> 63);
        num.lo <<= 1;
        q <<= 1;
        if (dev_u128_ge(rem, den)) {
            rem = dev_u128_sub(rem, den);
            q |= 1ULL;
        }
    }
    if (out_q_lo) *out_q_lo = q;
    if (out_rem)  *out_rem  = rem;
}

__device__ __forceinline__ uint64_t dev_mulmod64(uint64_t a, uint64_t b, uint64_t mod) {
    uint64_t lo = a * b;
    uint64_t hi = __umul64hi(a, b);
    return dev_u128_rem64(hi, lo, mod);
}

/* =========================================================================
 * Constant Memory Tables: BLAKE3 & AES S-Box
 * ========================================================================= */
__constant__ uint32_t D_B3_IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

__constant__ uint8_t D_B3_SCHED[7][16] = {
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    { 2,  6,  3, 10,  7,  0,  4, 13,  1, 11, 12,  5,  9, 14, 15,  8},
    { 3,  4, 10, 12, 13,  2,  7, 14,  6,  5,  9,  0, 11, 15,  8,  1},
    {10,  7, 12,  9, 14,  3, 13, 15,  4,  0, 11,  2,  5,  8,  1,  6},
    {12, 13,  9, 11, 15, 10, 14,  8,  7,  2,  5,  3,  0,  1,  6,  4},
    { 9, 14, 11,  5,  8, 12, 15,  1, 13,  3,  0, 10,  2,  6,  4,  7},
    {11, 15,  5,  0,  1,  9,  8,  6, 14, 10,  2, 12,  3,  4,  7, 13}
};

__constant__ uint8_t D_AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

__constant__ uint8_t D_POW_KEY[16] = {
    'x','e','l','i','s','h','a','s','h','-','p','o','w','-','v','3'
};

__device__ __forceinline__ uint32_t dev_load32_le(const uint8_t *p) {
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

__device__ __forceinline__ void dev_store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* =========================================================================
 * L2-Cached Global Memory Scratchpad Accessors (PTX Volatile)
 * ========================================================================= */
__device__ __forceinline__ uint64_t inst_load_cg(const uint64_t * __restrict__ inst_scratch, uint32_t idx) {
    uint64_t val;
    const uint64_t *ptr = inst_scratch + idx;
    asm volatile("ld.global.cg.u64 %0, [%1];" : "=l"(val) : "l"(ptr));
    return val;
}

__device__ __forceinline__ void inst_store_cg(uint64_t * __restrict__ inst_scratch, uint32_t idx, uint64_t val) {
    uint64_t *ptr = inst_scratch + idx;
    asm volatile("st.global.cg.u64 [%0], %1;" :: "l"(ptr), "l"(val) : "memory");
}

/* =========================================================================
 * 4-Thread Sub-Warp Cooperative Tensor BLAKE3 Compression (Pure C Pointers)
 * ========================================================================= */
__device__ __forceinline__ void dev_b3_merge_transpose(uint32_t sl, uint32_t sh,
                                                        uint32_t cl, uint32_t ch,
                                                        uint32_t sub,
                                                        uint32_t *m0, uint32_t *m1,
                                                        uint32_t *m2, uint32_t *m3) {
    uint32_t a0 = __shfl_sync(0xFFFFFFFFu, sl, 0, 4);
    uint32_t a1 = __shfl_sync(0xFFFFFFFFu, sh, 0, 4);
    uint32_t a2 = __shfl_sync(0xFFFFFFFFu, cl, 0, 4);
    uint32_t a3 = __shfl_sync(0xFFFFFFFFu, ch, 0, 4);
    *m0 = (sub == 0u) ? a0 : (sub == 1u) ? a1 : (sub == 2u) ? a2 : a3;

    a0 = __shfl_sync(0xFFFFFFFFu, sl, 1, 4);
    a1 = __shfl_sync(0xFFFFFFFFu, sh, 1, 4);
    a2 = __shfl_sync(0xFFFFFFFFu, cl, 1, 4);
    a3 = __shfl_sync(0xFFFFFFFFu, ch, 1, 4);
    *m1 = (sub == 0u) ? a0 : (sub == 1u) ? a1 : (sub == 2u) ? a2 : a3;

    a0 = __shfl_sync(0xFFFFFFFFu, sl, 2, 4);
    a1 = __shfl_sync(0xFFFFFFFFu, sh, 2, 4);
    a2 = __shfl_sync(0xFFFFFFFFu, cl, 2, 4);
    a3 = __shfl_sync(0xFFFFFFFFu, ch, 2, 4);
    *m2 = (sub == 0u) ? a0 : (sub == 1u) ? a1 : (sub == 2u) ? a2 : a3;

    a0 = __shfl_sync(0xFFFFFFFFu, sl, 3, 4);
    a1 = __shfl_sync(0xFFFFFFFFu, sh, 3, 4);
    a2 = __shfl_sync(0xFFFFFFFFu, cl, 3, 4);
    a3 = __shfl_sync(0xFFFFFFFFu, ch, 3, 4);
    *m3 = (sub == 0u) ? a0 : (sub == 1u) ? a1 : (sub == 2u) ? a2 : a3;
}

__device__ __forceinline__ void dev_b3_compress_4t(uint32_t cv_lo, uint32_t cv_hi,
                                                   uint32_t m0, uint32_t m1, uint32_t m2, uint32_t m3,
                                                   uint64_t counter, uint32_t block_len, uint32_t flags,
                                                   uint32_t sub, uint32_t inst_local,
                                                   uint32_t s_b3_msg[16][16],
                                                   uint32_t *out_lo, uint32_t *out_hi) {
    s_b3_msg[inst_local][sub * 4u + 0u] = m0;
    s_b3_msg[inst_local][sub * 4u + 1u] = m1;
    s_b3_msg[inst_local][sub * 4u + 2u] = m2;
    s_b3_msg[inst_local][sub * 4u + 3u] = m3;
    __syncwarp(0xFFFFFFFFu);

    uint32_t s0 = cv_lo;
    uint32_t s1 = cv_hi;
    uint32_t s2 = D_B3_IV[sub];
    uint32_t s3 = (sub == 0u) ? (uint32_t)counter :
                  (sub == 1u) ? (uint32_t)(counter >> 32) :
                  (sub == 2u) ? block_len : flags;

    #pragma unroll
    for (int r = 0; r < 7; r++) {
        uint32_t mx = s_b3_msg[inst_local][D_B3_SCHED[r][sub * 2u]];
        uint32_t my = s_b3_msg[inst_local][D_B3_SCHED[r][sub * 2u + 1u]];

        s0 = s0 + s1 + mx; s3 = dev_rotr32_16(s3 ^ s0);
        s2 = s2 + s3;      s1 = dev_rotr32(s1 ^ s2, 12u);
        s0 = s0 + s1 + my; s3 = dev_rotr32_8(s3 ^ s0);
        s2 = s2 + s3;      s1 = dev_rotr32(s1 ^ s2, 7u);

        s1 = __shfl_sync(0xFFFFFFFFu, s1, (int)((sub + 1u) & 3u), 4);
        s2 = __shfl_sync(0xFFFFFFFFu, s2, (int)((sub + 2u) & 3u), 4);
        s3 = __shfl_sync(0xFFFFFFFFu, s3, (int)((sub + 3u) & 3u), 4);

        mx = s_b3_msg[inst_local][D_B3_SCHED[r][8u + sub * 2u]];
        my = s_b3_msg[inst_local][D_B3_SCHED[r][8u + sub * 2u + 1u]];

        s0 = s0 + s1 + mx; s3 = dev_rotr32_16(s3 ^ s0);
        s2 = s2 + s3;      s1 = dev_rotr32(s1 ^ s2, 12u);
        s0 = s0 + s1 + my; s3 = dev_rotr32_8(s3 ^ s0);
        s2 = s2 + s3;      s1 = dev_rotr32(s1 ^ s2, 7u);

        s1 = __shfl_sync(0xFFFFFFFFu, s1, (int)((sub + 3u) & 3u), 4);
        s2 = __shfl_sync(0xFFFFFFFFu, s2, (int)((sub + 2u) & 3u), 4);
        s3 = __shfl_sync(0xFFFFFFFFu, s3, (int)((sub + 1u) & 3u), 4);
    }

    *out_lo = s0 ^ s2;
    *out_hi = s1 ^ s3;
}

/* =========================================================================
 * 4-Thread Sub-Warp Cooperative PTX Bit-Shift ChaCha8 (Pure C Pointers)
 * ========================================================================= */
__device__ __forceinline__ void dev_chacha8_4t(uint32_t key_lo, uint32_t key_hi,
                                               uint32_t nonce_word, uint32_t sub,
                                               uint64_t * __restrict__ inst_scratch,
                                               uint32_t start_qidx, uint32_t num_blocks,
                                               uint32_t *out_last12_word) {
    const uint32_t st0 = (sub == 0u) ? 0x61707865u :
                         (sub == 1u) ? 0x3320646eu :
                         (sub == 2u) ? 0x79622d32u : 0x6b206574u;
    const uint32_t st1 = key_lo;
    const uint32_t st2 = key_hi;
    uint32_t st3 = (sub == 0u) ? 0u : nonce_word;

    uint4 * __restrict__ vec_out = (uint4 *)(inst_scratch + start_qidx);

    for (uint32_t b = 0; b < num_blocks; b++) {
        uint32_t x0 = st0, x1 = st1, x2 = st2, x3 = st3;

        #pragma unroll
        for (int r = 0; r < 4; r++) {
            asm("{\n\t"
                "add.u32 %0, %0, %1;\n\t"
                "xor.b32 %3, %3, %0;\n\t"
                "prmt.b32 %3, %3, 0, 0x1032;\n\t"
                "add.u32 %2, %2, %3;\n\t"
                "xor.b32 %1, %1, %2;\n\t"
                "shf.l.wrap.b32 %1, %1, %1, 12;\n\t"
                "add.u32 %0, %0, %1;\n\t"
                "xor.b32 %3, %3, %0;\n\t"
                "prmt.b32 %3, %3, 0, 0x2103;\n\t"
                "add.u32 %2, %2, %3;\n\t"
                "xor.b32 %1, %1, %2;\n\t"
                "shf.l.wrap.b32 %1, %1, %1, 7;\n\t"
                "}"
                : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3));

            x1 = __shfl_sync(0xFFFFFFFFu, x1, (int)((sub + 1u) & 3u), 4);
            x2 = __shfl_sync(0xFFFFFFFFu, x2, (int)((sub + 2u) & 3u), 4);
            x3 = __shfl_sync(0xFFFFFFFFu, x3, (int)((sub + 3u) & 3u), 4);

            asm("{\n\t"
                "add.u32 %0, %0, %1;\n\t"
                "xor.b32 %3, %3, %0;\n\t"
                "prmt.b32 %3, %3, 0, 0x1032;\n\t"
                "add.u32 %2, %2, %3;\n\t"
                "xor.b32 %1, %1, %2;\n\t"
                "shf.l.wrap.b32 %1, %1, %1, 12;\n\t"
                "add.u32 %0, %0, %1;\n\t"
                "xor.b32 %3, %3, %0;\n\t"
                "prmt.b32 %3, %3, 0, 0x2103;\n\t"
                "add.u32 %2, %2, %3;\n\t"
                "xor.b32 %1, %1, %2;\n\t"
                "shf.l.wrap.b32 %1, %1, %1, 7;\n\t"
                "}"
                : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3));

            x1 = __shfl_sync(0xFFFFFFFFu, x1, (int)((sub + 3u) & 3u), 4);
            x2 = __shfl_sync(0xFFFFFFFFu, x2, (int)((sub + 2u) & 3u), 4);
            x3 = __shfl_sync(0xFFFFFFFFu, x3, (int)((sub + 1u) & 3u), 4);
        }

        x0 += st0; x1 += st1; x2 += st2; x3 += st3;

        uint4 row_vec;
        {
            uint32_t t0 = __shfl_sync(0xFFFFFFFFu, x0, 0, 4);
            uint32_t t1 = __shfl_sync(0xFFFFFFFFu, x1, 0, 4);
            uint32_t t2 = __shfl_sync(0xFFFFFFFFu, x2, 0, 4);
            uint32_t t3 = __shfl_sync(0xFFFFFFFFu, x3, 0, 4);
            row_vec.x = (sub == 0u) ? t0 : (sub == 1u) ? t1 : (sub == 2u) ? t2 : t3;

            t0 = __shfl_sync(0xFFFFFFFFu, x0, 1, 4);
            t1 = __shfl_sync(0xFFFFFFFFu, x1, 1, 4);
            t2 = __shfl_sync(0xFFFFFFFFu, x2, 1, 4);
            t3 = __shfl_sync(0xFFFFFFFFu, x3, 1, 4);
            row_vec.y = (sub == 0u) ? t0 : (sub == 1u) ? t1 : (sub == 2u) ? t2 : t3;

            t0 = __shfl_sync(0xFFFFFFFFu, x0, 2, 4);
            t1 = __shfl_sync(0xFFFFFFFFu, x1, 2, 4);
            t2 = __shfl_sync(0xFFFFFFFFu, x2, 2, 4);
            t3 = __shfl_sync(0xFFFFFFFFu, x3, 2, 4);
            row_vec.z = (sub == 0u) ? t0 : (sub == 1u) ? t1 : (sub == 2u) ? t2 : t3;

            t0 = __shfl_sync(0xFFFFFFFFu, x0, 3, 4);
            t1 = __shfl_sync(0xFFFFFFFFu, x1, 3, 4);
            t2 = __shfl_sync(0xFFFFFFFFu, x2, 3, 4);
            t3 = __shfl_sync(0xFFFFFFFFu, x3, 3, 4);
            row_vec.w = (sub == 0u) ? t0 : (sub == 1u) ? t1 : (sub == 2u) ? t2 : t3;
        }

        vec_out[b * 4u + sub] = row_vec;

        if (b + 1u == num_blocks) {
            *out_last12_word = x3;
        }
        st3 += (sub == 0u) ? 1u : 0u;
    }
}

__device__ __forceinline__ uint8_t dev_gf_mul2(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

__device__ __forceinline__ uint32_t dev_sub_bytes32(uint32_t w, const uint8_t * __restrict__ s_sbox) {
    return ((uint32_t)s_sbox[w & 0xFFu]) |
           ((uint32_t)s_sbox[(w >> 8) & 0xFFu] << 8) |
           ((uint32_t)s_sbox[(w >> 16) & 0xFFu] << 16) |
           ((uint32_t)s_sbox[w >> 24] << 24);
}

__device__ __forceinline__ uint32_t dev_mix_add_col(uint32_t tc, uint32_t rk) {
    uint32_t rot1 = __byte_perm(tc, tc, 0x0321u);
    uint32_t rot2 = __byte_perm(tc, tc, 0x1032u);
    uint32_t rot3 = __byte_perm(tc, tc, 0x2103u);
    uint32_t x    = tc ^ rot1 ^ rot2 ^ rot3;
    uint32_t y    = tc ^ rot1;
    uint32_t hi   = y & 0x80808080u;
    uint32_t m2   = ((y & 0x7F7F7F7Fu) << 1) ^ ((hi >> 7) * 0x1Bu);
    return tc ^ x ^ m2 ^ rk;
}

__device__ __forceinline__ uint64_t dev_aes_stage3_hash(uint64_t va, uint64_t vb,
                                                        const uint8_t * __restrict__ s_sbox) {
    uint32_t s0 = dev_sub_bytes32((uint32_t)vb, s_sbox);
    uint32_t s1 = dev_sub_bytes32((uint32_t)(vb >> 32), s_sbox);
    uint32_t s2 = dev_sub_bytes32((uint32_t)va, s_sbox);
    uint32_t s3 = dev_sub_bytes32((uint32_t)(va >> 32), s_sbox);

    uint32_t t0 = (s0 & 0x000000FFu) | (s1 & 0x0000FF00u) | (s2 & 0x00FF0000u) | (s3 & 0xFF000000u);
    uint32_t t1 = (s1 & 0x000000FFu) | (s2 & 0x0000FF00u) | (s3 & 0x00FF0000u) | (s0 & 0xFF000000u);
    uint32_t t2 = (s2 & 0x000000FFu) | (s3 & 0x0000FF00u) | (s0 & 0x00FF0000u) | (s1 & 0xFF000000u);
    uint32_t t3 = (s3 & 0x000000FFu) | (s0 & 0x0000FF00u) | (s1 & 0x00FF0000u) | (s2 & 0xFF000000u);

    /* D_POW_KEY = "xelishash-pow-v3" in LE uint32 words */
    uint32_t o0 = dev_mix_add_col(t0, 0x696c6578u);
    uint32_t o1 = dev_mix_add_col(t1, 0x73616873u);
    uint32_t o2 = dev_mix_add_col(t2, 0x6f702d68u);
    uint32_t o3 = dev_mix_add_col(t3, 0x33762d77u);

    return ~((((uint64_t)(o1 ^ o3)) << 32) | (uint64_t)(o0 ^ o2));
}

/* =========================================================================
 * Stage 3 Pure PTX Inline Assembly Helpers & BF32/FP32-Residual isqrt64
 * ========================================================================= */
__device__ __forceinline__ uint64_t dev_murmurhash3(uint64_t seed) {
    uint64_t out;
    asm("{\n\t"
        ".reg .u64 t0, s;\n\t"
        "mov.b64 s, %1;\n\t"
        "shr.u64 t0, s, 55;\n\t"
        "xor.b64 s, s, t0;\n\t"
        "mul.lo.u64 s, s, 0xff51afd7ed558ccd;\n\t"
        "shr.u64 t0, s, 32;\n\t"
        "xor.b64 s, s, t0;\n\t"
        "mul.lo.u64 s, s, 0xc4ceb9fe1a85ec53;\n\t"
        "shr.u64 t0, s, 15;\n\t"
        "xor.b64 %0, s, t0;\n\t"
        "}"
        : "=l"(out) : "l"(seed));
    return out;
}

__device__ __forceinline__ uint32_t dev_map_index(uint64_t x) {
    uint32_t idx;
    asm("{\n\t"
        ".reg .u64 t0, t1;\n\t"
        "shr.u64 t0, %1, 33;\n\t"
        "xor.b64 t1, %1, t0;\n\t"
        "mul.lo.u64 t1, t1, 0xff51afd7ed558ccd;\n\t"
        "mul.hi.u64 t1, t1, 33984;\n\t"
        "cvt.u32.u64 %0, t1;\n\t"
        "}"
        : "=r"(idx) : "l"(x));
    return idx;
}

__device__ __forceinline__ uint64_t dev_ptx_mad_u64(uint64_t a, uint64_t b, uint64_t c) {
    uint64_t res;
    asm("mad.lo.u64 %0, %1, %2, %3;" : "=l"(res) : "l"(a), "l"(b), "l"(c));
    return res;
}

__device__ __forceinline__ uint64_t dev_ptx_mulhi_add_u64(uint64_t a, uint64_t b, uint64_t c) {
    uint64_t res;
    asm("{\n\t"
        ".reg .u64 hi;\n\t"
        "mul.hi.u64 hi, %1, %2;\n\t"
        "add.u64 %0, hi, %3;\n\t"
        "}"
        : "=l"(res) : "l"(a), "l"(b), "l"(c));
    return res;
}

__device__ __forceinline__ uint64_t dev_isqrt64(uint64_t n) {
    if (n < 2) return n;
    float fn = (float)n;
    float rx = rsqrtf(fn);
    uint64_t x = (uint64_t)(fn * rx);
    if (x == 0) x = 1;
    if (x > 0xFFFFFFFFULL) x = 0xFFFFFFFFULL;
    int64_t rem = (int64_t)(n - x * x);
    int64_t dx = (int64_t)((float)rem * (0.5f * rx));
    int64_t x2 = (int64_t)x + dx;
    if (x2 < 0) x2 = 0;
    x = (uint64_t)x2;
    if (x > 0xFFFFFFFFULL) x = 0xFFFFFFFFULL;
    while (x * x > n) x--;
    while (x < 0xFFFFFFFFULL && (x + 1) * (x + 1) <= n) x++;
    return x;
}

__device__ __forceinline__ uint64_t dev_modular_power(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1ULL) {
            result = dev_mulmod64(result, base, mod);
        }
        base = dev_mulmod64(base, base, mod);
        exp >>= 1;
    }
    return result;
}

/* =========================================================================
 * Main Pure-C 4-Thread Cooperative XelisHash V3 Kernel (10+ KH/s Target)
 * ========================================================================= */
extern "C" __global__ void __launch_bounds__(64, 16)
xelis_v3_mine_kernel(xelis_kparams_t params,
                     uint64_t start_nonce,
                     uint64_t * __restrict__ d_scratchpads,
                     int * __restrict__ d_found_flag,
                     uint64_t * __restrict__ d_found_nonce,
                     uint8_t * __restrict__ d_found_hash) {
    __shared__ uint8_t  s_aes_sbox[256];
    __shared__ uint32_t s_stack_lo[64][10];
    __shared__ uint32_t s_stack_hi[64][10];
    __shared__ uint32_t s_b3_msg[16][16];
    __shared__ uint64_t s_addr_a[16];
    __shared__ uint64_t s_addr_b[16];

    const uint32_t t_local = threadIdx.x;
    for (uint32_t i = t_local; i < 256u; i += blockDim.x) {
        s_aes_sbox[i] = D_AES_SBOX[i];
    }
    __syncthreads();

    const uint32_t tid = blockIdx.x * blockDim.x + t_local;
    const uint32_t sub = t_local & 3u;
    const uint32_t inst_local = t_local >> 2;
    const uint32_t inst_id = tid >> 2;
    uint64_t my_nonce = start_nonce + (uint64_t)inst_id;
    const int inject_nonce = (start_nonce != 0xFFFFFFFFFFFFFFFFULL);

    uint64_t * __restrict__ inst_scratch = d_scratchpads + ((size_t)inst_id * XELIS_MEMSIZE);

    /* ---------------------------------------------------------------------
     * Stage 1: 4-Thread Cooperative BLAKE3 + PTX Bit-Shift ChaCha8
     * --------------------------------------------------------------------- */
    uint32_t m0 = dev_load32_le(params.work + sub * 16u + 0u);
    uint32_t m1 = dev_load32_le(params.work + sub * 16u + 4u);
    uint32_t m2 = dev_load32_le(params.work + sub * 16u + 8u);
    uint32_t m3 = dev_load32_le(params.work + sub * 16u + 12u);

    uint32_t n_word0 = 0, n_word1 = 0;
    if (inject_nonce) {
        n_word0 = __byte_perm((uint32_t)(my_nonce >> 32), 0u, 0x0123u);
        n_word1 = __byte_perm((uint32_t)my_nonce, 0u, 0x0123u);
        if (sub == 2u) { m2 = n_word0; m3 = n_word1; }
    }

    uint32_t cv_lo, cv_hi;
    dev_b3_compress_4t(D_B3_IV[sub], D_B3_IV[4u + sub], m0, m1, m2, m3, 0, 64u, 1u, sub, inst_local, s_b3_msg, &cv_lo, &cv_hi);

    if (sub < 3u) {
        m0 = dev_load32_le(params.work + 64u + sub * 16u + 0u);
        m1 = dev_load32_le(params.work + 64u + sub * 16u + 4u);
        m2 = dev_load32_le(params.work + 64u + sub * 16u + 8u);
        m3 = dev_load32_le(params.work + 64u + sub * 16u + 12u);
    } else {
        m0 = 0; m1 = 0; m2 = 0; m3 = 0;
    }
    uint32_t buf_lo, buf_hi;
    dev_b3_compress_4t(cv_lo, cv_hi, m0, m1, m2, m3, 0, 48u, 2u | 8u, sub, inst_local, s_b3_msg, &buf_lo, &buf_hi);

    uint32_t b_lo0 = __shfl_sync(0xFFFFFFFFu, buf_lo, 0, 4);
    uint32_t b_lo1 = __shfl_sync(0xFFFFFFFFu, buf_lo, 1, 4);
    uint32_t b_lo2 = __shfl_sync(0xFFFFFFFFu, buf_lo, 2, 4);
    uint32_t b_lo3 = __shfl_sync(0xFFFFFFFFu, buf_lo, 3, 4);
    uint32_t b_hi0 = __shfl_sync(0xFFFFFFFFu, buf_hi, 0, 4);
    uint32_t b_hi1 = __shfl_sync(0xFFFFFFFFu, buf_hi, 1, 4);
    uint32_t b_hi2 = __shfl_sync(0xFFFFFFFFu, buf_hi, 2, 4);
    uint32_t b_hi3 = __shfl_sync(0xFFFFFFFFu, buf_hi, 3, 4);

    if (sub == 0u) {
        m0 = b_lo0; m1 = b_lo1; m2 = b_lo2; m3 = b_lo3;
    } else if (sub == 1u) {
        m0 = b_hi0; m1 = b_hi1; m2 = b_hi2; m3 = b_hi3;
    } else {
        uint32_t kbase = (sub - 2u) * 16u;
        m0 = dev_load32_le(params.work + kbase + 0u);
        m1 = dev_load32_le(params.work + kbase + 4u);
        m2 = dev_load32_le(params.work + kbase + 8u);
        m3 = dev_load32_le(params.work + kbase + 12u);
    }
    uint32_t key_lo, key_hi;
    dev_b3_compress_4t(D_B3_IV[sub], D_B3_IV[4u + sub], m0, m1, m2, m3, 0, 64u, 1u | 2u | 8u, sub, inst_local, s_b3_msg, &key_lo, &key_hi);

    uint32_t nonce_w = __shfl_sync(0xFFFFFFFFu, buf_lo, (int)((sub - 1u) & 3u), 4);
    uint32_t last12_w = 0;
    const uint32_t chunk_qwords = (XELIS_OUTPUT_SIZE / 4u) / 8u; /* 16,992 */
    const uint32_t chunk_blocks = chunk_qwords / 8u;             /* 2,124 */

    dev_chacha8_4t(key_lo, key_hi, nonce_w, sub, inst_scratch, 0u, chunk_blocks, &last12_w);

    for (int c = 1; c < 4; c++) {
        uint32_t k_lo0 = __shfl_sync(0xFFFFFFFFu, key_lo, 0, 4);
        uint32_t k_lo1 = __shfl_sync(0xFFFFFFFFu, key_lo, 1, 4);
        uint32_t k_lo2 = __shfl_sync(0xFFFFFFFFu, key_lo, 2, 4);
        uint32_t k_lo3 = __shfl_sync(0xFFFFFFFFu, key_lo, 3, 4);
        uint32_t k_hi0 = __shfl_sync(0xFFFFFFFFu, key_hi, 0, 4);
        uint32_t k_hi1 = __shfl_sync(0xFFFFFFFFu, key_hi, 1, 4);
        uint32_t k_hi2 = __shfl_sync(0xFFFFFFFFu, key_hi, 2, 4);
        uint32_t k_hi3 = __shfl_sync(0xFFFFFFFFu, key_hi, 3, 4);

        if (sub == 0u) {
            m0 = k_lo0; m1 = k_lo1; m2 = k_lo2; m3 = k_lo3;
        } else if (sub == 1u) {
            m0 = k_hi0; m1 = k_hi1; m2 = k_hi2; m3 = k_hi3;
        } else {
            uint32_t kbase = (uint32_t)c * 32u + (sub - 2u) * 16u;
            m0 = (kbase + 0u  < 112u) ? dev_load32_le(params.work + kbase + 0u)  : 0u;
            m1 = (kbase + 4u  < 112u) ? dev_load32_le(params.work + kbase + 4u)  : 0u;
            m2 = (kbase + 8u  < 112u) ? dev_load32_le(params.work + kbase + 8u)  : 0u;
            m3 = (kbase + 12u < 112u) ? dev_load32_le(params.work + kbase + 12u) : 0u;
            if (inject_nonce && c == 1 && sub == 2u) {
                m2 = n_word0;
                m3 = n_word1;
            }
        }
        dev_b3_compress_4t(D_B3_IV[sub], D_B3_IV[4u + sub], m0, m1, m2, m3, 0, 64u, 1u | 2u | 8u, sub, inst_local, s_b3_msg, &key_lo, &key_hi);
        dev_chacha8_4t(key_lo, key_hi, last12_w, sub, inst_scratch, (uint32_t)c * chunk_qwords, chunk_blocks, &last12_w);
    }

    __syncwarp(0xFFFFFFFFu);

    /* ---------------------------------------------------------------------
     * Stage 3: Hardware Funnel-Shift + PTX Memory-Hard Loop
     * --------------------------------------------------------------------- */
    if (sub == 0u) {
        s_addr_a[inst_local] = inst_load_cg(inst_scratch, XELIS_MEMSIZE - 1u);
        s_addr_b[inst_local] = inst_load_cg(inst_scratch, XELIS_BUFSIZE - 1u) >> 32;
    }
    __syncwarp(0xFFFFFFFFu);
    uint32_t r = 0;

    for (uint32_t i = 0; i < XELIS_ITERS; i++) {
        uint64_t va = inst_load_cg(inst_scratch, dev_map_index(s_addr_a[inst_local]));
        uint64_t vb = inst_load_cg(inst_scratch, XELIS_BUFSIZE + dev_map_index(va ^ s_addr_b[inst_local]));

        uint64_t result = dev_aes_stage3_hash(va, vb, s_aes_sbox);

        for (uint32_t j = 0; j < XELIS_BUFSIZE; j++) {
            uint32_t load_idx_ac = (sub == 0u) ? dev_map_index(result) : r;
            uint64_t val_ac = (sub == 0u || sub == 2u) ? inst_load_cg(inst_scratch, load_idx_ac) : 0ULL;
            uint64_t a = shfl_u64(val_ac, 0);
            uint64_t c = shfl_u64(val_ac, 2);

            uint64_t b_local = (sub == 1u)
                ? inst_load_cg(inst_scratch, XELIS_BUFSIZE + dev_map_index(a ^ ~dev_rotr64(result, r)))
                : 0ULL;
            uint64_t b = shfl_u64(b_local, 1);
            r = (r < XELIS_MEMSIZE - 1u) ? (r + 1u) : 0u;

            uint32_t op = (uint32_t)dev_rotl64(result, (uint32_t)c) & 0xfu;

            uint64_t sq_in = (op == 0u) ? ((sub == 0u) ? (b + j) : 1ULL) :
                             (op == 1u) ? ((sub == 0u) ? (b | 2ULL) : (a + j)) :
                                          ((sub == 0u) ? (a + i) : (c + j));
            uint32_t sq_val = (op < 3u && sub < 2u) ? (uint32_t)dev_isqrt64(sq_in) : 1u;
            uint64_t sq0 = (uint64_t)__shfl_sync(0xFFFFFFFFu, sq_val, 0, 4);
            uint64_t sq1 = (uint64_t)__shfl_sync(0xFFFFFFFFu, sq_val, 1, 4);

            uint32_t owner = (op < 3u) ? 0u : (op >> 2);
            uint64_t v_local = 0ULL;
            if (sub == owner) {
                if (op == 0u || op == 10u || op == 12u) {
                    uint64_t u_hi = (op == 0u) ? (a + i) : (op == 10u) ? a : c;
                    uint64_t u_lo = (op == 0u) ? sq0     : (op == 10u) ? b : a;
                    uint64_t u_d  = (op == 0u) ? (dev_murmurhash3(c ^ result ^ i ^ j) | 1ULL)
                                  : (op == 10u) ? (c | 1ULL) : (b | 4ULL);
                    uint64_t q_out = 0, r_out = 0;
                    dev_divrem_u128_u64(u_hi, u_lo, u_d, &q_out, &r_out);
                    v_local = (op == 12u) ? q_out : r_out;
                } else if (op == 11u || op == 13u) {
                    dev_u128_t t1 = (op == 11u) ? dev_u128(b, c) : dev_u128(dev_rotl64(result, r), b);
                    dev_u128_t t2 = (op == 11u) ? dev_u128(dev_rotl64(result, r), a | 2ULL) : dev_u128(a, c | 8ULL);
                    if (op == 11u) {
                        if (dev_u128_gt(t2, t1)) {
                            v_local = c;
                        } else {
                            dev_u128_t rem;
                            dev_u128_divmod128(t1, t2, NULL, &rem);
                            v_local = rem.lo;
                        }
                    } else {
                        if (dev_u128_gt(t1, t2)) {
                            uint64_t q_lo = 0;
                            dev_u128_divmod128(t1, t2, &q_lo, NULL);
                            v_local = q_lo;
                        } else {
                            v_local = a ^ b;
                        }
                    }
                } else {
                    switch (op) {
                        case 1:
                            v_local = dev_rotl64((c + i) % sq0, i + j) * sq1;
                            break;
                        case 2:
                            v_local = (sq0 * sq1) ^ (b + i + j);
                            break;
                        case 3:  v_local = (a + b) * c; break;
                        case 4:  v_local = (b - c) * a; break;
                        case 5:  v_local = c - a + b; break;
                        case 6:  v_local = a - b + c; break;
                        case 7:  v_local = dev_ptx_mad_u64(b, c, a); break;
                        case 8:  v_local = dev_ptx_mad_u64(c, a, b); break;
                        case 9:  v_local = a * b * c; break;
                        case 14:
                            v_local = dev_ptx_mulhi_add_u64(a, c, b * c);
                            break;
                        default: {
                            uint64_t t2_hi = dev_rotr64(result, r);
                            uint64_t base_sum = dev_ptx_mad_u64(a, b, c * t2_hi);
                            v_local = dev_ptx_mulhi_add_u64(c, b, base_sum);
                            break;
                        }
                    }
                }
            }
            uint64_t v = shfl_u64(v_local, (int)owner);

            uint64_t idx_seed = v ^ result;
            result = dev_rotl64(idx_seed, r);

            int use_b = (dev_murmurhash3(v) & (1ULL << 58)) != 0;
            uint32_t idx_t = dev_map_index(idx_seed) + (use_b ? XELIS_BUFSIZE : 0u);
            uint64_t tv_local = (sub == 0u) ? (inst_load_cg(inst_scratch, idx_t) ^ result) : 0ULL;
            uint64_t tv = shfl_u64(tv_local, 0);

            uint32_t idx_a = dev_map_index(tv ^ result ^ 0x9e3779b97f4a7c15ULL);
            uint32_t idx_b = dev_map_index((uint64_t)idx_a ^ ~result ^ 0xd2b74407b1ce6e93ULL);

            uint32_t rw_idx = (sub == 0u) ? idx_a : (XELIS_BUFSIZE + idx_b);
            uint64_t prev_val = (sub < 2u) ? inst_load_cg(inst_scratch, rw_idx) : 0ULL;
            uint64_t prev_a = shfl_u64(prev_val, 0);

            if (sub == 0u) {
                inst_store_cg(inst_scratch, idx_a, tv);
            } else if (sub == 1u) {
                uint64_t new_b = prev_val ^ prev_a ^ dev_rotr64(tv, i + j);
                inst_store_cg(inst_scratch, XELIS_BUFSIZE + idx_b, new_b);
            }
            __syncwarp(0xFFFFFFFFu);
        }

        if (sub == 0u) {
            uint64_t na = dev_modular_power(s_addr_a[inst_local], s_addr_b[inst_local], result);
            s_addr_a[inst_local] = na;
            s_addr_b[inst_local] = dev_isqrt64(result) * (r + 1u) * dev_isqrt64(na);
        }
        __syncwarp(0xFFFFFFFFu);
    }

    /* ---------------------------------------------------------------------
     * Stage 4: 128-bit Vectorized (uint4) Tensor BLAKE3 Merkle Tree
     * --------------------------------------------------------------------- */
    uint8_t stack_len = 0;
    const uint4 * __restrict__ vec_in = (const uint4 *)inst_scratch;

    const uint32_t b3_iv_lo = D_B3_IV[sub];
    const uint32_t b3_iv_hi = D_B3_IV[4u + sub];

    for (uint32_t chunk_idx = 0; chunk_idx < 531u; chunk_idx++) {
        cv_lo = b3_iv_lo;
        cv_hi = b3_iv_hi;

        uint32_t base_v = chunk_idx * 64u;
        uint4 v4_cur = vec_in[base_v + sub];
        for (uint32_t b = 0; b < 16u; b++) {
            uint4 v4_next = (b + 1u < 16u) ? vec_in[base_v + (b + 1u) * 4u + sub] : make_uint4(0u, 0u, 0u, 0u);
            uint32_t flags = (b == 0u ? 1u : 0u) | (b == 15u ? 2u : 0u);
            dev_b3_compress_4t(cv_lo, cv_hi, v4_cur.x, v4_cur.y, v4_cur.z, v4_cur.w,
                               (uint64_t)chunk_idx, 64u, flags, sub, inst_local, s_b3_msg, &cv_lo, &cv_hi);
            v4_cur = v4_next;
        }

        uint32_t total_chunks = chunk_idx + 1u;
        if (chunk_idx + 1u < 531u) {
            while ((total_chunks & 1u) == 0u) {
                stack_len--;
                uint32_t sl = s_stack_lo[t_local][stack_len];
                uint32_t sh = s_stack_hi[t_local][stack_len];

                dev_b3_merge_transpose(sl, sh, cv_lo, cv_hi, sub, &m0, &m1, &m2, &m3);

                dev_b3_compress_4t(D_B3_IV[sub], D_B3_IV[4u + sub], m0, m1, m2, m3,
                                   0, 64u, 4u, sub, inst_local, s_b3_msg, &cv_lo, &cv_hi);
                total_chunks >>= 1;
            }
            s_stack_lo[t_local][stack_len] = cv_lo;
            s_stack_hi[t_local][stack_len] = cv_hi;
            stack_len++;
        } else {
            while (stack_len > 0u) {
                stack_len--;
                uint32_t sl = s_stack_lo[t_local][stack_len];
                uint32_t sh = s_stack_hi[t_local][stack_len];

                dev_b3_merge_transpose(sl, sh, cv_lo, cv_hi, sub, &m0, &m1, &m2, &m3);

                uint32_t flags = 4u | ((stack_len == 0u) ? 8u : 0u);
                dev_b3_compress_4t(D_B3_IV[sub], D_B3_IV[4u + sub], m0, m1, m2, m3,
                                   0, 64u, flags, sub, inst_local, s_b3_msg, &cv_lo, &cv_hi);
            }
        }
    }

    uint32_t w0 = __shfl_sync(0xFFFFFFFFu, cv_lo, 0, 4);
    uint32_t w1 = __shfl_sync(0xFFFFFFFFu, cv_lo, 1, 4);
    uint32_t w2 = __shfl_sync(0xFFFFFFFFu, cv_lo, 2, 4);
    uint32_t w3 = __shfl_sync(0xFFFFFFFFu, cv_lo, 3, 4);
    uint32_t w4 = __shfl_sync(0xFFFFFFFFu, cv_hi, 0, 4);
    uint32_t w5 = __shfl_sync(0xFFFFFFFFu, cv_hi, 1, 4);
    uint32_t w6 = __shfl_sync(0xFFFFFFFFu, cv_hi, 2, 4);
    uint32_t w7 = __shfl_sync(0xFFFFFFFFu, cv_hi, 3, 4);

    if (sub == 0u) {
        int meets = 1;
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            uint32_t wi = (i == 0) ? w0 : (i == 1) ? w1 : (i == 2) ? w2 : (i == 3) ? w3 :
                          (i == 4) ? w4 : (i == 5) ? w5 : (i == 6) ? w6 : w7;
            uint32_t hw = __byte_perm(wi, 0u, 0x0123u);
            uint32_t tw = ((uint32_t)params.target_be[i * 4 + 0] << 24) |
                          ((uint32_t)params.target_be[i * 4 + 1] << 16) |
                          ((uint32_t)params.target_be[i * 4 + 2] << 8)  |
                          ((uint32_t)params.target_be[i * 4 + 3]);
            if (hw < tw) { meets = 1; break; }
            if (hw > tw) { meets = 0; break; }
        }

        if (meets) {
            if (atomicCAS(d_found_flag, 0, 1) == 0) {
                *d_found_nonce = start_nonce + (uint64_t)((blockIdx.x * blockDim.x + t_local) >> 2);
                dev_store32_le(d_found_hash + 0,  w0);
                dev_store32_le(d_found_hash + 4,  w1);
                dev_store32_le(d_found_hash + 8,  w2);
                dev_store32_le(d_found_hash + 12, w3);
                dev_store32_le(d_found_hash + 16, w4);
                dev_store32_le(d_found_hash + 20, w5);
                dev_store32_le(d_found_hash + 24, w6);
                dev_store32_le(d_found_hash + 28, w7);
            }
        }
    }
}

/* =========================================================================
 * Host CUDA Management (4 Threads per Hash Instance, <3.0 GiB Default VRAM)
 * ========================================================================= */
int xelis_cuda_init(xelis_cuda_ctx_t *ctx, int gpu_id, int blocks, int threads_per_block) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->device_id = gpu_id;

    if (cudaSetDevice(gpu_id) != cudaSuccess) return -1;

    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, gpu_id) != cudaSuccess) return -1;

    snprintf(ctx->name, sizeof(ctx->name), "%s", prop.name);
    ctx->sm_major = prop.major;
    ctx->sm_minor = prop.minor;
    ctx->sm_count = prop.multiProcessorCount;

    if (cudaMemGetInfo(&ctx->free_vram, &ctx->total_vram) != cudaSuccess) return -1;

    if (threads_per_block <= 0) {
        ctx->block_threads = 64u;
    } else if (threads_per_block <= 4) {
        ctx->block_threads = 4u;
    } else {
        uint32_t t = (uint32_t)threads_per_block;
        if (t > 64u) t = 64u;
        t = ((t + 31u) / 32u) * 32u;
        ctx->block_threads = t;
    }

    uint32_t instances_per_block = ctx->block_threads / 4u;
    if (instances_per_block == 0u) instances_per_block = 1u;

    if (blocks > 0) {
        ctx->grid_blocks = (uint32_t)blocks;
    } else {
        size_t usable = (ctx->free_vram * 70) / 100;
        size_t cap_3gb = (size_t)3060 * 1024ULL * 1024ULL;
        if (usable > cap_3gb) usable = cap_3gb;

        size_t max_instances = usable / XELIS_OUTPUT_SIZE;
        uint32_t b = (uint32_t)(max_instances / instances_per_block);
        uint32_t sm = (uint32_t)ctx->sm_count;
        if (b < sm) {
            b = sm;
        } else {
            b = (b / sm) * sm;
        }
        ctx->grid_blocks = b;
    }

    size_t total_threads = (size_t)ctx->grid_blocks * ctx->block_threads;
    size_t total_instances = total_threads / 4u;
    size_t scratch_bytes = total_instances * XELIS_OUTPUT_SIZE;

    if (cudaMalloc(&ctx->d_scratchpads, scratch_bytes) != cudaSuccess) return -1;
    if (cudaMalloc(&ctx->d_found_nonce, sizeof(uint64_t)) != cudaSuccess) return -1;
    if (cudaMalloc(&ctx->d_found_hash, 32) != cudaSuccess) return -1;
    if (cudaMalloc(&ctx->d_found_flag, sizeof(int)) != cudaSuccess) return -1;

    printf("[CUDA] GPU #%d: %s (sm_%d%d, %d SMs) | Grid=%ux%u (%zu instances / %zu 4T-coop, %.2f GiB VRAM)\n",
           gpu_id, ctx->name, ctx->sm_major, ctx->sm_minor, ctx->sm_count,
           ctx->grid_blocks, ctx->block_threads, total_instances, total_threads,
           (double)scratch_bytes / (1024.0 * 1024.0 * 1024.0));
    return 0;
}

void xelis_cuda_free(xelis_cuda_ctx_t *ctx) {
    if (ctx->d_scratchpads) cudaFree(ctx->d_scratchpads);
    if (ctx->d_found_nonce) cudaFree(ctx->d_found_nonce);
    if (ctx->d_found_hash)  cudaFree(ctx->d_found_hash);
    if (ctx->d_found_flag)  cudaFree(ctx->d_found_flag);
    memset(ctx, 0, sizeof(*ctx));
}

int xelis_cuda_mine_batch(xelis_cuda_ctx_t *ctx,
                          const uint8_t work112[112],
                          const uint8_t target_be[32],
                          uint64_t start_nonce,
                          uint64_t *out_nonce,
                          uint8_t out_hash[32],
                          uint32_t *out_hashes_done) {
    xelis_kparams_t params;
    memcpy(params.work, work112, 112);
    memcpy(params.target_be, target_be, 32);

    cudaMemsetAsync(ctx->d_found_flag, 0, sizeof(int), 0);
    xelis_v3_mine_kernel<<<ctx->grid_blocks, ctx->block_threads>>>(
        params, start_nonce, ctx->d_scratchpads, ctx->d_found_flag, ctx->d_found_nonce, ctx->d_found_hash);

    cudaError_t err = cudaDeviceSynchronize();
    if (err != cudaSuccess) {
        fprintf(stderr, "[CUDA] Kernel error: %s\n", cudaGetErrorString(err));
        return -1;
    }

    if (out_hashes_done) *out_hashes_done = (ctx->grid_blocks * ctx->block_threads) / 4u;

    int found = 0;
    cudaMemcpy(&found, ctx->d_found_flag, sizeof(int), cudaMemcpyDeviceToHost);
    if (found) {
        cudaMemcpy(out_nonce, ctx->d_found_nonce, sizeof(uint64_t), cudaMemcpyDeviceToHost);
        cudaMemcpy(out_hash, ctx->d_found_hash, 32, cudaMemcpyDeviceToHost);
        return 1;
    }
    return 0;
}

int xelis_cuda_selftest(int gpu_id) {
    xelis_cuda_ctx_t ctx;
    if (xelis_cuda_init(&ctx, gpu_id, 1, 4) != 0) return -1;

    uint8_t zero_in[112];
    uint8_t max_target[32];
    memset(zero_in, 0, sizeof(zero_in));
    memset(max_target, 0xFF, sizeof(max_target));

    uint64_t nonce = 0;
    uint8_t gpu_hash[32];
    int rc = xelis_cuda_mine_batch(&ctx, zero_in, max_target, 0xFFFFFFFFFFFFFFFFULL, &nonce, gpu_hash, NULL);
    if (rc != 1) {
        xelis_cuda_free(&ctx);
        return -2;
    }

    static const uint8_t gold1[32] = {
        105, 172, 103, 40, 94, 253, 92, 162,
        42, 252, 5, 196, 236, 238, 91, 218,
        22, 157, 228, 233, 239, 8, 250, 57,
        212, 166, 121, 132, 148, 205, 103, 163
    };
    if (memcmp(gpu_hash, gold1, 32) != 0) {
        fprintf(stderr, "[CUDA SELFTEST] Gold vector 1 mismatch!\n");
        xelis_cuda_free(&ctx);
        return -3;
    }

    uint8_t test_work[112];
    for (int i = 0; i < 112; i++) test_work[i] = (uint8_t)(i * 13 + 7);
    rc = xelis_cuda_mine_batch(&ctx, test_work, max_target, 15782ULL, &nonce, gpu_hash, NULL);
    xelis_cuda_free(&ctx);
    if (rc != 1) return -4;

    for (int k = 0; k < 8; k++) test_work[40 + k] = (uint8_t)(15782ULL >> (56 - k * 8));
    uint64_t *cpu_scratch = (uint64_t *)calloc(XELIS_MEMSIZE, sizeof(uint64_t));
    uint8_t cpu_hash[32];
    xelis_hash_v3_cpu(test_work, cpu_hash, cpu_scratch);
    free(cpu_scratch);

    if (memcmp(gpu_hash, cpu_hash, 32) != 0) {
        fprintf(stderr, "[CUDA SELFTEST] Nonce injection mismatch against CPU reference!\n");
        return -5;
    }

    printf("[CUDA SELFTEST] GPU hash matches official XelisHash V3 gold vector & CPU nonce injection!\n");
    return 0;
}
