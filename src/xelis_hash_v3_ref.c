#include "xelis_hash_v3.h"
#include <string.h>
#include <math.h>
#include <stdio.h>

/* =========================================================================
 * Portable 128-bit Unsigned Arithmetic (MSVC + GCC/Clang compatible)
 * ========================================================================= */
typedef struct {
    uint64_t hi;
    uint64_t lo;
} u128_t;

static inline u128_t u128_make(uint64_t hi, uint64_t lo) {
    u128_t v;
    v.hi = hi;
    v.lo = lo;
    return v;
}

static inline int u128_gt(u128_t a, u128_t b) {
    return (a.hi > b.hi) || (a.hi == b.hi && a.lo > b.lo);
}

static inline int u128_ge(u128_t a, u128_t b) {
    return (a.hi > b.hi) || (a.hi == b.hi && a.lo >= b.lo);
}

static inline u128_t u128_sub(u128_t a, u128_t b) {
    u128_t r;
    r.lo = a.lo - b.lo;
    r.hi = a.hi - b.hi - (a.lo < b.lo ? 1ULL : 0ULL);
    return r;
}

static inline uint64_t umul64_hi_portable(uint64_t a, uint64_t b) {
    uint64_t a_lo = (uint32_t)a, a_hi = a >> 32;
    uint64_t b_lo = (uint32_t)b, b_hi = b >> 32;
    uint64_t p0 = a_lo * b_lo;
    uint64_t p1 = a_lo * b_hi;
    uint64_t p2 = a_hi * b_lo;
    uint64_t p3 = a_hi * b_hi;
    uint64_t mid = (p0 >> 32) + (uint32_t)p1 + (uint32_t)p2;
    return p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
}

static inline uint64_t u128_rem64(uint64_t hi, uint64_t lo, uint64_t d) {
    if (hi == 0) return lo % d;
    uint64_t r = hi % d;
    for (int k = 63; k >= 0; k--) {
        uint64_t bit = (lo >> k) & 1ULL;
        uint64_t overflow = r >> 63;
        r = (r << 1) | bit;
        if (overflow || r >= d) r -= d;
    }
    return r;
}

static inline uint64_t u128_div64_lo(uint64_t hi, uint64_t lo, uint64_t d) {
    if (hi == 0) return lo / d;
    uint64_t r = hi % d;
    uint64_t q = 0;
    for (int k = 63; k >= 0; k--) {
        uint64_t bit = (lo >> k) & 1ULL;
        uint64_t overflow = r >> 63;
        r = (r << 1) | bit;
        q <<= 1;
        if (overflow || r >= d) {
            r -= d;
            q |= 1ULL;
        }
    }
    return q;
}

static inline void u128_divmod(u128_t num, u128_t den, uint64_t *out_q_lo, u128_t *out_rem) {
    if (den.hi == 0) {
        if (out_q_lo) *out_q_lo = u128_div64_lo(num.hi, num.lo, den.lo);
        if (out_rem) {
            out_rem->hi = 0;
            out_rem->lo = u128_rem64(num.hi, num.lo, den.lo);
        }
        return;
    }
    u128_t r = u128_make(0, 0);
    uint64_t q_lo = 0;
    for (int k = 127; k >= 0; k--) {
        uint64_t bit = (k >= 64) ? ((num.hi >> (k - 64)) & 1ULL) : ((num.lo >> k) & 1ULL);
        uint64_t overflow = r.hi >> 63;
        r.hi = (r.hi << 1) | (r.lo >> 63);
        r.lo = (r.lo << 1) | bit;
        q_lo <<= 1;
        if (overflow || u128_ge(r, den)) {
            r = u128_sub(r, den);
            q_lo |= 1ULL;
        }
    }
    if (out_q_lo) *out_q_lo = q_lo;
    if (out_rem) *out_rem = r;
}

static inline uint64_t mulmod64(uint64_t a, uint64_t b, uint64_t mod) {
    uint64_t lo = a * b;
    uint64_t hi = umul64_hi_portable(a, b);
    return u128_rem64(hi, lo, mod);
}

/* =========================================================================
 * Portable C99 BLAKE3 (supports arbitrary input lengths, including 543,744B)
 * ========================================================================= */
#define B3_CHUNK_LEN 1024
#define B3_BLOCK_LEN 64
#define B3_CHUNK_START (1u << 0)
#define B3_CHUNK_END   (1u << 1)
#define B3_PARENT      (1u << 2)
#define B3_ROOT        (1u << 3)

static const uint32_t B3_IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

static const uint8_t B3_MSG_PERM[16] = {
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
};

static inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t load32_le(const uint8_t *p) {
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void b3_g(uint32_t state[16], size_t a, size_t b, size_t c, size_t d,
                        uint32_t mx, uint32_t my) {
    state[a] = state[a] + state[b] + mx;
    state[d] = rotr32(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + my;
    state[d] = rotr32(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 7);
}

static void b3_compress(const uint32_t cv[8], const uint8_t block[64],
                        uint64_t counter, uint32_t block_len, uint32_t flags,
                        uint32_t out[16]) {
    uint32_t m[16];
    for (int i = 0; i < 16; i++) {
        m[i] = load32_le(block + i * 4);
    }
    uint32_t s[16] = {
        cv[0], cv[1], cv[2], cv[3],
        cv[4], cv[5], cv[6], cv[7],
        B3_IV[0], B3_IV[1], B3_IV[2], B3_IV[3],
        (uint32_t)counter, (uint32_t)(counter >> 32), block_len, flags
    };
    for (int r = 0; r < 7; r++) {
        b3_g(s, 0, 4,  8, 12, m[0],  m[1]);
        b3_g(s, 1, 5,  9, 13, m[2],  m[3]);
        b3_g(s, 2, 6, 10, 14, m[4],  m[5]);
        b3_g(s, 3, 7, 11, 15, m[6],  m[7]);
        b3_g(s, 0, 5, 10, 15, m[8],  m[9]);
        b3_g(s, 1, 6, 11, 12, m[10], m[11]);
        b3_g(s, 2, 7,  8, 13, m[12], m[13]);
        b3_g(s, 3, 4,  9, 14, m[14], m[15]);
        if (r < 6) {
            uint32_t perm[16];
            for (int i = 0; i < 16; i++) perm[i] = m[B3_MSG_PERM[i]];
            memcpy(m, perm, sizeof(m));
        }
    }
    for (int i = 0; i < 8; i++) {
        s[i] ^= s[i + 8];
        s[i + 8] ^= cv[i];
    }
    memcpy(out, s, 64);
}

static void b3_chunk_cv(const uint8_t *chunk, size_t len, uint64_t chunk_counter,
                        uint32_t out_cv[8], int is_root_only) {
    uint32_t cv[8];
    memcpy(cv, B3_IV, sizeof(cv));
    size_t offset = 0;
    size_t num_blocks = (len == 0) ? 1 : (len + B3_BLOCK_LEN - 1) / B3_BLOCK_LEN;
    for (size_t b = 0; b < num_blocks; b++) {
        uint8_t block[64];
        memset(block, 0, 64);
        size_t take = (len > offset) ? (len - offset) : 0;
        if (take > B3_BLOCK_LEN) take = B3_BLOCK_LEN;
        if (take > 0) memcpy(block, chunk + offset, take);

        uint32_t flags = 0;
        if (b == 0) flags |= B3_CHUNK_START;
        if (b == num_blocks - 1) {
            flags |= B3_CHUNK_END;
            if (is_root_only) flags |= B3_ROOT;
        }
        uint32_t out[16];
        b3_compress(cv, block, chunk_counter, (uint32_t)take, flags, out);
        memcpy(cv, out, 32);
        offset += take;
    }
    memcpy(out_cv, cv, 32);
}

void xelis_blake3_hash(const uint8_t *input, size_t len, uint8_t output[32]) {
    if (len <= B3_CHUNK_LEN) {
        uint32_t cv[8];
        b3_chunk_cv(input, len, 0, cv, 1);
        for (int i = 0; i < 8; i++) store32_le(output + i * 4, cv[i]);
        return;
    }

    uint32_t cv_stack[54][8];
    uint8_t stack_len = 0;
    uint64_t chunk_idx = 0;
    size_t offset = 0;

    while (offset < len) {
        size_t take = len - offset;
        if (take > B3_CHUNK_LEN) take = B3_CHUNK_LEN;
        int is_last = (offset + take == len);

        uint32_t cv[8];
        b3_chunk_cv(input + offset, take, chunk_idx, cv, 0);
        offset += take;
        chunk_idx++;

        uint64_t total_chunks = chunk_idx;
        if (!is_last) {
            while ((total_chunks & 1) == 0) {
                uint8_t parent_block[64];
                for (int i = 0; i < 8; i++) store32_le(parent_block + i * 4, cv_stack[stack_len - 1][i]);
                for (int i = 0; i < 8; i++) store32_le(parent_block + 32 + i * 4, cv[i]);
                stack_len--;
                uint32_t out[16];
                b3_compress(B3_IV, parent_block, 0, B3_BLOCK_LEN, B3_PARENT, out);
                memcpy(cv, out, 32);
                total_chunks >>= 1;
            }
            memcpy(cv_stack[stack_len++], cv, 32);
        } else {
            while (stack_len > 0) {
                uint8_t parent_block[64];
                for (int i = 0; i < 8; i++) store32_le(parent_block + i * 4, cv_stack[stack_len - 1][i]);
                for (int i = 0; i < 8; i++) store32_le(parent_block + 32 + i * 4, cv[i]);
                stack_len--;
                uint32_t flags = B3_PARENT | ((stack_len == 0) ? B3_ROOT : 0);
                uint32_t out[16];
                b3_compress(B3_IV, parent_block, 0, B3_BLOCK_LEN, flags, out);
                memcpy(cv, out, 32);
            }
            for (int i = 0; i < 8; i++) store32_le(output + i * 4, cv[i]);
        }
    }
}

/* =========================================================================
 * Portable C99 ChaCha8
 * ========================================================================= */
static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

#define CHACHA_QR(a, b, c, d) \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d, 8);  \
    c += d; b ^= c; b = rotl32(b, 7);

static void chacha8_keystream(const uint8_t key[32], const uint8_t nonce[12],
                              uint8_t *out, size_t bytes) {
    uint32_t state[16];
    state[0] = 0x61707865u;
    state[1] = 0x3320646eu;
    state[2] = 0x79622d32u;
    state[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++) state[4 + i] = load32_le(key + i * 4);
    state[12] = 0;
    for (int i = 0; i < 3; i++) state[13 + i] = load32_le(nonce + i * 4);

    size_t offset = 0;
    while (offset < bytes) {
        uint32_t x[16];
        memcpy(x, state, sizeof(x));
        for (int r = 0; r < 4; r++) {
            CHACHA_QR(x[0], x[4],  x[8], x[12]);
            CHACHA_QR(x[1], x[5],  x[9], x[13]);
            CHACHA_QR(x[2], x[6], x[10], x[14]);
            CHACHA_QR(x[3], x[7], x[11], x[15]);
            CHACHA_QR(x[0], x[5], x[10], x[15]);
            CHACHA_QR(x[1], x[6], x[11], x[12]);
            CHACHA_QR(x[2], x[7],  x[8], x[13]);
            CHACHA_QR(x[3], x[4],  x[9], x[14]);
        }
        for (int i = 0; i < 16; i++) x[i] += state[i];

        size_t take = bytes - offset;
        if (take >= 64) {
            for (int i = 0; i < 16; i++) store32_le(out + offset + i * 4, x[i]);
            offset += 64;
        } else {
            uint8_t tmp[64];
            for (int i = 0; i < 16; i++) store32_le(tmp + i * 4, x[i]);
            memcpy(out + offset, tmp, take);
            offset += take;
        }
        state[12]++;
    }
}

/* =========================================================================
 * Portable C99 AES Single Round
 * ========================================================================= */
static const uint8_t AES_SBOX[256] = {
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

static inline uint8_t gf_mul2(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

static void aes_single_round_portable(uint8_t block[16], const uint8_t key[16]) {
    uint8_t s[16];
    for (int i = 0; i < 16; i++) s[i] = AES_SBOX[block[i]];

    uint8_t t[16];
    t[0]  = s[0];  t[1]  = s[5];  t[2]  = s[10]; t[3]  = s[15];
    t[4]  = s[4];  t[5]  = s[9];  t[6]  = s[14]; t[7]  = s[3];
    t[8]  = s[8];  t[9]  = s[13]; t[10] = s[2];  t[11] = s[7];
    t[12] = s[12]; t[13] = s[1];  t[14] = s[6];  t[15] = s[11];

    for (int c = 0; c < 4; c++) {
        uint8_t a0 = t[c * 4 + 0];
        uint8_t a1 = t[c * 4 + 1];
        uint8_t a2 = t[c * 4 + 2];
        uint8_t a3 = t[c * 4 + 3];
        uint8_t x = a0 ^ a1 ^ a2 ^ a3;
        block[c * 4 + 0] = (uint8_t)(a0 ^ x ^ gf_mul2(a0 ^ a1)) ^ key[c * 4 + 0];
        block[c * 4 + 1] = (uint8_t)(a1 ^ x ^ gf_mul2(a1 ^ a2)) ^ key[c * 4 + 1];
        block[c * 4 + 2] = (uint8_t)(a2 ^ x ^ gf_mul2(a2 ^ a3)) ^ key[c * 4 + 2];
        block[c * 4 + 3] = (uint8_t)(a3 ^ x ^ gf_mul2(a3 ^ a0)) ^ key[c * 4 + 3];
    }
}

/* =========================================================================
 * XelisHash V3 Stage 1 & Stage 3 & Stage 4
 * ========================================================================= */
static inline uint64_t rotl64(uint64_t x, uint32_t r) {
    r &= 63u;
    return (r == 0) ? x : ((x << r) | (x >> (64 - r)));
}

static inline uint64_t rotr64(uint64_t x, uint32_t r) {
    r &= 63u;
    return (r == 0) ? x : ((x >> r) | (x << (64 - r)));
}

static inline uint64_t murmurhash3(uint64_t seed) {
    seed ^= seed >> 55;
    seed *= 0xff51afd7ed558ccdULL;
    seed ^= seed >> 32;
    seed *= 0xc4ceb9fe1a85ec53ULL;
    seed ^= seed >> 15;
    return seed;
}

static inline uint64_t map_index(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    return umul64_hi_portable(x, (uint64_t)XELIS_BUFSIZE);
}

static inline int pick_half(uint64_t seed) {
    return (murmurhash3(seed) & (1ULL << 58)) != 0;
}

static inline uint64_t isqrt64(uint64_t n) {
    if (n < 2) return n;
    uint64_t approx = (uint64_t)sqrt((double)n);
    if (approx > 0xFFFFFFFFULL) approx = 0xFFFFFFFFULL;
    if (approx * approx > n) return approx - 1;
    if (approx < 0xFFFFFFFFULL && (approx + 1) * (approx + 1) <= n) return approx + 1;
    return approx;
}

static uint64_t modular_power(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) {
            result = mulmod64(result, base, mod);
        }
        base = mulmod64(base, base, mod);
        exp >>= 1;
    }
    return result;
}

static inline void u64_to_le(uint64_t v, uint8_t b[8]) {
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (i * 8));
}

static inline uint64_t le_to_u64(const uint8_t b[8]) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | b[i];
    return v;
}

static void stage1(const uint8_t input[XELIS_INPUT_LEN], uint8_t scratch_pad[XELIS_OUTPUT_SIZE]) {
    uint8_t key[32 * 4];
    memset(key, 0, sizeof(key));
    memcpy(key, input, XELIS_INPUT_LEN);

    uint8_t input_hash[32];
    uint8_t buffer[64];
    xelis_blake3_hash(input, XELIS_INPUT_LEN, buffer);

    uint8_t *t = scratch_pad;
    size_t chunk_out = XELIS_OUTPUT_SIZE / 4;

    memcpy(buffer + 32, key + 0 * 32, 32);
    xelis_blake3_hash(buffer, 64, input_hash);
    chacha8_keystream(input_hash, buffer, t, chunk_out);

    for (int c = 1; c < 4; c++) {
        t += chunk_out;
        memcpy(buffer, input_hash, 32);
        memcpy(buffer + 32, key + c * 32, 32);
        xelis_blake3_hash(buffer, 64, input_hash);
        chacha8_keystream(input_hash, t - 12, t, chunk_out);
    }
}

static void stage3(uint64_t scratch[XELIS_MEMSIZE]) {
    static const uint8_t POW_KEY[16] = "xelishash-pow-v3";
    uint64_t *mem_buffer_a = scratch;
    uint64_t *mem_buffer_b = &scratch[XELIS_BUFSIZE];

    uint64_t addr_a = mem_buffer_b[XELIS_BUFSIZE - 1];
    uint64_t addr_b = mem_buffer_a[XELIS_BUFSIZE - 1] >> 32;
    uint32_t r = 0;

    for (uint32_t i = 0; i < XELIS_ITERS; i++) {
        uint64_t mem_a = mem_buffer_a[map_index(addr_a)];
        uint64_t mem_b = mem_buffer_b[map_index(mem_a ^ addr_b)];

        uint8_t block[16];
        u64_to_le(mem_b, block);
        u64_to_le(mem_a, block + 8);
        aes_single_round_portable(block, POW_KEY);

        uint64_t hash1 = le_to_u64(block);
        uint64_t hash2 = le_to_u64(block + 8);
        uint64_t result = ~(hash1 ^ hash2);

        for (uint32_t j = 0; j < XELIS_BUFSIZE; j++) {
            uint64_t a = mem_buffer_a[map_index(result)];
            uint64_t b = mem_buffer_b[map_index(a ^ ~rotr64(result, r))];
            uint64_t c = (r < XELIS_BUFSIZE) ? mem_buffer_a[r] : mem_buffer_b[r - XELIS_BUFSIZE];
            r = (r < XELIS_MEMSIZE - 1) ? (r + 1) : 0;

            uint64_t v = 0;
            switch (rotl64(result, (uint32_t)c) & 0xfu) {
                case 0: {
                    uint64_t denom = murmurhash3(c ^ result ^ i ^ j) | 1ULL;
                    v = u128_rem64(a + i, isqrt64(b + j), denom);
                    break;
                }
                case 1:
                    v = rotl64((c + i) % isqrt64(b | 2ULL), i + j) * isqrt64(a + j);
                    break;
                case 2:
                    v = (isqrt64(a + i) * isqrt64(c + j)) ^ (b + i + j);
                    break;
                case 3:  v = (a + b) * c; break;
                case 4:  v = (b - c) * a; break;
                case 5:  v = c - a + b; break;
                case 6:  v = a - b + c; break;
                case 7:  v = b * c + a; break;
                case 8:  v = c * a + b; break;
                case 9:  v = a * b * c; break;
                case 10:
                    v = u128_rem64(a, b, c | 1ULL);
                    break;
                case 11: {
                    u128_t t1 = u128_make(b, c);
                    u128_t t2 = u128_make(rotl64(result, r), a | 2ULL);
                    if (u128_gt(t2, t1)) {
                        v = c;
                    } else {
                        u128_t rem;
                        u128_divmod(t1, t2, NULL, &rem);
                        v = rem.lo;
                    }
                    break;
                }
                case 12:
                    v = u128_div64_lo(c, a, b | 4ULL);
                    break;
                case 13: {
                    u128_t t1 = u128_make(rotl64(result, r), b);
                    u128_t t2 = u128_make(a, c | 8ULL);
                    if (u128_gt(t1, t2)) {
                        uint64_t q_lo = 0;
                        u128_divmod(t1, t2, &q_lo, NULL);
                        v = q_lo;
                    } else {
                        v = a ^ b;
                    }
                    break;
                }
                case 14:
                    v = (b * c) + umul64_hi_portable(a, c);
                    break;
                case 15: {
                    uint64_t t2_hi = rotr64(result, r);
                    v = umul64_hi_portable(c, b) + (a * b) + (c * t2_hi);
                    break;
                }
            }

            uint64_t idx_seed = v ^ result;
            result = rotl64(idx_seed, r);

            uint64_t use_buffer_b = (uint64_t)pick_half(v);
            uint64_t idx_t = map_index(idx_seed);
            uint64_t t = (use_buffer_b ? mem_buffer_b[idx_t] : mem_buffer_a[idx_t]) ^ result;

            uint64_t idx_a = map_index(t ^ result ^ 0x9e3779b97f4a7c15ULL);
            uint64_t idx_b = map_index(idx_a ^ ~result ^ 0xd2b74407b1ce6e93ULL);

            uint64_t prev_a = mem_buffer_a[idx_a];
            mem_buffer_a[idx_a] = t;
            mem_buffer_b[idx_b] ^= prev_a ^ rotr64(t, i + j);
        }

        addr_a = modular_power(addr_a, addr_b, result);
        addr_b = isqrt64(result) * (r + 1) * isqrt64(addr_a);
    }
}

void xelis_hash_v3_cpu(const uint8_t input[XELIS_INPUT_LEN],
                       uint8_t hash[XELIS_HASH_SIZE],
                       uint64_t scratch[XELIS_MEMSIZE]) {
    uint8_t *scratch_u8 = (uint8_t *)scratch;
    stage1(input, scratch_u8);
    stage3(scratch);
    xelis_blake3_hash(scratch_u8, XELIS_OUTPUT_SIZE, hash);
}

int xelis_hash_v3_selftest(void) {
    static uint64_t scratch[XELIS_MEMSIZE];
    uint8_t out[XELIS_HASH_SIZE];

    uint8_t in1[XELIS_INPUT_LEN];
    memset(in1, 0, sizeof(in1));
    static const uint8_t gold1[XELIS_HASH_SIZE] = {
        105, 172, 103, 40, 94, 253, 92, 162,
        42, 252, 5, 196, 236, 238, 91, 218,
        22, 157, 228, 233, 239, 8, 250, 57,
        212, 166, 121, 132, 148, 205, 103, 163
    };
    xelis_hash_v3_cpu(in1, out, scratch);
    if (memcmp(out, gold1, XELIS_HASH_SIZE) != 0) {
        fprintf(stderr, "[SELFTEST] Vector 1 (zero_hash) FAILED!\n");
        return -1;
    }

    static const uint8_t in2[XELIS_INPUT_LEN] = {
        172, 236, 108, 212, 181, 31, 109, 45, 44, 242, 54, 225, 143, 133,
        89, 44, 179, 108, 39, 191, 32, 116, 229, 33, 63, 130, 33, 120, 185, 89,
        146, 141, 10, 79, 183, 107, 238, 122, 92, 222, 25, 134, 90, 107, 116,
        110, 236, 53, 255, 5, 214, 126, 24, 216, 97, 199, 148, 239, 253, 102,
        199, 184, 232, 253, 158, 145, 86, 187, 112, 81, 78, 70, 80, 110, 33,
        37, 159, 233, 198, 1, 178, 108, 210, 100, 109, 155, 106, 124, 124, 83,
        89, 50, 197, 115, 231, 32, 74, 2, 92, 47, 25, 220, 135, 249, 122,
        172, 220, 137, 143, 234, 68, 188
    };
    static const uint8_t gold2[XELIS_HASH_SIZE] = {
        242, 8, 176, 222, 203, 27, 104,
        187, 22, 40, 68, 73, 79, 79, 65,
        83, 138, 101, 10, 116, 194, 41, 153,
        21, 92, 163, 12, 206, 231, 156, 70, 83
    };
    xelis_hash_v3_cpu(in2, out, scratch);
    if (memcmp(out, gold2, XELIS_HASH_SIZE) != 0) {
        fprintf(stderr, "[SELFTEST] Vector 2 (verify_output) FAILED!\n");
        return -2;
    }

    return 0;
}
