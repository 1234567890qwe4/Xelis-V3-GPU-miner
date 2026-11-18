#ifndef MINER_COMMON_H
#define MINER_COMMON_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PROTO_STRATUM_TCP = 0,
    PROTO_STRATUM_SSL = 1,
    PROTO_XELIS_WS    = 2,
    PROTO_XELIS_WSS   = 3
} protocol_type_t;

typedef enum {
    POOL_MODE_STANDARD   = 0,
    POOL_MODE_UNMINEABLE = 1,
    POOL_MODE_F2POOL     = 2
} pool_mode_t;

typedef struct {
    char            url[512];
    protocol_type_t proto;
    char            host[256];
    uint16_t        port;
    char            path[256];

    pool_mode_t     pool_mode;
    char            wallet[256];
    char            alias[128];     /* F2Pool account alias or unMineable coin */
    char            coin[32];       /* unMineable payout coin e.g. XEL, USDT, BTC */
    char            worker[128];
    char            referral[64];   /* unMineable referral code */
    char            password[128];

    int             gpu_id;
    int             threads_per_block;
    int             blocks;         /* 0 = auto-tune to ~75% free VRAM */
    int             cpu_verify;     /* 1 = verify GPU hits on CPU before submit */
    int             cpu_fallback;   /* 1 = run CPU miner if no GPU or --cpu */
    int             selftest;
} miner_config_t;

typedef struct {
    char     job_id[128];
    uint8_t  header_work[112];  /* [0..32]=header_work_hash, [32..40]=ts_be, [40..48]=nonce_be, [48..80]=extranonce, [80..112]=pubkey */
    uint8_t  target_be[32];     /* U256::MAX / difficulty (big-endian) */
    uint64_t difficulty;
    uint64_t height;
    uint64_t topoheight;
    int      clean_jobs;
    uint64_t seq;               /* monotonic job sequence number */
} miner_job_t;

/* Hex utilities */
int  hex_to_bytes(const char *hex, uint8_t *out, size_t expected_bytes);
void bytes_to_hex(const uint8_t *in, size_t len, char *out_hex);

/* U256 difficulty -> 32-byte big-endian target = U256::MAX / difficulty */
int  compute_target_from_u64(uint64_t difficulty, uint8_t target_be[32]);
int  compute_target_from_dec(const char *dec_str, uint8_t target_be[32]);
int  hash_meets_target(const uint8_t hash[32], const uint8_t target_be[32]);

/* Format username/worker according to pool_mode (standard / unmineable / f2pool) */
void format_pool_credentials(const miner_config_t *cfg,
                             char *out_user, size_t user_sz,
                             char *out_worker, size_t worker_sz);

/* Parse pool/node URI into miner_config_t */
int  parse_miner_url(const char *url, miner_config_t *cfg);

/* Minimal JSON string/int/array helpers */
int  json_extract_string(const char *json, const char *key, char *out, size_t out_sz);
int  json_extract_u64(const char *json, const char *key, uint64_t *out);

#ifdef __cplusplus
}
#endif

#endif /* MINER_COMMON_H */
