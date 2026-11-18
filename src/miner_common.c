#include "miner_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_to_bytes(const char *hex, uint8_t *out, size_t expected_bytes) {
    if (!hex || !out) return -1;
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;
    size_t len = strlen(hex);
    if (len != expected_bytes * 2) return -1;
    for (size_t i = 0; i < expected_bytes; i++) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

void bytes_to_hex(const uint8_t *in, size_t len, char *out_hex) {
    static const char HEX[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out_hex[i * 2]     = HEX[(in[i] >> 4) & 0xf];
        out_hex[i * 2 + 1] = HEX[in[i] & 0xf];
    }
    out_hex[len * 2] = '\0';
}

/* Portable 96-bit / 64-bit division for U256::MAX / difficulty (MSVC + GCC compatible) */
static void div96_by_64(uint64_t rem_hi, uint32_t limb_lo, uint64_t d, uint32_t *out_q, uint64_t *out_rem) {
    uint64_t r = rem_hi % d;
    uint32_t q = 0;
    for (int k = 31; k >= 0; k--) {
        uint64_t bit = (limb_lo >> k) & 1ULL;
        uint64_t overflow = r >> 63;
        r = (r << 1) | bit;
        q <<= 1;
        if (overflow || r >= d) {
            r -= d;
            q |= 1u;
        }
    }
    *out_q = q;
    *out_rem = r;
}

/* Compute U256::MAX / difficulty (256-bit unsigned division by u64) */
int compute_target_from_u64(uint64_t difficulty, uint8_t target_be[32]) {
    if (difficulty == 0) return -1;
    uint64_t rem = 0;
    for (int i = 0; i < 8; i++) {
        uint32_t q = 0;
        div96_by_64(rem, 0xFFFFFFFFu, difficulty, &q, &rem);
        target_be[i * 4 + 0] = (uint8_t)(q >> 24);
        target_be[i * 4 + 1] = (uint8_t)(q >> 16);
        target_be[i * 4 + 2] = (uint8_t)(q >> 8);
        target_be[i * 4 + 3] = (uint8_t)(q);
    }
    return 0;
}

int compute_target_from_dec(const char *dec_str, uint8_t target_be[32]) {
    if (!dec_str || !*dec_str) return -1;
    uint64_t d = strtoull(dec_str, NULL, 10);
    if (d == 0) return -1;
    return compute_target_from_u64(d, target_be);
}

int hash_meets_target(const uint8_t hash[32], const uint8_t target_be[32]) {
    return memcmp(hash, target_be, 32) <= 0;
}

void format_pool_credentials(const miner_config_t *cfg,
                             char *out_user, size_t user_sz,
                             char *out_worker, size_t worker_sz) {
    const char *worker = (cfg->worker[0] != '\0') ? cfg->worker : "xelis_gpu";
    snprintf(out_worker, worker_sz, "%s", worker);

    if (cfg->pool_mode == POOL_MODE_UNMINEABLE) {
        const char *coin = (cfg->coin[0] != '\0') ? cfg->coin : "XEL";
        if (cfg->referral[0] != '\0') {
            snprintf(out_user, user_sz, "%s:%s.%s#%s", coin, cfg->wallet, worker, cfg->referral);
        } else {
            snprintf(out_user, user_sz, "%s:%s.%s", coin, cfg->wallet, worker);
        }
    } else if (cfg->pool_mode == POOL_MODE_F2POOL) {
        const char *acc = (cfg->alias[0] != '\0') ? cfg->alias : cfg->wallet;
        snprintf(out_user, user_sz, "%s.%s", acc, worker);
    } else {
        if (cfg->alias[0] != '\0') {
            snprintf(out_user, user_sz, "%s.%s", cfg->alias, worker);
        } else {
            snprintf(out_user, user_sz, "%s", cfg->wallet);
        }
    }
}

int parse_miner_url(const char *url, miner_config_t *cfg) {
    if (!url || !cfg) return -1;
    snprintf(cfg->url, sizeof(cfg->url), "%s", url);
    cfg->path[0] = '\0';

    const char *p = url;
    if (strncmp(p, "stratum++ssl://", 15) == 0) {
        cfg->proto = PROTO_STRATUM_SSL; p += 15;
    } else if (strncmp(p, "stratum+ssl://", 14) == 0) {
        cfg->proto = PROTO_STRATUM_SSL; p += 14;
    } else if (strncmp(p, "ssl://", 6) == 0) {
        cfg->proto = PROTO_STRATUM_SSL; p += 6;
    } else if (strncmp(p, "stratum++tcp://", 15) == 0) {
        cfg->proto = PROTO_STRATUM_TCP; p += 15;
    } else if (strncmp(p, "stratum+tcp://", 14) == 0) {
        cfg->proto = PROTO_STRATUM_TCP; p += 14;
    } else if (strncmp(p, "tcp://", 6) == 0) {
        cfg->proto = PROTO_STRATUM_TCP; p += 6;
    } else if (strncmp(p, "wss://", 6) == 0) {
        cfg->proto = PROTO_XELIS_WSS; p += 6;
    } else if (strncmp(p, "ws://", 5) == 0) {
        cfg->proto = PROTO_XELIS_WS; p += 5;
    } else {
        cfg->proto = PROTO_STRATUM_TCP;
    }

    const char *slash = strchr(p, '/');
    char hostport[256];
    if (slash) {
        size_t hp_len = (size_t)(slash - p);
        if (hp_len >= sizeof(hostport)) hp_len = sizeof(hostport) - 1;
        memcpy(hostport, p, hp_len);
        hostport[hp_len] = '\0';
        snprintf(cfg->path, sizeof(cfg->path), "%s", slash);
    } else {
        snprintf(hostport, sizeof(hostport), "%s", p);
    }

    char *colon = strrchr(hostport, ':');
    if (colon) {
        *colon = '\0';
        snprintf(cfg->host, sizeof(cfg->host), "%s", hostport);
        cfg->port = (uint16_t)atoi(colon + 1);
    } else {
        snprintf(cfg->host, sizeof(cfg->host), "%s", hostport);
        cfg->port = (cfg->proto == PROTO_STRATUM_SSL || cfg->proto == PROTO_XELIS_WSS) ? 443 :
                    (cfg->proto == PROTO_XELIS_WS) ? 8080 : 3333;
    }
    return 0;
}

int json_extract_string(const char *json, const char *key, char *out, size_t out_sz) {
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *k = strstr(json, pat);
    if (!k) return -1;
    k += strlen(pat);
    while (*k && (*k == ' ' || *k == ':' || *k == '\t')) k++;
    if (*k != '"') return -1;
    k++;
    size_t i = 0;
    while (*k && *k != '"' && i + 1 < out_sz) {
        if (*k == '\\' && k[1]) k++;
        out[i++] = *k++;
    }
    out[i] = '\0';
    return (*k == '"') ? 0 : -1;
}

int json_extract_u64(const char *json, const char *key, uint64_t *out) {
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *k = strstr(json, pat);
    if (!k) return -1;
    k += strlen(pat);
    while (*k && (*k == ' ' || *k == ':' || *k == '\t')) k++;
    if (*k == '"') k++;
    if (!isdigit((unsigned char)*k)) return -1;
    *out = strtoull(k, NULL, 10);
    return 0;
}
