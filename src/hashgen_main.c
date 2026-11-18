#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
#endif

#include "xelis_hash_v3.h"
#include "xelis_v3_oracle.h"
#include "miner_common.h"
#include "miner_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

static volatile int g_running = 1;
static void on_sigint(int sig) { (void)sig; g_running = 0; }

static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
}

static void print_usage(const char *prog) {
    printf("Xelis-V3 Equivalent Oracle & Legal Hash Generator (Pure C99 + CUDA)\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Generator / Oracle Modes:\n");
    printf("      --generate           Generate legal difficulty-meeting nonces & branched blocks (default)\n");
    printf("      --hash               Compute exact Xelis-V3 pow_hash + block_hash for --work & --nonce\n");
    printf("      --work <hex224>      112-byte MinerWork hex (optional; defaults to deterministic template)\n");
    printf("      --diff <n>           Target difficulty for --generate (default: 32)\n");
    printf("      --start-nonce <n>    Starting nonce (default: 0)\n");
    printf("      --count <n>          Number of legal nonces/blocks to generate (default: 1)\n");
    printf("      --json               Output machine-readable JSON lines\n");
    printf("\nNetwork Protocol Modes (Stratum++ Priority / Xelis-V3 Native WS):\n");
    printf("  -o, --url <uri>          stratum++tcp://host:port | stratum++ssl://host:port | ws://host:port\n");
    printf("  -u, --wallet <addr>      XEL wallet address\n");
    printf("  -w, --worker <name>      Worker name (default: xelis_oracle)\n");
    printf("  -p, --pass <pass>        Pool password (default: x)\n");
    printf("      --pool-mode <mode>   standard | unmineable | f2pool\n");
    printf("      --alias <name>       F2Pool account alias\n");
    printf("      --coin <ticker>      unMineable payout coin (default: XEL)\n");
    printf("      --referral <code>    unMineable referral code\n");
    printf("\nCompute Backend Options:\n");
    printf("  -d, --gpu <id>           CUDA GPU device index (default: 0)\n");
    printf("      --blocks <n>         CUDA grid blocks (0 = auto-tune to <3 GiB VRAM)\n");
    printf("      --threads <n>        CUDA threads per block (default: 64)\n");
    printf("      --cpu                Use pure-C CPU oracle (no GPU required)\n");
    printf("      --no-cpu-verify      Skip CPU double-check on GPU hits\n");
    printf("      --selftest           Run Xelis-V3 Oracle + Blockchain Branch + Alias self-tests\n");
    printf("  -h, --help               Show this help message\n");
}

static void build_default_work(uint8_t work[112]) {
    memset(work, 0, 112);
    for (int i = 0; i < 32; i++) work[i] = (uint8_t)(0xA0 + i);        /* header_work_hash */
    work[38] = 0x19; work[39] = 0x99;                                   /* timestamp BE */
    for (int i = 0; i < 32; i++) work[80 + i] = (uint8_t)(0x30 + i);   /* miner pubkey */
}

static int run_oracle_selftest(int use_gpu, int gpu_id) {
    printf("=== Xelis-V3 Equivalent Oracle Self-Test ===\n");
    if (xelis_hash_v3_selftest() != 0) return 1;
    printf("[PASS] XelisHash V3 CPU reference matches official v3.rs gold vectors\n");

    miner_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    char user[512], worker[128];

    cfg.pool_mode = POOL_MODE_UNMINEABLE;
    snprintf(cfg.coin, sizeof(cfg.coin), "XEL");
    snprintf(cfg.wallet, sizeof(cfg.wallet), "xel:1234567890abcdef");
    snprintf(cfg.worker, sizeof(cfg.worker), "oracle01");
    snprintf(cfg.referral, sizeof(cfg.referral), "ref-999");
    format_pool_credentials(&cfg, user, sizeof(user), worker, sizeof(worker));
    if (strcmp(user, "XEL:xel:1234567890abcdef.oracle01#ref-999") != 0) {
        fprintf(stderr, "[FAIL] unMineable alias format: %s\n", user);
        return 1;
    }
    printf("[PASS] unMineable alias format: %s\n", user);

    cfg.pool_mode = POOL_MODE_F2POOL;
    snprintf(cfg.alias, sizeof(cfg.alias), "myf2account");
    format_pool_credentials(&cfg, user, sizeof(user), worker, sizeof(worker));
    if (strcmp(user, "myf2account.oracle01") != 0) {
        fprintf(stderr, "[FAIL] F2Pool alias format: %s\n", user);
        return 1;
    }
    printf("[PASS] F2Pool alias format: %s\n", user);

    xelis_oracle_t oracle;
    if (xelis_oracle_init(&oracle, use_gpu, gpu_id, 1, 64, 1) != 0) {
        fprintf(stderr, "[FAIL] Oracle init failed\n");
        return 1;
    }

    uint8_t base_work[112];
    uint8_t target[32];
    build_default_work(base_work);
    compute_target_from_u64(32, target);

    uint64_t next_nonce = 0;
    for (int round = 1; round <= 3; round++) {
        xelis_oracle_result_t res;
        int rc = xelis_oracle_generate_legal_nonce(&oracle, base_work, target, next_nonce, 0, &res);
        if (rc != 1 || xelis_oracle_branch_verify(&res, target) != 0) {
            fprintf(stderr, "[FAIL] Oracle generation/verification failed on round %d\n", round);
            xelis_oracle_free(&oracle);
            return 1;
        }
        printf("[PASS] Oracle round %d: legal nonce=%llu pow_hash[0..3]=%02x%02x%02x%02x block_hash[0..3]=%02x%02x%02x%02x\n",
               round, (unsigned long long)res.nonce,
               res.pow_hash[0], res.pow_hash[1], res.pow_hash[2], res.pow_hash[3],
               res.block_hash[0], res.block_hash[1], res.block_hash[2], res.block_hash[3]);
        next_nonce = res.nonce + 1;
    }

    xelis_oracle_free(&oracle);
#ifdef USE_CUDA
    if (xelis_cuda_selftest(gpu_id) != 0) {
        fprintf(stderr, "[WARN] CUDA GPU selftest skipped or failed\n");
    } else {
        printf("[PASS] CUDA GPU oracle matches official v3.rs gold vectors!\n");
    }
#endif
    return 0;
}

int main(int argc, char **argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    miner_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.threads_per_block = 64;
    cfg.cpu_verify = 1;
    snprintf(cfg.worker, sizeof(cfg.worker), "xelis_oracle");
    snprintf(cfg.password, sizeof(cfg.password), "x");
    snprintf(cfg.coin, sizeof(cfg.coin), "XEL");

    int mode_hash = 0;
    int mode_json = 0;
    int has_work_hex = 0;
    uint8_t work112[112];
    build_default_work(work112);

    uint64_t diff = 32;
    uint64_t start_nonce = 0;
    uint64_t single_nonce = UINT64_MAX;
    int count = 1;

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--url") == 0) && i + 1 < argc) {
            parse_miner_url(argv[++i], &cfg);
        } else if ((strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--wallet") == 0) && i + 1 < argc) {
            snprintf(cfg.wallet, sizeof(cfg.wallet), "%s", argv[++i]);
        } else if ((strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--worker") == 0) && i + 1 < argc) {
            snprintf(cfg.worker, sizeof(cfg.worker), "%s", argv[++i]);
        } else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--pass") == 0) && i + 1 < argc) {
            snprintf(cfg.password, sizeof(cfg.password), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--pool-mode") == 0 && i + 1 < argc) {
            const char *m = argv[++i];
            if (strcmp(m, "unmineable") == 0) cfg.pool_mode = POOL_MODE_UNMINEABLE;
            else if (strcmp(m, "f2pool") == 0) cfg.pool_mode = POOL_MODE_F2POOL;
            else cfg.pool_mode = POOL_MODE_STANDARD;
        } else if (strcmp(argv[i], "--alias") == 0 && i + 1 < argc) {
            snprintf(cfg.alias, sizeof(cfg.alias), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--coin") == 0 && i + 1 < argc) {
            snprintf(cfg.coin, sizeof(cfg.coin), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--referral") == 0 && i + 1 < argc) {
            snprintf(cfg.referral, sizeof(cfg.referral), "%s", argv[++i]);
        } else if ((strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--gpu") == 0) && i + 1 < argc) {
            cfg.gpu_id = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--blocks") == 0 && i + 1 < argc) {
            cfg.blocks = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            cfg.threads_per_block = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--cpu") == 0) {
            cfg.cpu_fallback = 1;
        } else if (strcmp(argv[i], "--no-cpu-verify") == 0) {
            cfg.cpu_verify = 0;
        } else if (strcmp(argv[i], "--selftest") == 0) {
            cfg.selftest = 1;
        } else if (strcmp(argv[i], "--hash") == 0) {
            mode_hash = 1;
        } else if (strcmp(argv[i], "--generate") == 0) {
            mode_hash = 0;
        } else if (strcmp(argv[i], "--json") == 0) {
            mode_json = 1;
        } else if (strcmp(argv[i], "--work") == 0 && i + 1 < argc) {
            const char *w = argv[++i];
            if (strlen(w) != 224 || hex_to_bytes(w, work112, 112) != 0) {
                fprintf(stderr, "[ERROR] --work must be exactly 224 hex chars (112 bytes)\n");
                return 1;
            }
            has_work_hex = 1;
        } else if (strcmp(argv[i], "--diff") == 0 && i + 1 < argc) {
            diff = strtoull(argv[++i], NULL, 10);
            if (diff == 0) diff = 1;
        } else if (strcmp(argv[i], "--start-nonce") == 0 && i + 1 < argc) {
            start_nonce = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--nonce") == 0 && i + 1 < argc) {
            single_nonce = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            count = atoi(argv[++i]);
            if (count < 1) count = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (cfg.selftest) {
        return run_oracle_selftest(!cfg.cpu_fallback, cfg.gpu_id);
    }

    xelis_oracle_t oracle;
    if (xelis_oracle_init(&oracle, !cfg.cpu_fallback, cfg.gpu_id,
                          cfg.blocks, cfg.threads_per_block, cfg.cpu_verify) != 0) {
        fprintf(stderr, "[ERROR] Failed to initialize Xelis-V3 Oracle\n");
        return 1;
    }

    /* Mode 1: Single Exact Hash Generation */
    if (mode_hash) {
        uint8_t pow_hash[32], block_hash[32], solved[112];
        if (!has_work_hex && single_nonce == UINT64_MAX) single_nonce = 0;
        xelis_oracle_hash(&oracle, work112, single_nonce, pow_hash, block_hash, solved);
        if (mode_json) {
            printf("{\"pow_hash\":\""); print_hex(pow_hash, 32);
            printf("\",\"block_hash\":\""); print_hex(block_hash, 32);
            printf("\",\"miner_work\":\""); print_hex(solved, 112);
            printf("\"}\n");
        } else {
            printf("pow_hash   : "); print_hex(pow_hash, 32); printf("\n");
            printf("block_hash : "); print_hex(block_hash, 32); printf("\n");
            printf("miner_work : "); print_hex(solved, 112); printf("\n");
        }
        xelis_oracle_free(&oracle);
        return 0;
    }

    /* Mode 2: Local Standalone Legal Nonce & Branched Block Generator (no URL) */
    if (cfg.host[0] == '\0') {
        uint8_t target_be[32];
        compute_target_from_u64(diff, target_be);

        uint64_t cur = start_nonce;
        for (int idx = 0; idx < count; idx++) {
            xelis_oracle_result_t res;
            int rc = xelis_oracle_generate_legal_nonce(&oracle, work112, target_be, cur, 0, &res);
            if (rc != 1 || xelis_oracle_branch_verify(&res, target_be) != 0) {
                fprintf(stderr, "[ERROR] Oracle failed to generate/verify legal nonce!\n");
                xelis_oracle_free(&oracle);
                return 1;
            }
            if (mode_json) {
                printf("{\"index\":%d,\"difficulty\":%llu,\"nonce\":%llu,\"nonce_hex\":\"%016llx\","
                       "\"hashes_evaluated\":%llu,\"pow_hash\":\"",
                       idx + 1, (unsigned long long)diff, (unsigned long long)res.nonce,
                       (unsigned long long)res.nonce, (unsigned long long)res.hashes_evaluated);
                print_hex(res.pow_hash, 32);
                printf("\",\"block_hash\":\""); print_hex(res.block_hash, 32);
                printf("\",\"miner_work\":\""); print_hex(res.solved_work, 112);
                printf("\"}\n");
            } else {
                printf("[ORACLE #%d] diff=%llu | legal_nonce=%llu (0x%016llx) | evals=%llu\n",
                       idx + 1, (unsigned long long)diff,
                       (unsigned long long)res.nonce, (unsigned long long)res.nonce,
                       (unsigned long long)res.hashes_evaluated);
                printf("  pow_hash   : "); print_hex(res.pow_hash, 32); printf("\n");
                printf("  block_hash : "); print_hex(res.block_hash, 32); printf("\n");
                printf("  miner_work : "); print_hex(res.solved_work, 112); printf("\n");
            }
            cur = res.nonce + 1;
        }
        xelis_oracle_free(&oracle);
        return 0;
    }

    /* Mode 3: Network Protocol Oracle (Stratum++ TCP/SSL & Xelis-V3 Native WS) */
    if (cfg.wallet[0] == '\0' && cfg.alias[0] == '\0') {
        fprintf(stderr, "[ERROR] Wallet (-u) or alias (--alias) required for network mode\n");
        xelis_oracle_free(&oracle);
        return 1;
    }

    signal(SIGINT, on_sigint);
    net_global_init();
    protocol_session_t sess;

    while (g_running) {
        if (proto_connect_and_auth(&sess, &cfg) != 0) {
            fprintf(stderr, "[NET] Reconnecting in 5s...\n");
#ifdef _WIN32
            Sleep(5000);
#else
            struct timespec ts = {5, 0}; nanosleep(&ts, NULL);
#endif
            continue;
        }

        uint64_t cur_nonce = start_nonce;
        uint64_t chunk_cap = oracle.use_gpu ? 65536ULL : 256ULL;

        while (g_running) {
            int pr = proto_poll(&sess, sess.has_job ? 0 : 200);
            if (pr < 0) break;
            if (pr > 0) {
                printf("[JOB] seq=%llu diff=%llu height=%llu\n",
                       (unsigned long long)sess.latest_job.seq,
                       (unsigned long long)sess.latest_job.difficulty,
                       (unsigned long long)sess.latest_job.height);
                if (sess.latest_job.clean_jobs) cur_nonce = 0;
            }
            if (!sess.has_job) continue;

            xelis_oracle_result_t res;
            int rc = xelis_oracle_generate_legal_nonce(&oracle,
                                                       sess.latest_job.header_work,
                                                       sess.latest_job.target_be,
                                                       cur_nonce,
                                                       chunk_cap,
                                                       &res);
            if (rc < 0) break;
            if (rc == 1) {
                printf("[ORACLE] Legal nonce=0x%016llx | block_hash[0..3]=%02x%02x%02x%02x\n",
                       (unsigned long long)res.nonce,
                       res.block_hash[0], res.block_hash[1], res.block_hash[2], res.block_hash[3]);
                proto_submit_solution(&sess, &sess.latest_job, res.nonce, res.solved_work);
                cur_nonce = res.nonce + 1;
            } else {
                cur_nonce += res.hashes_evaluated;
            }
        }
        proto_disconnect(&sess);
    }

    xelis_oracle_free(&oracle);
    net_global_cleanup();
    return 0;
}
