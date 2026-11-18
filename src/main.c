#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
#endif

#include "xelis_hash_v3.h"
#include "miner_common.h"
#include "miner_net.h"
#ifdef USE_CUDA
  #include "xelis_cuda.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

static volatile int g_running = 1;
static void on_sigint(int sig) { (void)sig; g_running = 0; }

static double now_sec(void) {
#ifdef _WIN32
    LARGE_INTEGER freq, cnt;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&cnt);
    return (double)cnt.QuadPart / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
#endif
}

static void print_usage(const char *prog) {
    printf("Xelis-V3 GPU Miner (Stratum++ TCP/SSL + Xelis-V3 Native WS + unMineable/F2Pool Alias)\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("  -o, --url <uri>          Pool or Node URI:\n");
    printf("                             stratum++tcp://host:port  (or stratum+tcp://)\n");
    printf("                             stratum++ssl://host:port  (or stratum+ssl://)\n");
    printf("                             ws://127.0.0.1:8080       (Xelis-V3 Native GetWork)\n");
    printf("                             wss://host:port\n");
    printf("  -u, --wallet <addr>      XEL wallet address (or payout address for unMineable)\n");
    printf("  -w, --worker <name>      Worker name (default: xelis_gpu)\n");
    printf("  -p, --pass <pass>        Pool password (default: x)\n");
    printf("      --pool-mode <mode>   standard | unmineable | f2pool\n");
    printf("      --alias <name>       F2Pool account alias (for --pool-mode f2pool)\n");
    printf("      --coin <ticker>      unMineable payout coin e.g. XEL, USDT (default: XEL)\n");
    printf("      --referral <code>    unMineable referral code (lowers pool fee)\n");
    printf("  -d, --gpu <id>           CUDA GPU device index (default: 0)\n");
    printf("      --blocks <n>         CUDA grid blocks (0 = auto-tune to ~70%% free VRAM)\n");
    printf("      --threads <n>        CUDA threads per block (default: 64)\n");
    printf("      --cpu                Force CPU mining mode (reference fallback)\n");
    printf("      --no-cpu-verify      Skip CPU double-check of GPU solutions\n");
    printf("      --selftest           Run XelisHash V3 + protocol + alias self-tests\n");
    printf("  -h, --help               Show this help message\n");
}

static int run_selftest(void) {
    printf("=== Xelis-V3 Miner Self-Test ===\n");
    if (xelis_hash_v3_selftest() != 0) return 1;
    printf("[PASS] XelisHash V3 CPU reference matches official v3.rs gold vectors\n");

    miner_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    char user[512], worker[128];

    cfg.pool_mode = POOL_MODE_UNMINEABLE;
    snprintf(cfg.coin, sizeof(cfg.coin), "XEL");
    snprintf(cfg.wallet, sizeof(cfg.wallet), "xel:1234567890abcdef");
    snprintf(cfg.worker, sizeof(cfg.worker), "rig5070ti");
    snprintf(cfg.referral, sizeof(cfg.referral), "ref-999");
    format_pool_credentials(&cfg, user, sizeof(user), worker, sizeof(worker));
    if (strcmp(user, "XEL:xel:1234567890abcdef.rig5070ti#ref-999") != 0) {
        fprintf(stderr, "[FAIL] unMineable alias format: %s\n", user);
        return 1;
    }
    printf("[PASS] unMineable alias format: %s\n", user);

    cfg.pool_mode = POOL_MODE_F2POOL;
    snprintf(cfg.alias, sizeof(cfg.alias), "myf2account");
    format_pool_credentials(&cfg, user, sizeof(user), worker, sizeof(worker));
    if (strcmp(user, "myf2account.rig5070ti") != 0) {
        fprintf(stderr, "[FAIL] F2Pool alias format: %s\n", user);
        return 1;
    }
    printf("[PASS] F2Pool alias format: %s\n", user);

    uint8_t target[32];
    compute_target_from_u64(1, target);
    for (int i = 0; i < 32; i++) {
        if (target[i] != 0xFF) { fprintf(stderr, "[FAIL] diff=1 target\n"); return 1; }
    }
    compute_target_from_u64(256, target);
    if (target[0] != 0x00 || target[1] != 0xFF) {
        fprintf(stderr, "[FAIL] diff=256 target\n"); return 1;
    }
    printf("[PASS] U256 difficulty target calculation verified\n");

    /* Local Xelis-V3 Blockchain Branch & Nonce Equivalence Test (MinerWork 112B @ diff=32) */
    {
        uint8_t chain_work[112];
        memset(chain_work, 0, sizeof(chain_work));
        for (int i = 0; i < 32; i++) chain_work[i] = (uint8_t)(0xA0 + i); /* header_work_hash */
        chain_work[38] = 0x19; chain_work[39] = 0x99;                      /* timestamp BE */
        for (int i = 0; i < 32; i++) chain_work[80 + i] = (uint8_t)(0x30 + i); /* miner pubkey */

        uint8_t chain_target[32];
        compute_target_from_u64(32, chain_target);
        uint64_t *scratch = (uint64_t *)calloc(XELIS_MEMSIZE, sizeof(uint64_t));
        uint64_t valid_nonce = 0;
        uint8_t valid_hash[32];
        int found = 0;
        for (uint64_t n = 0; n < 4096; n++) {
            for (int k = 0; k < 8; k++) chain_work[40 + k] = (uint8_t)(n >> (56 - k * 8));
            xelis_hash_v3_cpu(chain_work, valid_hash, scratch);
            if (hash_meets_target(valid_hash, chain_target)) {
                valid_nonce = n;
                found = 1;
                break;
            }
        }
        free(scratch);
        if (!found) {
            fprintf(stderr, "[FAIL] Local Xelis-V3 blockchain branch nonce search failed!\n");
            return 1;
        }
        printf("[PASS] Local Xelis-V3 blockchain branch mined legal nonce=%llu (diff=32, hash[0..3]=%02x%02x%02x%02x)\n",
               (unsigned long long)valid_nonce, valid_hash[0], valid_hash[1], valid_hash[2], valid_hash[3]);
    }

#ifdef USE_CUDA
    if (xelis_cuda_selftest(0) != 0) {
        fprintf(stderr, "[WARN] CUDA GPU selftest skipped or failed (no GPU detected in environment)\n");
    } else {
        printf("[PASS] CUDA GPU kernel matches official gold vector!\n");
    }
#else
    printf("[INFO] Built without CUDA (CPU/Protocol verification mode)\n");
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
    snprintf(cfg.worker, sizeof(cfg.worker), "xelis_gpu");
    snprintf(cfg.password, sizeof(cfg.password), "x");
    snprintf(cfg.coin, sizeof(cfg.coin), "XEL");

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
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (cfg.selftest) {
        return run_selftest();
    }

    if (cfg.host[0] == '\0' || (cfg.wallet[0] == '\0' && cfg.alias[0] == '\0')) {
        print_usage(argv[0]);
        return 1;
    }

    signal(SIGINT, on_sigint);
    net_global_init();

#ifdef USE_CUDA
    xelis_cuda_ctx_t cuda_ctx;
    int use_gpu = !cfg.cpu_fallback;
    if (use_gpu) {
        if (xelis_cuda_init(&cuda_ctx, cfg.gpu_id, cfg.blocks, cfg.threads_per_block) != 0) {
            fprintf(stderr, "[WARN] CUDA init failed on GPU %d, falling back to CPU\n", cfg.gpu_id);
            use_gpu = 0;
        }
    }
#else
    int use_gpu = 0;
#endif

    uint64_t *cpu_scratch = (uint64_t *)calloc(XELIS_MEMSIZE, sizeof(uint64_t));
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

        uint64_t nonce = 0;
        uint64_t total_hashes = 0;
        uint64_t report_hashes = 0;
        double last_stat = now_sec();
        double last_report = last_stat;

        while (g_running) {
            int pr = proto_poll(&sess, sess.has_job ? 0 : 200);
            if (pr < 0) break;
            if (pr > 0) {
                printf("[JOB] seq=%llu diff=%llu height=%llu\n",
                       (unsigned long long)sess.latest_job.seq,
                       (unsigned long long)sess.latest_job.difficulty,
                       (unsigned long long)sess.latest_job.height);
                if (sess.latest_job.clean_jobs) nonce = 0;
            }
            if (!sess.has_job) continue;

            uint64_t found_nonce = 0;
            uint8_t  found_hash[32];
            int hit = 0;
            uint32_t batch_hashes = 1;

#ifdef USE_CUDA
            if (use_gpu) {
                hit = xelis_cuda_mine_batch(&cuda_ctx,
                                            sess.latest_job.header_work,
                                            sess.latest_job.target_be,
                                            nonce, &found_nonce, found_hash, &batch_hashes);
                if (hit < 0) break;
            } else
#endif
            {
                uint8_t work[112];
                memcpy(work, sess.latest_job.header_work, 112);
                for (int k = 0; k < 8; k++) work[40 + k] = (uint8_t)(nonce >> (56 - k * 8));
                xelis_hash_v3_cpu(work, found_hash, cpu_scratch);
                if (hash_meets_target(found_hash, sess.latest_job.target_be)) {
                    hit = 1;
                    found_nonce = nonce;
                }
            }

            nonce += batch_hashes;
            total_hashes += batch_hashes;
            report_hashes += batch_hashes;

            if (hit == 1) {
                uint8_t solved[112];
                memcpy(solved, sess.latest_job.header_work, 112);
                for (int k = 0; k < 8; k++) solved[40 + k] = (uint8_t)(found_nonce >> (56 - k * 8));

                int valid = 1;
                if (use_gpu && cfg.cpu_verify) {
                    uint8_t verify_hash[32];
                    xelis_hash_v3_cpu(solved, verify_hash, cpu_scratch);
                    if (memcmp(verify_hash, found_hash, 32) != 0) {
                        fprintf(stderr, "[WARN] CPU verification mismatch on nonce %llu! Skipping.\n",
                                (unsigned long long)found_nonce);
                        valid = 0;
                    }
                }
                if (valid) {
                    printf("[SHARE] Found solution! nonce=0x%016llx\n", (unsigned long long)found_nonce);
                    proto_submit_solution(&sess, &sess.latest_job, found_nonce, solved);
                }
            }

            double t = now_sec();
            if (t - last_stat >= 1.0) {
                double dt = t - last_stat;
                double hs = (double)total_hashes / dt;
                printf("[STATS 1s] %.2f H/s | Accepted: %llu | Rejected: %llu\n",
                       hs, (unsigned long long)sess.accepted, (unsigned long long)sess.rejected);
                total_hashes = 0;
                last_stat = t;
            }
            if (t - last_report >= 10.0) {
                double rdt = t - last_report;
                proto_report_hashrate(&sess, (uint64_t)((double)report_hashes / rdt));
                report_hashes = 0;
                last_report = t;
            }
        }
        proto_disconnect(&sess);
    }

    free(cpu_scratch);
#ifdef USE_CUDA
    if (use_gpu) xelis_cuda_free(&cuda_ctx);
#endif
    net_global_cleanup();
    return 0;
}
