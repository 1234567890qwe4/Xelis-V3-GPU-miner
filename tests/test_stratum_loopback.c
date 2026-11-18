#include "xelis_hash_v3.h"
#include "miner_common.h"
#include "miner_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int g_listen_fd = -1;
static uint16_t g_port = 0;

static void *mock_stratum_server(void *arg) {
    (void)arg;
    int cli = accept(g_listen_fd, NULL, NULL);
    if (cli < 0) return NULL;

    char buf[2048];
    FILE *fp = fdopen(dup(cli), "r");
    /* 1. Read mining.subscribe */
    if (!fgets(buf, sizeof(buf), fp)) { fclose(fp); close(cli); return NULL; }
    const char *sub_resp = "{\"id\":1,\"result\":[\"sess01\",\"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\",32,\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]}\n";
    send(cli, sub_resp, strlen(sub_resp), 0);

    /* 2. Read mining.authorize */
    if (!fgets(buf, sizeof(buf), fp)) { fclose(fp); close(cli); return NULL; }
    if (!strstr(buf, "XEL:xel:testwallet.rig1#ref123")) {
        fprintf(stderr, "[MOCK-STRATUM] Unexpected authorize user: %s\n", buf);
    }
    const char *auth_resp = "{\"id\":2,\"result\":true}\n";
    send(cli, auth_resp, strlen(auth_resp), 0);

    /* 3. Send mining.set_difficulty + mining.notify */
    const char *set_diff = "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[1]}\n";
    send(cli, set_diff, strlen(set_diff), 0);
    const char *notify = "{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"job42\",\"19726d97f49\",\"d9da51a0c3f8a1784911d370fdb617ea7f41581f5059d31e35f176b85efa5570\",\"xel/v3\",true]}\n";
    send(cli, notify, strlen(notify), 0);

    /* 4. Read mining.submit */
    if (fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, "\"method\":\"mining.submit\"") && strstr(buf, "\"job42\"")) {
            const char *ok = "{\"id\":10,\"result\":true}\n";
            send(cli, ok, strlen(ok), 0);
        }
    }

    fclose(fp);
    close(cli);
    return NULL;
}

int main(void) {
    net_global_init();

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) return 1;
    socklen_t alen = sizeof(addr);
    getsockname(g_listen_fd, (struct sockaddr *)&addr, &alen);
    g_port = ntohs(addr.sin_port);
    listen(g_listen_fd, 1);

    pthread_t th;
    pthread_create(&th, NULL, mock_stratum_server, NULL);

    miner_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    char uri[128];
    snprintf(uri, sizeof(uri), "stratum++tcp://127.0.0.1:%u", (unsigned)g_port);
    parse_miner_url(uri, &cfg);
    cfg.pool_mode = POOL_MODE_UNMINEABLE;
    snprintf(cfg.coin, sizeof(cfg.coin), "XEL");
    snprintf(cfg.wallet, sizeof(cfg.wallet), "xel:testwallet");
    snprintf(cfg.worker, sizeof(cfg.worker), "rig1");
    snprintf(cfg.referral, sizeof(cfg.referral), "ref123");

    protocol_session_t sess;
    if (proto_connect_and_auth(&sess, &cfg) != 0) {
        fprintf(stderr, "[LOOPBACK] Connect/auth failed\n");
        return 1;
    }

    /* Poll set_difficulty and notify */
    for (int i = 0; i < 5 && !sess.has_job; i++) {
        proto_poll(&sess, 1000);
    }
    if (!sess.has_job || strcmp(sess.latest_job.job_id, "job42") != 0) {
        fprintf(stderr, "[LOOPBACK] Did not receive job42\n");
        return 1;
    }

    /* Compute real XelisHash V3 on nonce=0 and submit */
    static uint64_t scratch[XELIS_MEMSIZE];
    uint8_t hash[32];
    xelis_hash_v3_cpu(sess.latest_job.header_work, hash, scratch);
    if (!hash_meets_target(hash, sess.latest_job.target_be)) {
        fprintf(stderr, "[LOOPBACK] Diff=1 should accept any hash\n");
        return 1;
    }
    proto_submit_solution(&sess, &sess.latest_job, 0, sess.latest_job.header_work);
    proto_poll(&sess, 1000);

    if (sess.accepted != 1) {
        fprintf(stderr, "[LOOPBACK] Expected 1 accepted share, got %llu\n", (unsigned long long)sess.accepted);
        return 1;
    }

    printf("[PASS] Stratum++ loopback (subscribe -> unMineable alias auth -> notify -> XelisHash V3 -> submit -> accepted)!\n");
    proto_disconnect(&sess);
    pthread_join(th, NULL);
    close(g_listen_fd);
    net_global_cleanup();
    return 0;
}
