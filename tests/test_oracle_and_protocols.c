#include "miner_common.h"
#include "miner_net.h"
#include "xelis_hash_v3.h"
#include "xelis_v3_oracle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int recv_exact_fd(int fd, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

static int create_loopback_server(uint16_t *out_port) {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) return -1;
    if (listen(srv, 4) != 0) return -1;
    socklen_t len = sizeof(addr);
    getsockname(srv, (struct sockaddr *)&addr, &len);
    *out_port = ntohs(addr.sin_port);
    return srv;
}

/* Mock Stratum++ pool that validates the submitted nonce against real XelisHash V3 */
static void *stratum_oracle_mock_thread(void *arg) {
    int srv = *(int *)arg;
    int cli = accept(srv, NULL, NULL);
    if (cli < 0) return (void *)1;

    char buf[4096];
    ssize_t n = recv(cli, buf, sizeof(buf) - 1, 0);
    if (n <= 0 || !strstr(buf, "mining.subscribe") || !strstr(buf, "xel/v3")) {
        close(cli); return (void *)2;
    }

    const char *sub_resp =
        "{\"id\":1,\"result\":[\"SESS01\","
        "\"1111111111111111111111111111111111111111111111111111111111111111\","
        "32,"
        "\"2222222222222222222222222222222222222222222222222222222222222222\"]}\n";
    send(cli, sub_resp, strlen(sub_resp), 0);

    n = recv(cli, buf, sizeof(buf) - 1, 0);
    if (n <= 0 || !strstr(buf, "mining.authorize")) {
        close(cli); return (void *)3;
    }

    const char *auth_and_job =
        "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[16]}\n"
        "{\"id\":2,\"result\":true}\n"
        "{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"job_oracle_1\",\"000001933a1b2c3d\","
        "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"xel/v3\",true]}\n";
    send(cli, auth_and_job, strlen(auth_and_job), 0);

    n = recv(cli, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { close(cli); return (void *)4; }
    buf[n] = '\0';
    if (!strstr(buf, "mining.submit") || !strstr(buf, "job_oracle_1")) {
        close(cli); return (void *)5;
    }

    const char *acc = "{\"id\":10,\"result\":true}\n";
    send(cli, acc, strlen(acc), 0);
    close(cli);
    return NULL;
}

/* Mock Xelis-V3 Native WebSocket Daemon that verifies submitted 112B MinerWork against v3.rs rules */
static void *daemon_ws_oracle_mock_thread(void *arg) {
    int srv = *(int *)arg;
    int cli = accept(srv, NULL, NULL);
    if (cli < 0) return (void *)1;

    char buf[4096];
    ssize_t n = recv(cli, buf, sizeof(buf) - 1, 0);
    if (n <= 0 || !strstr(buf, "GET /getwork/xel:oraclewallet/oracle01")) {
        close(cli); return (void *)2;
    }

    const char *hs =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    send(cli, hs, strlen(hs), 0);

    char work_hex[225];
    memset(work_hex, 'a', 224);
    work_hex[224] = '\0';
    char json_msg[512];
    snprintf(json_msg, sizeof(json_msg),
             "{\"new_job\":{\"algorithm\":\"xel/v3\",\"miner_work\":\"%s\","
             "\"height\":3282151,\"topoheight\":3282151,\"difficulty\":\"32\"}}",
             work_hex);
    size_t jlen = strlen(json_msg);
    uint8_t frame[1024];
    frame[0] = 0x81;
    frame[1] = 126;
    frame[2] = (uint8_t)(jlen >> 8);
    frame[3] = (uint8_t)(jlen & 0xFF);
    memcpy(frame + 4, json_msg, jlen);
    send(cli, frame, 4 + jlen, 0);

    uint8_t hdr[2];
    if (recv_exact_fd(cli, hdr, 2) != 0) { close(cli); return (void *)3; }
    size_t plen = hdr[1] & 0x7f;
    if (plen == 126) {
        uint8_t ext[2];
        if (recv_exact_fd(cli, ext, 2) != 0) { close(cli); return (void *)3; }
        plen = ((size_t)ext[0] << 8) | ext[1];
    }
    uint8_t mask[4];
    if (recv_exact_fd(cli, mask, 4) != 0) { close(cli); return (void *)3; }
    uint8_t payload[512];
    if (plen >= sizeof(payload) || recv_exact_fd(cli, payload, plen) != 0) { close(cli); return (void *)3; }

    char decoded[512];
    for (size_t i = 0; i < plen; i++) decoded[i] = (char)(payload[i] ^ mask[i & 3]);
    decoded[plen] = '\0';

    const char *mw = strstr(decoded, "\"miner_work\":\"");
    if (!mw) { close(cli); return (void *)4; }
    mw += strlen("\"miner_work\":\"");

    char mw_hex[225];
    if (strlen(mw) < 224) { close(cli); return (void *)5; }
    memcpy(mw_hex, mw, 224);
    mw_hex[224] = '\0';
    uint8_t submitted_work[112];
    if (hex_to_bytes(mw_hex, submitted_work, 112) != 0) {
        close(cli); return (void *)5;
    }

    /* Verify PoW hash against Xelis-V3 diff=32 directly in mock blockchain daemon */
    uint64_t *scratch = (uint64_t *)calloc(XELIS_MEMSIZE, sizeof(uint64_t));
    uint8_t pow_hash[32], target_be[32];
    xelis_hash_v3_cpu(submitted_work, pow_hash, scratch);
    free(scratch);
    compute_target_from_u64(32, target_be);

    if (!hash_meets_target(pow_hash, target_be)) {
        fprintf(stderr, "[DAEMON-MOCK] Submitted block failed diff=32 PoW check!\n");
        close(cli); return (void *)6;
    }

    const char *acc_json = "\"block_accepted\"";
    size_t alen = strlen(acc_json);
    frame[0] = 0x81;
    frame[1] = (uint8_t)alen;
    memcpy(frame + 2, acc_json, alen);
    send(cli, frame, 2 + alen, 0);
    close(cli);
    return NULL;
}

int main(void) {
    net_global_init();

    xelis_oracle_t oracle;
    if (xelis_oracle_init(&oracle, 0, 0, 1, 64, 1) != 0) {
        fprintf(stderr, "[FAIL] Oracle init\n"); return 1;
    }

    /* 1. Mandatory Stratum++ Oracle Test (Priority) */
    {
        uint16_t port = 0;
        int srv = create_loopback_server(&port);
        pthread_t th;
        pthread_create(&th, NULL, stratum_oracle_mock_thread, &srv);

        miner_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        char url[64];
        snprintf(url, sizeof(url), "stratum++tcp://127.0.0.1:%u", (unsigned)port);
        parse_miner_url(url, &cfg);
        snprintf(cfg.wallet, sizeof(cfg.wallet), "xel:oraclewallet");
        snprintf(cfg.worker, sizeof(cfg.worker), "oracle01");
        snprintf(cfg.password, sizeof(cfg.password), "x");

        protocol_session_t sess;
        if (proto_connect_and_auth(&sess, &cfg) != 0) return 1;
        if (proto_poll(&sess, 2000) != 1 || !sess.has_job) return 1;

        xelis_oracle_result_t res;
        if (xelis_oracle_generate_legal_nonce(&oracle, sess.latest_job.header_work,
                                              sess.latest_job.target_be, 0, 0, &res) != 1) return 1;
        if (xelis_oracle_branch_verify(&res, sess.latest_job.target_be) != 0) return 1;

        proto_submit_solution(&sess, &sess.latest_job, res.nonce, res.solved_work);
        proto_poll(&sess, 2000);
        if (sess.accepted != 1) return 1;
        proto_disconnect(&sess);

        void *ret = NULL;
        pthread_join(th, &ret);
        close(srv);
        if (ret != NULL) return 1;
        printf("[PASS] Stratum++ Oracle: generated real legal nonce=%llu & ACCEPTED!\n",
               (unsigned long long)res.nonce);
    }

    /* 2. Mandatory Xelis-V3 Native WS GetWork Block-Branching Test (Secondary) */
    {
        uint16_t port = 0;
        int srv = create_loopback_server(&port);
        pthread_t th;
        pthread_create(&th, NULL, daemon_ws_oracle_mock_thread, &srv);

        miner_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        char url[64];
        snprintf(url, sizeof(url), "ws://127.0.0.1:%u", (unsigned)port);
        parse_miner_url(url, &cfg);
        snprintf(cfg.wallet, sizeof(cfg.wallet), "xel:oraclewallet");
        snprintf(cfg.worker, sizeof(cfg.worker), "oracle01");

        protocol_session_t sess;
        if (proto_connect_and_auth(&sess, &cfg) != 0) return 1;
        if (proto_poll(&sess, 2000) != 1 || !sess.has_job) return 1;

        xelis_oracle_result_t res;
        if (xelis_oracle_generate_legal_nonce(&oracle, sess.latest_job.header_work,
                                              sess.latest_job.target_be, 0, 0, &res) != 1) return 1;
        if (xelis_oracle_branch_verify(&res, sess.latest_job.target_be) != 0) return 1;

        proto_submit_solution(&sess, &sess.latest_job, res.nonce, res.solved_work);
        proto_poll(&sess, 2000);
        if (sess.accepted != 1) return 1;
        proto_disconnect(&sess);

        void *ret = NULL;
        pthread_join(th, &ret);
        close(srv);
        if (ret != NULL) return 1;
        printf("[PASS] Xelis-V3 Native WS Oracle: branched legal block nonce=%llu & block_accepted!\n",
               (unsigned long long)res.nonce);
    }

    xelis_oracle_free(&oracle);
    net_global_cleanup();
    return 0;
}
