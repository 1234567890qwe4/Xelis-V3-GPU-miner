#include "miner_common.h"
#include "miner_net.h"
#include "xelis_hash_v3.h"

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

static void *stratum_mock_thread(void *arg) {
    int srv = *(int *)arg;
    int cli = accept(srv, NULL, NULL);
    if (cli < 0) return NULL;

    char buf[4096];
    ssize_t n = recv(cli, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { close(cli); return NULL; }
    buf[n] = '\0';

    if (!strstr(buf, "mining.subscribe") || !strstr(buf, "xel/v3")) {
        close(cli); return (void *)1;
    }

    const char *sub_resp =
        "{\"id\":1,\"result\":[\"SESS01\","
        "\"1111111111111111111111111111111111111111111111111111111111111111\","
        "32,"
        "\"2222222222222222222222222222222222222222222222222222222222222222\"]}\n";
    send(cli, sub_resp, strlen(sub_resp), 0);

    n = recv(cli, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { close(cli); return NULL; }
    buf[n] = '\0';
    if (!strstr(buf, "mining.authorize")) { close(cli); return (void *)2; }

    const char *auth_and_job =
        "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[16]}\n"
        "{\"id\":2,\"result\":true}\n"
        "{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"job_42\",\"000001933a1b2c3d\","
        "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"xel/v3\",true]}\n";
    send(cli, auth_and_job, strlen(auth_and_job), 0);

    n = recv(cli, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { close(cli); return NULL; }
    buf[n] = '\0';

    if (!strstr(buf, "mining.submit") || !strstr(buf, "job_42") || !strstr(buf, "0000000000003da6")) {
        fprintf(stderr, "[TEST-STRATUM] Invalid submit payload: %s\n", buf);
        close(cli);
        return (void *)3;
    }
    const char *acc = "{\"id\":10,\"result\":true}\n";
    send(cli, acc, strlen(acc), 0);
    close(cli);
    return NULL;
}

static void *getwork_ws_mock_thread(void *arg) {
    int srv = *(int *)arg;
    int cli = accept(srv, NULL, NULL);
    if (cli < 0) return NULL;

    char buf[4096];
    ssize_t n = recv(cli, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { close(cli); return NULL; }
    buf[n] = '\0';

    if (!strstr(buf, "GET /getwork/xel:testwallet/rig5070ti")) {
        fprintf(stderr, "[TEST-WS] Unexpected path: %s\n", buf);
        close(cli); return (void *)1;
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
             "\"height\":3282150,\"topoheight\":3282150,\"difficulty\":\"256\"}}",
             work_hex);
    size_t jlen = strlen(json_msg);
    uint8_t frame[1024];
    frame[0] = 0x81;
    frame[1] = 126;
    frame[2] = (uint8_t)(jlen >> 8);
    frame[3] = (uint8_t)(jlen & 0xFF);
    memcpy(frame + 4, json_msg, jlen);
    send(cli, frame, 4 + jlen, 0);

    /* Read complete WebSocket frame header + mask + payload */
    uint8_t hdr[2];
    if (recv_exact_fd(cli, hdr, 2) != 0) { close(cli); return (void *)2; }
    size_t plen = hdr[1] & 0x7f;
    if (plen == 126) {
        uint8_t ext[2];
        if (recv_exact_fd(cli, ext, 2) != 0) { close(cli); return (void *)2; }
        plen = ((size_t)ext[0] << 8) | ext[1];
    }
    uint8_t mask[4];
    if (recv_exact_fd(cli, mask, 4) != 0) { close(cli); return (void *)2; }
    uint8_t payload[512];
    if (plen >= sizeof(payload) || recv_exact_fd(cli, payload, plen) != 0) { close(cli); return (void *)2; }

    char decoded[512];
    for (size_t i = 0; i < plen; i++) decoded[i] = (char)(payload[i] ^ mask[i & 3]);
    decoded[plen] = '\0';

    if (!strstr(decoded, "\"miner_work\":\"") || !strstr(decoded, "0000000000003da6")) {
        fprintf(stderr, "[TEST-WS] Invalid submit JSON: %s\n", decoded);
        close(cli); return (void *)3;
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

    {
        uint16_t port = 0;
        int srv = create_loopback_server(&port);
        pthread_t th;
        pthread_create(&th, NULL, stratum_mock_thread, &srv);

        miner_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        char url[64];
        snprintf(url, sizeof(url), "stratum++tcp://127.0.0.1:%u", (unsigned)port);
        parse_miner_url(url, &cfg);
        snprintf(cfg.wallet, sizeof(cfg.wallet), "xel:testwallet");
        snprintf(cfg.worker, sizeof(cfg.worker), "rig5070ti");
        snprintf(cfg.password, sizeof(cfg.password), "x");

        protocol_session_t sess;
        if (proto_connect_and_auth(&sess, &cfg) != 0) {
            fprintf(stderr, "[FAIL] Stratum++ connect/auth\n"); return 1;
        }
        if (proto_poll(&sess, 2000) != 1 || !sess.has_job) {
            fprintf(stderr, "[FAIL] Stratum++ notify poll\n"); return 1;
        }
        if (sess.latest_job.difficulty != 16 || sess.latest_job.header_work[0] != 0xaa ||
            sess.latest_job.header_work[48] != 0x11 || sess.latest_job.header_work[80] != 0x22) {
            fprintf(stderr, "[FAIL] Stratum++ MinerWork 112-byte layout mismatch\n"); return 1;
        }

        uint64_t test_nonce = 15782ULL;
        uint8_t solved[112];
        memcpy(solved, sess.latest_job.header_work, 112);
        for (int k = 0; k < 8; k++) solved[40 + k] = (uint8_t)(test_nonce >> (56 - k * 8));
        proto_submit_solution(&sess, &sess.latest_job, test_nonce, solved);
        proto_poll(&sess, 2000);
        if (sess.accepted != 1) {
            fprintf(stderr, "[FAIL] Stratum++ share acceptance\n"); return 1;
        }
        proto_disconnect(&sess);
        void *ret = NULL;
        pthread_join(th, &ret);
        close(srv);
        if (ret != NULL) return 1;
        printf("[PASS] Stratum++ TCP protocol + MinerWork 112B + nonce 0x%016llx verified!\n",
               (unsigned long long)test_nonce);
    }

    {
        uint16_t port = 0;
        int srv = create_loopback_server(&port);
        pthread_t th;
        pthread_create(&th, NULL, getwork_ws_mock_thread, &srv);

        miner_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        char url[64];
        snprintf(url, sizeof(url), "ws://127.0.0.1:%u", (unsigned)port);
        parse_miner_url(url, &cfg);
        snprintf(cfg.wallet, sizeof(cfg.wallet), "xel:testwallet");
        snprintf(cfg.worker, sizeof(cfg.worker), "rig5070ti");

        protocol_session_t sess;
        if (proto_connect_and_auth(&sess, &cfg) != 0) {
            fprintf(stderr, "[FAIL] Xelis-WS connect\n"); return 1;
        }
        if (proto_poll(&sess, 2000) != 1 || !sess.has_job) {
            fprintf(stderr, "[FAIL] Xelis-WS new_job poll\n"); return 1;
        }
        if (sess.latest_job.difficulty != 256 || sess.latest_job.height != 3282150) {
            fprintf(stderr, "[FAIL] Xelis-WS job metadata mismatch\n"); return 1;
        }
        uint64_t test_nonce = 15782ULL;
        uint8_t solved[112];
        memcpy(solved, sess.latest_job.header_work, 112);
        for (int k = 0; k < 8; k++) solved[40 + k] = (uint8_t)(test_nonce >> (56 - k * 8));
        proto_submit_solution(&sess, &sess.latest_job, test_nonce, solved);
        proto_poll(&sess, 2000);
        if (sess.accepted != 1) {
            fprintf(stderr, "[FAIL] Xelis-WS block acceptance\n"); return 1;
        }
        proto_disconnect(&sess);
        void *ret = NULL;
        pthread_join(th, &ret);
        close(srv);
        if (ret != NULL) return 1;
        printf("[PASS] Xelis-V3 Native WS GetWork + MinerWork submit + block_accepted verified!\n");
    }

    net_global_cleanup();
    return 0;
}
