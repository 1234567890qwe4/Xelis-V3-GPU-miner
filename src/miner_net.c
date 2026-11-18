#ifdef _WIN32
  #define _WIN32_WINNT 0x0601
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET sock_t;
  #define INVALID_SOCK INVALID_SOCKET
  #define close_sock(s) closesocket(s)
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <sys/select.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <errno.h>
  typedef int sock_t;
  #define INVALID_SOCK (-1)
  #define close_sock(s) close(s)
#endif

#include "miner_net.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct net_conn {
    sock_t   fd;
    int      use_ssl;
    SSL_CTX *ssl_ctx;
    SSL     *ssl;
    char     rx_buf[16384];
    size_t   rx_len;
};

int net_global_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;
#endif
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    return 0;
}

void net_global_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

net_conn_t *net_connect(const char *host, uint16_t port, int use_ssl) {
    struct addrinfo hints, *res = NULL, *rp = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return NULL;

    sock_t fd = INVALID_SOCK;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == INVALID_SOCK) continue;
        if (connect(fd, rp->ai_addr, (int)rp->ai_addrlen) == 0) break;
        close_sock(fd);
        fd = INVALID_SOCK;
    }
    freeaddrinfo(res);
    if (fd == INVALID_SOCK) return NULL;

    net_conn_t *c = (net_conn_t *)calloc(1, sizeof(net_conn_t));
    c->fd = fd;
    c->use_ssl = use_ssl;

    if (use_ssl) {
        c->ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!c->ssl_ctx) { net_close(c); return NULL; }
        c->ssl = SSL_new(c->ssl_ctx);
        SSL_set_tlsext_host_name(c->ssl, host);
        SSL_set_fd(c->ssl, (int)fd);
        if (SSL_connect(c->ssl) != 1) {
            ERR_print_errors_fp(stderr);
            net_close(c);
            return NULL;
        }
    }
    return c;
}

void net_close(net_conn_t *c) {
    if (!c) return;
    if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); }
    if (c->ssl_ctx) SSL_CTX_free(c->ssl_ctx);
    if (c->fd != INVALID_SOCK) close_sock(c->fd);
    free(c);
}

int net_send_all(net_conn_t *c, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    while (sent < len) {
        int n;
        if (c->use_ssl) {
            n = SSL_write(c->ssl, p + sent, (int)(len - sent));
        } else {
            n = (int)send(c->fd, (const char *)(p + sent), (int)(len - sent), 0);
        }
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int wait_readable(net_conn_t *c, int timeout_ms) {
    if (c->use_ssl && SSL_pending(c->ssl) > 0) return 1;
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(c->fd, &rfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return select((int)c->fd + 1, &rfds, NULL, NULL, &tv);
}

int net_recv_raw(net_conn_t *c, void *buf, size_t len, int timeout_ms) {
    int ready = wait_readable(c, timeout_ms);
    if (ready <= 0) return ready;
    int n = c->use_ssl ? SSL_read(c->ssl, buf, (int)len)
                       : (int)recv(c->fd, (char *)buf, (int)len, 0);
    return (n <= 0) ? -1 : n;
}

int net_recv_line(net_conn_t *c, char *buf, size_t buf_sz, int timeout_ms) {
    for (;;) {
        char *nl = (char *)memchr(c->rx_buf, '\n', c->rx_len);
        if (nl) {
            size_t line_len = (size_t)(nl - c->rx_buf);
            size_t copy_len = (line_len < buf_sz - 1) ? line_len : (buf_sz - 1);
            memcpy(buf, c->rx_buf, copy_len);
            if (copy_len > 0 && buf[copy_len - 1] == '\r') copy_len--;
            buf[copy_len] = '\0';
            size_t rem = c->rx_len - (line_len + 1);
            if (rem > 0) memmove(c->rx_buf, nl + 1, rem);
            c->rx_len = rem;
            return 1;
        }
        if (c->rx_len >= sizeof(c->rx_buf) - 1) {
            c->rx_len = 0;
            return -1;
        }
        int r = wait_readable(c, timeout_ms);
        if (r == 0) return 0; /* timeout */
        if (r < 0) return -1;
        int n = c->use_ssl
            ? SSL_read(c->ssl, c->rx_buf + c->rx_len, (int)(sizeof(c->rx_buf) - 1 - c->rx_len))
            : (int)recv(c->fd, c->rx_buf + c->rx_len, (int)(sizeof(c->rx_buf) - 1 - c->rx_len), 0);
        if (n <= 0) return -1;
        c->rx_len += (size_t)n;
    }
}

/* =========================================================================
 * Minimal RFC 6455 WebSocket Frame Helpers (for Xelis-V3 Native GetWork)
 * ========================================================================= */
static int ws_handshake(net_conn_t *c, const char *host, uint16_t port, const char *path) {
    char req[1024];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\n"
             "Host: %s:%u\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
             "Sec-WebSocket-Version: 13\r\n\r\n",
             path, host, (unsigned)port);
    if (net_send_all(c, req, strlen(req)) != 0) return -1;

    char line[1024];
    int got_101 = 0;
    while (net_recv_line(c, line, sizeof(line), 5000) > 0) {
        if (strstr(line, "101") != NULL) got_101 = 1;
        if (line[0] == '\0') break;
    }
    return got_101 ? 0 : -1;
}

static int ws_send_text(net_conn_t *c, const char *text) {
    size_t len = strlen(text);
    uint8_t hdr[14];
    size_t hlen = 0;
    hdr[0] = 0x81; /* FIN + text */
    if (len <= 125) {
        hdr[1] = (uint8_t)(0x80 | len);
        hlen = 2;
    } else if (len <= 65535) {
        hdr[1] = (uint8_t)(0x80 | 126);
        hdr[2] = (uint8_t)(len >> 8);
        hdr[3] = (uint8_t)(len & 0xff);
        hlen = 4;
    } else {
        return -1;
    }
    uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};
    memcpy(hdr + hlen, mask, 4);
    hlen += 4;
    if (net_send_all(c, hdr, hlen) != 0) return -1;

    uint8_t *masked = (uint8_t *)malloc(len);
    for (size_t i = 0; i < len; i++) masked[i] = (uint8_t)(text[i] ^ mask[i & 3]);
    int rc = net_send_all(c, masked, len);
    free(masked);
    return rc;
}

static int ws_read_exact(net_conn_t *c, uint8_t *out, size_t len, int timeout_ms) {
    size_t got = 0;
    while (got < len) {
        if (c->rx_len > 0) {
            size_t take = (c->rx_len < len - got) ? c->rx_len : (len - got);
            memcpy(out + got, c->rx_buf, take);
            if (c->rx_len > take) memmove(c->rx_buf, c->rx_buf + take, c->rx_len - take);
            c->rx_len -= take;
            got += take;
            continue;
        }
        int n = net_recv_raw(c, out + got, len - got, (got == 0) ? timeout_ms : 2000);
        if (n == 0 && got == 0) return 0; /* clean timeout */
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 1;
}

static int ws_recv_text(net_conn_t *c, char *out, size_t out_sz, int timeout_ms) {
    uint8_t hdr[2];
    int r = ws_read_exact(c, hdr, 2, timeout_ms);
    if (r <= 0) return r;

    uint8_t opcode = hdr[0] & 0x0f;
    int masked = (hdr[1] & 0x80) != 0;
    uint64_t plen = hdr[1] & 0x7f;

    if (plen == 126) {
        uint8_t ext[2];
        if (ws_read_exact(c, ext, 2, 2000) <= 0) return -1;
        plen = ((uint64_t)ext[0] << 8) | ext[1];
    } else if (plen == 127) {
        uint8_t ext[8];
        if (ws_read_exact(c, ext, 8, 2000) <= 0) return -1;
        plen = 0;
        for (int i = 0; i < 8; i++) plen = (plen << 8) | ext[i];
    }

    uint8_t mask[4] = {0};
    if (masked && ws_read_exact(c, mask, 4, 2000) <= 0) return -1;

    if (plen >= out_sz) return -1;
    if (plen > 0 && ws_read_exact(c, (uint8_t *)out, (size_t)plen, 2000) <= 0) return -1;
    if (masked) {
        for (size_t i = 0; i < (size_t)plen; i++) out[i] ^= mask[i & 3];
    }
    out[plen] = '\0';

    if (opcode == 0x8) return -1; /* close */
    if (opcode == 0x9) { /* ping -> pong */
        uint8_t pong[6] = {0x8A, 0x80, 0x11, 0x22, 0x33, 0x44};
        net_send_all(c, pong, 6);
        return 0;
    }
    return 1;
}

/* =========================================================================
 * Stratum++ & Xelis-V3 GetWork Protocol Logic
 * ========================================================================= */
static int parse_stratum_array_strings(const char *params_start, char items[][256], int max_items) {
    const char *p = strchr(params_start, '[');
    if (!p) return 0;
    p++;
    int count = 0;
    while (*p && *p != ']' && count < max_items) {
        while (*p && (*p == ' ' || *p == ',' || *p == '\t')) p++;
        if (*p == ']') break;
        if (*p == '"') {
            p++;
            size_t i = 0;
            while (*p && *p != '"' && i < 255) {
                if (*p == '\\' && p[1]) p++;
                items[count][i++] = *p++;
            }
            items[count][i] = '\0';
            if (*p == '"') p++;
            count++;
        } else {
            size_t i = 0;
            while (*p && *p != ',' && *p != ']' && *p != ' ' && i < 255) {
                items[count][i++] = *p++;
            }
            items[count][i] = '\0';
            count++;
        }
    }
    return count;
}

static int handle_stratum_line(protocol_session_t *sess, const char *line) {
    char method[64] = {0};
    if (json_extract_string(line, "method", method, sizeof(method)) == 0) {
        const char *params = strstr(line, "\"params\"");
        if (strcmp(method, "mining.set_difficulty") == 0 && params) {
            char items[4][256];
            if (parse_stratum_array_strings(params, items, 4) >= 1) {
                uint64_t diff = strtoull(items[0], NULL, 10);
                if (diff > 0) {
                    sess->current_difficulty = diff;
                    compute_target_from_u64(diff, sess->current_target_be);
                    printf("[STRATUM++] Difficulty set to %llu\n", (unsigned long long)diff);
                }
            }
            return 0;
        }
        if (strcmp(method, "mining.set_extranonce") == 0 && params) {
            char items[4][256];
            int n = parse_stratum_array_strings(params, items, 4);
            if (n >= 2) {
                size_t elen = strlen(items[0]) / 2;
                if (elen > 32) elen = 32;
                if (hex_to_bytes(items[0], sess->extranonce, elen) == 0) {
                    sess->extranonce_len = elen;
                }
                if (n >= 3 && strlen(items[2]) >= 64) {
                    hex_to_bytes(items[2], sess->pubkey, 32);
                }
            }
            return 0;
        }
        if (strcmp(method, "mining.notify") == 0 && params) {
            char items[8][256];
            int n = parse_stratum_array_strings(params, items, 8);
            if (n >= 5) {
                /* params: [job_id, timestamp_hex, header_work_hash_hex, algo, clean_jobs] */
                miner_job_t *j = &sess->latest_job;
                memset(j, 0, sizeof(*j));
                snprintf(j->job_id, sizeof(j->job_id), "%.*s", (int)(sizeof(j->job_id) - 1), items[0]);
                uint64_t ts = strtoull(items[1], NULL, 16);
                hex_to_bytes(items[2], j->header_work, 32);
                for (int k = 0; k < 8; k++) {
                    j->header_work[32 + k] = (uint8_t)(ts >> (56 - k * 8));
                }
                memcpy(j->header_work + 48, sess->extranonce, sess->extranonce_len);
                memcpy(j->header_work + 80, sess->pubkey, 32);
                j->difficulty = sess->current_difficulty ? sess->current_difficulty : 1;
                memcpy(j->target_be, sess->current_target_be, 32);
                j->clean_jobs = (strcmp(items[4], "true") == 0);
                j->seq++;
                sess->has_job = 1;
                return 1;
            }
            return 0;
        }
        if (strcmp(method, "mining.ping") == 0) {
            uint64_t pid = 0;
            json_extract_u64(line, "id", &pid);
            char pong[128];
            snprintf(pong, sizeof(pong), "{\"id\":%llu,\"method\":\"mining.pong\"}\n", (unsigned long long)pid);
            net_send_all(sess->conn, pong, strlen(pong));
            return 0;
        }
        if (strcmp(method, "mining.print") == 0 && params) {
            printf("[POOL] %s\n", params);
            return 0;
        }
        return 0;
    }

    uint64_t id = 0;
    if (json_extract_u64(line, "id", &id) == 0 && id >= 10) {
        if (strstr(line, "\"result\":true") || strstr(line, "\"result\": true")) {
            sess->accepted++;
            printf("[STRATUM++] Share ACCEPTED! (accepted=%llu, rejected=%llu)\n",
                   (unsigned long long)sess->accepted, (unsigned long long)sess->rejected);
        } else {
            sess->rejected++;
            printf("[STRATUM++] Share REJECTED: %s\n", line);
        }
    }
    return 0;
}

static int handle_getwork_msg(protocol_session_t *sess, const char *msg) {
    if (strstr(msg, "block_accepted")) {
        sess->accepted++;
        printf("[XELIS-WS] Block ACCEPTED by daemon! (accepted=%llu, rejected=%llu)\n",
               (unsigned long long)sess->accepted, (unsigned long long)sess->rejected);
        return 0;
    }
    if (strstr(msg, "block_rejected")) {
        sess->rejected++;
        printf("[XELIS-WS] Block REJECTED: %s\n", msg);
        return 0;
    }
    if (strstr(msg, "new_job")) {
        char work_hex[256] = {0};
        char diff_str[64] = {0};
        if (json_extract_string(msg, "miner_work", work_hex, sizeof(work_hex)) == 0) {
            miner_job_t *j = &sess->latest_job;
            if (hex_to_bytes(work_hex, j->header_work, 112) != 0) return 0;
            json_extract_u64(msg, "height", &j->height);
            json_extract_u64(msg, "topoheight", &j->topoheight);
            if (json_extract_string(msg, "difficulty", diff_str, sizeof(diff_str)) == 0) {
                j->difficulty = strtoull(diff_str, NULL, 10);
            } else {
                json_extract_u64(msg, "difficulty", &j->difficulty);
            }
            if (j->difficulty == 0) j->difficulty = 1;
            compute_target_from_u64(j->difficulty, j->target_be);
            j->clean_jobs = 1;
            j->seq++;
            sess->has_job = 1;
            return 1;
        }
    }
    return 0;
}

int proto_connect_and_auth(protocol_session_t *sess, const miner_config_t *cfg) {
    memset(sess, 0, sizeof(*sess));
    sess->cfg = *cfg;
    sess->rpc_id = 1;
    sess->current_difficulty = 1;
    compute_target_from_u64(1, sess->current_target_be);

    format_pool_credentials(cfg, sess->auth_user, sizeof(sess->auth_user),
                            sess->auth_worker, sizeof(sess->auth_worker));

    int use_ssl = (cfg->proto == PROTO_STRATUM_SSL || cfg->proto == PROTO_XELIS_WSS);
    sess->is_ws = (cfg->proto == PROTO_XELIS_WS || cfg->proto == PROTO_XELIS_WSS);

    printf("[NET] Connecting to %s:%u (%s)...\n",
           cfg->host, (unsigned)cfg->port,
           sess->is_ws ? (use_ssl ? "Xelis-V3 WSS" : "Xelis-V3 WS")
                       : (use_ssl ? "Stratum++ SSL" : "Stratum++ TCP"));

    sess->conn = net_connect(cfg->host, cfg->port, use_ssl);
    if (!sess->conn) {
        fprintf(stderr, "[NET] Failed to connect to %s:%u\n", cfg->host, (unsigned)cfg->port);
        return -1;
    }

    if (sess->is_ws) {
        char path[512];
        if (cfg->path[0] != '\0') {
            snprintf(path, sizeof(path), "%s", cfg->path);
        } else {
            snprintf(path, sizeof(path), "/getwork/%.240s/%.120s", sess->auth_user, sess->auth_worker);
        }
        if (ws_handshake(sess->conn, cfg->host, cfg->port, path) != 0) {
            fprintf(stderr, "[XELIS-WS] WebSocket handshake failed on %s\n", path);
            proto_disconnect(sess);
            return -1;
        }
        printf("[XELIS-WS] Connected to %s\n", path);
        return 0;
    }

    /* Stratum++: 1. mining.subscribe */
    char msg[1024];
    uint32_t sub_id = sess->rpc_id++;
    snprintf(msg, sizeof(msg),
             "{\"id\":%u,\"method\":\"mining.subscribe\",\"params\":[\"xelis-v3-miner/1.0.0\",[\"xel/v3\"]]}\n",
             sub_id);
    if (net_send_all(sess->conn, msg, strlen(msg)) != 0) { proto_disconnect(sess); return -1; }

    char line[4096];
    for (;;) {
        if (net_recv_line(sess->conn, line, sizeof(line), 5000) <= 0) {
            fprintf(stderr, "[STRATUM++] Timeout waiting for mining.subscribe response\n");
            proto_disconnect(sess);
            return -1;
        }
        uint64_t rid = 0;
        if (strstr(line, "\"result\"") && json_extract_u64(line, "id", &rid) == 0 && rid == sub_id) {
            const char *res = strstr(line, "\"result\"");
            char items[6][256];
            int n = parse_stratum_array_strings(res, items, 6);
            if (n >= 4) {
                snprintf(sess->session_id, sizeof(sess->session_id), "%.*s",
                         (int)(sizeof(sess->session_id) - 1), items[0]);
                size_t elen = strlen(items[1]) / 2;
                if (elen > 32) elen = 32;
                hex_to_bytes(items[1], sess->extranonce, elen);
                sess->extranonce_len = elen;
                hex_to_bytes(items[3], sess->pubkey, 32);
            }
            break;
        }
        handle_stratum_line(sess, line);
    }

    /* Stratum++: 2. mining.authorize (supports standard, unMineable, F2Pool alias) */
    const char *pass = (cfg->password[0] != '\0') ? cfg->password : "x";
    uint32_t auth_id = sess->rpc_id++;
    snprintf(msg, sizeof(msg),
             "{\"id\":%u,\"method\":\"mining.authorize\",\"params\":[\"%s\",\"%s\",\"%s\"]}\n",
             auth_id, sess->auth_user, sess->auth_worker, pass);
    if (net_send_all(sess->conn, msg, strlen(msg)) != 0) { proto_disconnect(sess); return -1; }

    for (;;) {
        if (net_recv_line(sess->conn, line, sizeof(line), 5000) <= 0) {
            fprintf(stderr, "[STRATUM++] Timeout waiting for mining.authorize response\n");
            proto_disconnect(sess);
            return -1;
        }
        uint64_t rid = 0;
        if (strstr(line, "\"result\"") && json_extract_u64(line, "id", &rid) == 0 && rid == auth_id) {
            if (!strstr(line, "true")) {
                fprintf(stderr, "[STRATUM++] Authorization failed: %s\n", line);
                proto_disconnect(sess);
                return -1;
            }
            break;
        }
        handle_stratum_line(sess, line);
    }

    printf("[STRATUM++] Authorized user='%s' worker='%s'\n", sess->auth_user, sess->auth_worker);
    sess->rpc_id = 10; /* reserve >=10 for share submissions */
    return 0;
}

void proto_disconnect(protocol_session_t *sess) {
    if (sess->conn) {
        net_close(sess->conn);
        sess->conn = NULL;
    }
}

int proto_poll(protocol_session_t *sess, int timeout_ms) {
    if (!sess->conn) return -1;
    char buf[8192];
    if (sess->is_ws) {
        int r = ws_recv_text(sess->conn, buf, sizeof(buf), timeout_ms);
        if (r <= 0) return r;
        return handle_getwork_msg(sess, buf);
    } else {
        int r = net_recv_line(sess->conn, buf, sizeof(buf), timeout_ms);
        if (r <= 0) return r;
        return handle_stratum_line(sess, buf);
    }
}

int proto_submit_solution(protocol_session_t *sess, const miner_job_t *job, uint64_t nonce, const uint8_t solved_work112[112]) {
    if (!sess->conn) return -1;
    if (sess->is_ws) {
        char work_hex[225];
        bytes_to_hex(solved_work112, 112, work_hex);
        char msg[512];
        snprintf(msg, sizeof(msg), "{\"miner_work\":\"%s\"}", work_hex);
        return ws_send_text(sess->conn, msg);
    } else {
        uint8_t nonce_be[8];
        for (int i = 0; i < 8; i++) nonce_be[i] = (uint8_t)(nonce >> (56 - i * 8));
        char nonce_hex[17];
        bytes_to_hex(nonce_be, 8, nonce_hex);
        char msg[1024];
        snprintf(msg, sizeof(msg),
                 "{\"id\":%u,\"method\":\"mining.submit\",\"params\":[\"%s\",\"%s\",\"%s\"]}\n",
                 sess->rpc_id++, sess->auth_worker, job->job_id, nonce_hex);
        return net_send_all(sess->conn, msg, strlen(msg));
    }
}

int proto_report_hashrate(protocol_session_t *sess, uint64_t hashrate_hs) {
    if (!sess->conn || sess->is_ws) return 0;
    char msg[256];
    snprintf(msg, sizeof(msg),
             "{\"id\":null,\"method\":\"mining.hashrate\",\"params\":[%llu]}\n",
             (unsigned long long)hashrate_hs);
    return net_send_all(sess->conn, msg, strlen(msg));
}
