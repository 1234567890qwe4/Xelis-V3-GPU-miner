#ifndef MINER_NET_H
#define MINER_NET_H

#include "miner_common.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct net_conn net_conn_t;

int  net_global_init(void);
void net_global_cleanup(void);

net_conn_t *net_connect(const char *host, uint16_t port, int use_ssl);
void        net_close(net_conn_t *conn);
int         net_send_all(net_conn_t *conn, const void *buf, size_t len);
int         net_recv_line(net_conn_t *conn, char *buf, size_t buf_sz, int timeout_ms);
int         net_recv_raw(net_conn_t *conn, void *buf, size_t len, int timeout_ms);

/* Protocol session handle */
typedef struct {
    miner_config_t cfg;
    net_conn_t    *conn;
    int            is_ws;
    uint32_t       rpc_id;
    char           session_id[128];
    uint8_t        extranonce[32];
    size_t         extranonce_len;
    uint8_t        pubkey[32];
    uint64_t       current_difficulty;
    uint8_t        current_target_be[32];
    char           auth_user[512];
    char           auth_worker[128];
    miner_job_t    latest_job;
    int            has_job;
    uint64_t       accepted;
    uint64_t       rejected;
} protocol_session_t;

/* Connect & handshake (Stratum++ TCP/SSL as top priority, or Xelis-V3 WebSocket GetWork) */
int  proto_connect_and_auth(protocol_session_t *sess, const miner_config_t *cfg);
void proto_disconnect(protocol_session_t *sess);

/* Poll for incoming jobs / ping / share responses (returns >0 if new job arrived, 0 if ok, <0 on disconnect) */
int  proto_poll(protocol_session_t *sess, int timeout_ms);

/* Submit found nonce (for Stratum++) or full 112-byte MinerWork (for Xelis-V3 GetWork) */
int  proto_submit_solution(protocol_session_t *sess, const miner_job_t *job, uint64_t nonce, const uint8_t solved_work112[112]);

/* Send periodic hashrate report (Stratum++ mining.hashrate) */
int  proto_report_hashrate(protocol_session_t *sess, uint64_t hashrate_hs);

#ifdef __cplusplus
}
#endif

#endif /* MINER_NET_H */
