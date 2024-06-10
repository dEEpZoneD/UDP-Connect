#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <event2/event.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "lsquic.h"
// #include "../src/liblsquic/lsquic_hash.h"
#include "../src/liblsquic/lsquic_logger.h"
#include "../src/liblsquic/lsquic_int_types.h"
#include "../src/liblsquic/lsquic_util.h"
#include "lsxpack_header.h"
// #include "test_config.h"
// #include "test_common.h"
// #include "test_cert.h"
// #include "prog.h"

#define PORT 4443
#define BUF_SIZE 1024

static ssize_t s_pwritev;

static FILE *log_file;

static int
tut_log_buf (void *ctx, const char *buf, size_t len)
{
    FILE *out = ctx;
    fwrite(buf, 1, len, out);
    fflush(out);
    return 0;
}
static const struct lsquic_logger_if logger_if = { tut_log_buf, };

static int s_verbose;
static void
LOG (const char *fmt, ...)
{
    if (s_verbose)
    {
        va_list ap;
        fprintf(log_file, "LOG: ");
        va_start(ap, fmt);
        (void) vfprintf(log_file, fmt, ap);
        va_end(ap);
        fprintf(log_file, "\n");
    }
}

struct server_ctx
{
    struct lsquic_conn_ctx  *conn_h;
    lsquic_engine_t *engine;
    struct prog *prog;
    unsigned max_conn;
    unsigned n_conn;
    unsigned n_current_conns;
    unsigned delay_resp_sec;    
};

struct lsquic_conn_ctx
{
    lsquic_conn_t *conn;
    struct server_ctx *server_ctx;
    enum {
        RECEIVED_GOAWAY = 1 << 0,
    }                    flags;
};

struct lsquic_stream_ctx {
    lsquic_stream_t     *stream;
    struct server_ctx   *server_ctx;
    FILE                *req_fh;
    char                *req_buf;
    char                *req_filename;
    char                *req_path;
    size_t               req_sz;
    enum {
        SH_HEADERS_SENT = (1 << 0),
        SH_DELAYED      = (1 << 1),
        SH_HEADERS_READ = (1 << 2),
    }                    flags;
    struct lsquic_reader reader;
    int                  file_fd;   /* Used by pwritev */

    /* Fields below are used by interop callbacks: */
    enum interop_handler {
        IOH_ERROR,
        IOH_INDEX_HTML,
        IOH_MD5SUM,
        IOH_VER_HEAD,
        IOH_GEN_FILE,
        IOH_ECHO,
    }                    interop_handler;
    struct req          *req;
    const char          *resp_status;
    // union {
    //     struct index_html_ctx   ihc;
    //     struct ver_head_ctx     vhc;
    //     struct md5sum_ctx       md5c;
    //     struct gen_file_ctx     gfc;
    //     struct {
    //         char buf[0x100];
    //         struct resp resp;
    //     }                       err;
    // }                    interop_u;
    struct event        *resume_resp;
    size_t               written;
    size_t               file_size; /* Used by pwritev */
};

// static int server_packets_out();
// static int server_packets_in();

static lsquic_conn_ctx_t *server_on_new_conn(void *stream_if_ctx, struct lsquic_conn *conn) {
    struct server_ctx *server_ctx = stream_if_ctx;
    const char *sni;

    sni = lsquic_conn_get_sni(conn);
    LSQ_DEBUG("new connection, SNI: %s", sni ? sni : "<not set>");

    lsquic_conn_ctx_t *conn_h = malloc(sizeof(*conn_h));
    conn_h->conn = conn;
    conn_h->server_ctx = server_ctx;
    server_ctx->conn_h = conn_h;
    ++server_ctx->n_current_conns;
    return conn_h;
}

static void
server_on_goaway (lsquic_conn_t *conn)
{
    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    conn_h->flags |= RECEIVED_GOAWAY;
    LSQ_INFO("received GOAWAY");
}

static void server_on_hsk_done (lsquic_conn_t *conn, enum lsquic_hsk_status status);

static void server_on_conn_closed (struct lsquic_conn *conn) {
    static int stopped;
    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    LSQ_INFO("Connection closed");
    --conn_h->server_ctx->n_current_conns;
    if (conn_h->server_ctx->max_conn > 0)
    {
        ++conn_h->server_ctx->n_conn;
        LOG("Connection closed, remaining: %d",
                   conn_h->server_ctx->max_conn - conn_h->server_ctx->n_conn);
        if (conn_h->server_ctx->n_conn >= conn_h->server_ctx->max_conn)
        {
            if (!stopped)
            {
                stopped = 1;
                exit(EXIT_FAILURE);
            }
        }
    }
    /* No provision is made to stop HTTP server */
    lsquic_conn_set_ctx(conn, NULL);
    free(conn_h);
}
static lsquic_stream_ctx_t *server_on_new_stream (void *stream_if_ctx, struct lsquic_stream *stream) {
    struct lsquic_stream_ctx *st_h = calloc(1, sizeof(*st_h));
    st_h->stream = stream;
    st_h->server_ctx = stream_if_ctx;
    lsquic_stream_wantread(stream, 1);
    return st_h;
}

static void server_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *h);

static void server_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *h) {
    if (st_h->flags & SH_HEADERS_SENT)
    {
        ssize_t nw;
        if (bytes_left(st_h) > 0)
        {
            // if (st_h->server_ctx->delay_resp_sec
            //         && !(st_h->flags & SH_DELAYED)
            //             && st_h->written > 10000000)
            // {
            //     struct timeval delay = {
            //                     .tv_sec = st_h->server_ctx->delay_resp_sec, };
            //     st_h->resume_resp = event_new(st_h->server_ctx->prog->prog_eb,
            //                 -1, EV_TIMEOUT, resume_response, st_h);
            //     if (st_h->resume_resp)
            //     {
            //         event_add(st_h->resume_resp, &delay);
            //         lsquic_stream_wantwrite(stream, 0);
            //         st_h->flags |= SH_DELAYED;
            //         LSQ_NOTICE("delay response of stream %"PRIu64" for %u seconds",
            //             lsquic_stream_id(stream), st_h->server_ctx->delay_resp_sec);
            //         return;
            //     }
            //     else
            //         LSQ_ERROR("cannot allocate event");
            // }
            if (s_pwritev)
            {
                size_t to_write = bytes_left(st_h);
                if (s_pwritev > 0 && (size_t) s_pwritev < to_write)
                    to_write = s_pwritev;
                nw = lsquic_stream_pwritev(stream, my_preadv, st_h, to_write);
                if (nw == 0)
                {
                    struct lsquic_reader reader = {
                        .lsqr_read = pwritev_fallback_read,
                        .lsqr_size = pwritev_fallback_size,
                        .lsqr_ctx = st_h,
                    };
                    nw = lsquic_stream_writef(stream, &reader);
                }
            }
            else
            {
                nw = lsquic_stream_writef(stream, &st_h->reader);
            }
            if (nw < 0)
            {
                struct lsquic_conn *conn = lsquic_stream_conn(stream);
                lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
                if (conn_h->flags & RECEIVED_GOAWAY)
                {
                    LSQ_NOTICE("cannot write: goaway received");
                    lsquic_stream_close(stream);
                }
                else
                {
                    LSQ_ERROR("write error: %s", strerror(errno));
                    exit(1);
                }
            }
            if (bytes_left(st_h) > 0)
            {
                st_h->written += (size_t) nw;
                lsquic_stream_wantwrite(stream, 1);
            }
            else
            {
                lsquic_stream_shutdown(stream, 1);
                lsquic_stream_wantread(stream, 1);
            }
        }
        else
        {
            lsquic_stream_shutdown(stream, 1);
            lsquic_stream_wantread(stream, 1);
        }
    }
    else
    {
        if (0 != send_headers(stream, st_h))
            exit(1);
    }
}

static void server_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *h) {
    LOG("stream closed");
}

static struct lsquic_stream_if my_client_callbacks =
{
    .on_new_conn        = server_on_new_conn,
    .on_hsk_done        = server_on_hsk_done,
    .on_conn_closed     = server_on_conn_closed,
    .on_new_stream      = server_on_new_stream,
    .on_read            = server_on_read,
    .on_write           = server_on_write,
    .on_close           = server_on_close,
};

union {
    struct sockaddr     sa;
    struct sockaddr_in  addr4;
    struct sockaddr_in6 addr6;
} local_addr;

union {
    struct sockaddr     sa;
    struct sockaddr_in  addr4;
    struct sockaddr_in6 addr6;
} client_addr;

union {
    struct sockaddr     sa;
    struct sockaddr_in  addr4;
    struct sockaddr_in6 addr6;
} target_addr;

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit.....\n", signum);
        lsquic_global_cleanup();
        exit(0);
    }
}

void argument_parser(int argc, char** argv) {
    int opt;
    const char* optstring = "p:t:";
    while (opt = getopt(argc, argv, optstring)) {
        switch(opt) {
            case 'p':
                break;
            default:
                break;
        }
    }
}

/* Return number of packets sent or -1 on error */
static int
send_packets_out (void *ctx, const struct lsquic_out_spec *specs,
                                                unsigned n_specs)
{
    struct msghdr msg;
    int sockfd;
    unsigned n;

    memset(&msg, 0, sizeof(msg));
    sockfd = (int) (uintptr_t) ctx;

    for (n = 0; n < n_specs; ++n)
    {
        msg.msg_name       = (void *) specs[n].dest_sa;
        msg.msg_namelen    = sizeof(struct sockaddr_in);
        msg.msg_iov        = specs[n].iov;
        msg.msg_iovlen     = specs[n].iovlen;
        if (sendmsg(sockfd, &msg, 0) < 0)
            break;
    }

    return (int) n;
}

int main(int argc, char** argv) {
    struct lsquic_engine_api engine_api;
    
    struct sockaddr* local_addr;

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_SERVER|LSQUIC_GLOBAL_CLIENT)) {
        exit(EXIT_FAILURE);
    }

    memset(&engine_api, 0, sizeof(engine_api));
    // int flags;

    // flags = fcntl(fd, F_GETFL);
    // if (-1 == flags)
    //     return -1;
    // flags |= O_NONBLOCK;
    // if (0 != fcntl(fd, F_SETFL, flags))
    //     return -1;
    
    // memset(local_addr, 0, sizeof(*local_addr));
    // int on = 1;
    // local_addr.sa.sa_family = AF_INET;
    // setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof(on));
    // local_addr->sa_data = INADDR_ANY;
    // local_addr.sin_port = htons(PORT);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    lsquic_engine_t *engine = lsquic_engine_new(LSENG_SERVER|LSENG_HTTP, &engine_api);
    if (!engine) {
        fprintf(stderr, "cannot create engine\n");
        exit(EXIT_FAILURE);
    }

    int lsquic_engine_packet_in (lsquic_engine_t *,
        const unsigned char *udp_payload, size_t sz,
        const struct sockaddr *sa_local,
        const struct sockaddr *sa_peer,
        void *peer_ctx, int ecn);

    lsquic_engine_destroy(engine);
    lsquic_global_cleanup();
    return 0;
}