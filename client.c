#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
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

#define PROXY_PORT 443
#define TARGET_PORT 8888

#define MAX(a, b) ((a) > (b) ? (a) : (b))

static FILE *log_file;

typedef struct
{
    const char *hostname;
    const char *method;
    const char *payload;
    char payload_sizep[20];
    struct lsquic_conn *conn;
    size_t              sz;         /* Size of bytes read is stored here */
    char                buf[0x100]; /* Read up to this many bytes */
}proxy_client_ctx;

struct lsquic_conn_ctx {
    lsquic_conn_t *conn;
    proxy_client_ctx *client_ctx;
};

struct lsquic_stream_ctx {
    lsquic_stream_t     *stream;
    proxy_client_ctx   *client_ctx;
    enum {
        HEADERS_SENT    = (1 << 0),
        PROCESSED_HEADERS = 1 << 1,
        ABANDON = 1 << 2,   /* Abandon reading from stream after sh_stop bytes
                             * have been read.
                             */
    } sh_flags;
    size_t               sh_stop;   /* Stop after reading this many bytes if ABANDON is set */
    size_t               sh_nread;  /* Number of bytes read from stream using one of
                                     * lsquic_stream_read* functions.
                                     */
    unsigned             count;
    FILE                *download_fh;
    struct lsquic_reader reader;
};

static int
my_log_buf (void *ctx, const char *buf, size_t len)
{
    FILE *out = ctx;
    fwrite(buf, 1, len, out);
    fflush(out);
    return 0;
}
static const struct lsquic_logger_if logger_if = { my_log_buf, };

static int s_verbose = 0;
static void
LOG (const char *fmt, ...)
{
    if (s_verbose)
    {
        va_list ap;
        fprintf(log_file, "LOG: ");
        va_start( ap, fmt);
        (void) vfprintf(log_file, fmt, ap);
        va_end(ap);
        fprintf(log_file, "\n");
    }
}

static int client_packets_out(void *packets_out_ctx, const struct lsquic_out_spec *specs, unsigned count) {
    proxy_client_ctx const* client_ctx = packets_out_ctx;
    unsigned n;
    int fd, s = 0;
    struct msghdr msg;
    // enum ctl_what cw;
    // union {
    //     /* cmsg(3) recommends union for proper alignment */
    //     unsigned char buf[
    //         CMSG_SPACE(MAX(sizeof(struct in_pktinfo),
    //             sizeof(struct in6_pktinfo))) + CMSG_SPACE(sizeof(int))
    //     ];
    struct cmsghdr cmsg;
    // } ancil;

    if (0 == count)
        return 0;

    n = 0;
    msg.msg_flags = 0;
    do
    {
        fd                 = (int) (uint64_t) specs[n].peer_ctx;
        msg.msg_name       = (void *) specs[n].dest_sa;
        msg.msg_namelen    = (AF_INET == specs[n].dest_sa->sa_family ?
                                            sizeof(struct sockaddr_in) :
                                            sizeof(struct sockaddr_in6)),
        msg.msg_iov        = specs[n].iov;
        msg.msg_iovlen     = specs[n].iovlen;

        /* Set up ancillary message */
        // cw = 0;
        // if (specs[n].ecn)
        //     cw |= CW_ECN;
        // if (cw)
        //     tut_setup_control_msg(&msg, cw, &specs[n], ancil.buf,
        //                                             sizeof(ancil.buf));
        // else
        // {
            msg.msg_control    = NULL;
            msg.msg_controllen = 0;
        // }

        s = sendmsg(fd, &msg, 0);
        if (s < 0)
        {
            LOG("sendmsg failed: %s", strerror(errno));
            break;
        }
        ++n;
    }
    while (n < count);

    if (n < count)
        LOG("could not send all of them");    /* TODO */

    if (n > 0)
        return n;
    else
    {
        assert(s < 0);
        return -1;
    }
}

static lsquic_conn_ctx_t *my_client_on_new_conn(void *stream_if_ctx, struct lsquic_conn *conn) {
    proxy_client_ctx *client_ctc = stream_if_ctx;
    lsquic_conn_ctx_t *conn_h = calloc(1, sizeof(*conn_h));
    conn_h->conn = conn;
    conn_h->client_ctx = client_ctc;
    return conn_h;
}

static void my_client_on_hsk_done (lsquic_conn_t *conn, enum lsquic_hsk_status status) {
    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    proxy_client_ctx *client_ctx = conn_h->client_ctx;

    if (status == LSQ_HSK_OK || status == LSQ_HSK_RESUMED_OK) {
        LOG("Handshake successful%s",
                    status == LSQ_HSK_RESUMED_OK ? "(session resumed)" : "");
    }
    else LOG("Handshake failed");
}

static void my_client_on_conn_closed (struct lsquic_conn *conn) {
    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    lsquic_conn_set_ctx(conn, NULL);
    free(conn_h);
    LOG("Connection closed");
}

static lsquic_stream_ctx_t *my_client_on_new_stream (void *stream_if_ctx, struct lsquic_stream *stream) {
    const int pushed = lsquic_stream_is_pushed(stream);

    if (pushed)
    {
        LOG("not accepting server push");
        lsquic_stream_refuse_push(stream);
        return NULL;
    }
    lsquic_stream_ctx_t *st_h = calloc(1, sizeof(*st_h));
    st_h->stream = stream;
    st_h->client_ctx = stream_if_ctx;
    LOG("created new stream, we want to write");
    lsquic_stream_wantwrite(stream, 1);
    /* return tut: we don't have any stream-specific context */
    return st_h;
}

static size_t
my_client_read(void *ctx, const unsigned char *data, size_t len, int fin)
{
    if (len)
    {
        fwrite(data, 1, len, stdout);
        fflush(stdout);
    }
    return len;
}

static void my_client_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *h){
    struct tut *tut = (struct tut *) h;
    ssize_t nread;

    nread = lsquic_stream_readf(stream, my_client_read, NULL);
    if (nread == 0)
    {
        LOG("read to end-of-stream: close and read from stdin again");
        lsquic_stream_shutdown(stream, 0);
    }
    else if (nread < 0)
    {
        LOG("error reading from stream (%s) -- exit loop");
    }
}

static void my_client_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *h) {
    lsquic_conn_t *conn;
    proxy_client_ctx *client_ctx;
    ssize_t nw;
    conn = lsquic_stream_conn(stream);
    struct lsquic_conn_ctx *conn_ctx = lsquic_conn_get_ctx(conn);

    nw = lsquic_stream_write(stream, client_ctx->buf, client_ctx->sz);

    if (nw > 0)
    {
        client_ctx->sz -= (size_t) nw;
        if (client_ctx->sz == 0)
        {
            LOG("wrote all %zd bytes to stream, switch to reading",
                                                            (size_t) nw);
            lsquic_stream_shutdown(stream, 1);  /* This flushes as well */
            lsquic_stream_wantread(stream, 1);
        }
        else
        {
            memmove(client_ctx->buf, client_ctx->buf + nw, client_ctx->sz);
            LOG("wrote %zd bytes to stream, still have %zd bytes to write",
                                                (size_t) nw, client_ctx->sz);
        }
    }
    else
    {
        /* When `on_write()' is called, the library guarantees that at least
         * something can be written.  If not, that's an error whether 0 or -1
         * is returned.
         */
        LOG("stream_write() returned %ld, abort connection", (long) nw);
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }
}

static void my_client_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *h) {
    LOG("stream closed");
}

static struct lsquic_stream_if my_client_callbacks =
{
    .on_new_conn        = my_client_on_new_conn,
    .on_hsk_done        = my_client_on_hsk_done,
    .on_conn_closed     = my_client_on_conn_closed,
    .on_new_stream      = my_client_on_new_stream,
    .on_read            = my_client_on_read,
    .on_write           = my_client_on_write,
    .on_close           = my_client_on_close,
};

union {
    struct sockaddr     sa;
    struct sockaddr_in  addr4;
    struct sockaddr_in6 addr6;
} proxy_addr;

union {
    struct sockaddr     sa;
    struct sockaddr_in  addr4;
    struct sockaddr_in6 addr6;
} local_addr;

union {
    struct sockaddr     sa;
    struct sockaddr_in  addr4;
    struct sockaddr_in6 addr6;
} target_addr;

void argument_parser(int argc, char** argv) {
    int opt;
    while ((opt = getopt(argc, argv, "vf:p:t:")) != -1) {
        switch(opt) {
            case 'v':
                s_verbose = 1;
                break;
            case 'f':
                log_file = fopen(optarg, "ab");
                if (!log_file)
                {
                    perror("cannot open log file for writing");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'p':
                if (inet_pton(AF_INET, optarg, &proxy_addr.addr4) != 1) {
                    fprintf(stderr, "Invalid IP address <%s>\n", optarg);
                    exit(EXIT_FAILURE);
                }
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &proxy_addr.addr4, ip_str, INET_ADDRSTRLEN);
                printf("%s\n", ip_str);
                break;
            case 't':
                if (inet_pton(AF_INET, optarg, &target_addr.addr4) != 1) {
                    fprintf(stderr, "Invalid IP address %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                fprintf(stderr, "Unknown option %c\n", opt);
                exit(EXIT_FAILURE);
                break;
        }
    }
}

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nReceived signal %d, preparing to exit.....\n", signum);
        lsquic_global_cleanup();
        exit(0);
    }
}

int main(int argc, char** argv) {
    struct lsquic_engine_api engine_api;
    struct lsquic_engine_settings settings;
    log_file = stderr;
    char errbuf[0x100];

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT)) {
        fprintf(stderr, "Lsquic global initialisation failed");
        exit(EXIT_FAILURE);
    }
    argument_parser(argc, argv);

    setvbuf(log_file, NULL, _IOLBF, 0);
    lsquic_logger_init(&logger_if, log_file, LLTS_HHMMSSUS);

    lsquic_engine_init_settings(&settings, LSENG_HTTP);
    settings.es_ql_bits = 0;

    if (0 != lsquic_engine_check_settings(&settings, LSENG_HTTP,
    errbuf, sizeof(errbuf))) {
        LOG("invalid settings: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    

    memset(&engine_api, 0, sizeof(engine_api));
    engine_api.ea_packets_out = client_packets_out;
    engine_api.ea_packets_out_ctx = NULL;
    engine_api.ea_stream_if = &my_client_callbacks;
    engine_api.ea_stream_if_ctx = NULL;
    engine_api.ea_settings = &settings;

    lsquic_engine_t* engine = lsquic_engine_new(LSENG_HTTP, &engine_api);
    if (!engine) {
        LOG("cannot create engine\n");
        exit(EXIT_FAILURE);
    }
    // lsquic_conn_close(conn);
    // lsquic_engine_destroy(engine);
    lsquic_global_cleanup();
    return 0;
}
