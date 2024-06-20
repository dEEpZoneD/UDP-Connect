#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <event2/event.h>
#include <event2/util.h>
#include <fcntl.h> 

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
#include "lsxpack_header.h"

#define HTTP_PORT 443
#define TARGET_PORT 8888

#define MAX(a, b) ((a) > (b) ? (a) : (b))

static FILE *log_file;

struct lsquic_http_headers headers;

struct proxy_client_ctx
{
    lsquic_engine_t *engine;
    // char payload_sizep[20];
    int sockfd;
    struct sockaddr_in local_sa;
    struct sockaddr_storage local_sas;
    struct lsquic_conn *conn;
    size_t              sz;         /* Size of bytes read is stored here */
    char                buf[0x100]; /* Read up to this many bytes */
    const char *method;
    const char *path;
    const char *protocol;
    const char *scheme;
    const char *authority;
    const char *payload;
};

struct proxy_client_ctx client_ctx;
lsquic_engine_t *engine;

struct lsquic_conn_ctx {
    lsquic_conn_t *conn;
    struct proxy_client_ctx *client_ctx;
};

struct lsquic_stream_ctx {
    lsquic_stream_t     *stream;
    struct proxy_client_ctx   *client_ctx;
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
        va_start(ap, fmt);
        (void) vfprintf(log_file, fmt, ap);
        va_end(ap);
        fprintf(log_file, "\n");
    }
}

static int
client_set_nonblocking (int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    if (-1 == flags)
        return -1;
    flags |= O_NONBLOCK;
    if (0 != fcntl(fd, F_SETFL, flags))
        return -1;

    return 0;
}

static SSL_CTX *s_ssl_ctx;
const char *cert_file = NULL, *key_file = NULL;
const char *key_log_dir = NULL;

static int
client_load_cert (const char *cert_file, const char *key_file)
{
    int rv = -1;

    s_ssl_ctx = SSL_CTX_new(TLS_method());
    if (!s_ssl_ctx)
    {
        LOG("SSL_CTX_new failed");
        goto end;
    }
    SSL_CTX_set_min_proto_version(s_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(s_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(s_ssl_ctx);
    if (1 != SSL_CTX_use_certificate_chain_file(s_ssl_ctx, cert_file))
    {
        LOG("SSL_CTX_use_certificate_chain_file failed");
        goto end;
    }
    if (1 != SSL_CTX_use_PrivateKey_file(s_ssl_ctx, key_file,
                                                            SSL_FILETYPE_PEM))
    {
        LOG("SSL_CTX_use_PrivateKey_file failed");
        goto end;
    }
    rv = 0;

  end:
    if (rv != 0)
    {
        if (s_ssl_ctx)
            SSL_CTX_free(s_ssl_ctx);
        s_ssl_ctx = NULL;
    }
    return rv;
}


static SSL_CTX *
my_client_get_ssl_ctx (void *peer_ctx)
{
    return s_ssl_ctx;
}

void print_packet_hex(const uint8_t *packet_data, int num_bytes) {
    fprintf(log_file, "Received Packet (%d bytes):\n", num_bytes);
    
    // Determine the maximum byte index for formatting (e.g., 99 for 100 bytes)
    int max_index = num_bytes - 1;
    int index_width = snprintf(NULL, 0, "%d", max_index);
    fprintf(log_file, "%*d: ", index_width, 0);
    for (int i = 0; i < num_bytes; i++) {
        fprintf(log_file, "%02X", packet_data[i]); 

        // Optional: Group bytes for readability
        if (i == num_bytes - 1) fprintf(log_file, "\n");
        else if ((i + 1) % 16 == 0) { 
            fprintf(log_file, "\n");
            fprintf(log_file, "%*d: ", index_width, i);
        } 
        else {
            fprintf(log_file, "  "); 
        }
    }
}

int read_socket(evutil_socket_t fd) {
    // struct proxy_client_ctx *client_ctx = (struct proxy_client_ctx*)arg;
    // lsquic_engine_t *engine = (lsquic_engine_t *)arg;
    ssize_t nread = 0;
    struct sockaddr_storage peer_addr_storage;
    struct sockaddr *peer_sa = (struct sockaddr *)&peer_addr_storage;
    unsigned char buf[0x1000];
    struct iovec iov[1] = {{ buf, sizeof(buf) }};;
    unsigned char ctl_buf[1024];

    struct msghdr msg = {
        .msg_name       = peer_sa,
        .msg_namelen    = sizeof(peer_addr_storage),
        .msg_iov        = iov,
        .msg_iovlen     = 1,
        .msg_control    = ctl_buf,
        .msg_controllen = 1024,
    };
    LOG("reading socket for packets");
    nread = recvmsg(fd, &msg, 0);
    LOG("Received %ld bytes", nread);
    if (0 > nread) {
        LOG("got -1 from recvmsg");
        if (!(EAGAIN == errno || EWOULDBLOCK == errno || ECONNRESET == errno)){
            LOG("recvmsg: %s", strerror(errno));
            return;
        }
    }
    if (nread > 0) {
        if (s_verbose) print_packet_hex(buf, nread);
        LOG("Providing packets to engine");
        (void) lsquic_engine_packet_in(client_ctx.engine, buf, nread,
            (struct sockaddr *) &(client_ctx.local_sa),
            peer_sa, (void*) &fd, 0);
    }
    int diff = 0;
    LOG("adv_tick");
    if (lsquic_engine_earliest_adv_tick(engine, &diff) == 1) {
        if (diff <= 0) {
            LOG("process_conn");
            lsquic_engine_process_conns(engine);
        }
    }
    LOG("read_socket end");
}

static int client_packets_out(void *packets_out_ctx, const struct lsquic_out_spec *specs, unsigned count) {
    struct proxy_client_ctx *client_ctx = packets_out_ctx;
    unsigned n;
    int fd, s = 0;
    struct msghdr msg;

    if (0 == count) 
        return 0;

    fd = 3;
    n = 0;
    LOG("sockfd = %d", fd);
    msg.msg_flags      = 0;
    msg.msg_control    = NULL;
    msg.msg_controllen = 0;
    do
    {   
        // fd                 = (int) (uint64_t) specs[n].peer_ctx;
        msg.msg_name       = (void *) specs[n].dest_sa;
        msg.msg_namelen    = (AF_INET == specs[n].dest_sa->sa_family ?
                                            sizeof(struct sockaddr_in) :
                                            sizeof(struct sockaddr_in6)),
        msg.msg_iov        = specs[n].iov;
        msg.msg_iovlen     = specs[n].iovlen;
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
    // struct proxy_client_ctx *client_ctc = stream_if_ctx;
    LOG("NEWW CONN");
    lsquic_conn_ctx_t *conn_h = stream_if_ctx;
    conn_h->conn = conn;
    lsquic_conn_make_stream(conn);
    conn_h->client_ctx = stream_if_ctx;
    return conn_h;
}

static void my_client_on_hsk_done (lsquic_conn_t *conn, enum lsquic_hsk_status status) {
    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    struct proxy_client_ctx *client_ctx = conn_h->client_ctx;

    if (status == LSQ_HSK_OK || status == LSQ_HSK_RESUMED_OK) {
        LOG("Handshake successful%s",
                    status == LSQ_HSK_RESUMED_OK ? "(session resumed)" : "");
    }
    else LOG("Handshake failed");
}

static void my_client_on_conn_closed (struct lsquic_conn *conn) {
    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    lsquic_conn_set_ctx(conn, NULL);
    // free(conn_h);
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
    return st_h;
}

static void my_client_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *h) {
    ssize_t nread;
    unsigned char buf[0x1000];

    nread = lsquic_stream_readf(stream, buf, sizeof(buf));
    if (nread > 0)
    {
        fwrite(buf, 1, nread, stdout);
        fflush(stdout);
    }
    else if (nread == 0)
    {
        LOG("read to end-of-stream: close connection");
        lsquic_stream_shutdown(stream, 0);
        lsquic_conn_close( lsquic_stream_conn(stream) );
    }
    else {
        LOG("error reading from stream (%s) -- exit loop");
        exit((EXIT_FAILURE));
    }
}

struct header_buf
{
    unsigned    off;
    char        buf[UINT16_MAX];
};


/* Convenience wrapper around somewhat involved lsxpack APIs */
int
client_set_header (struct lsxpack_header *hdr, struct header_buf *header_buf,
            const char *name, size_t name_len, const char *val, size_t val_len)
{
    if (header_buf->off + name_len + val_len <= sizeof(header_buf->buf))
    {
        memcpy(header_buf->buf + header_buf->off, name, name_len);
        memcpy(header_buf->buf + header_buf->off + name_len, val, val_len);
        lsxpack_header_set_offset2(hdr, header_buf->buf + header_buf->off,
                                            0, name_len, name_len, val_len);
        header_buf->off += name_len + val_len;
        return 0;
    }
    else
        return -1;
}

static void my_client_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *h) {
    lsquic_conn_t *conn;
    struct proxy_client_ctx *client_ctx;
    lsquic_stream_ctx_t *st_f = h;
    struct header_buf hbuf;
    struct lsxpack_header harray[5];
    struct lsquic_http_headers headers = { 6, harray, };

    hbuf.off = 0;
#define V(v) (v), strlen(v)
    client_set_header(&harray[0], &hbuf, V(":method"), V("CONNECT"));
    client_set_header(&harray[1], &hbuf, V(":protocol"), V("connect-udp"));
    client_set_header(&harray[2], &hbuf, V(":scheme"), V("https"));
    client_set_header(&harray[3], &hbuf, V(":path"), V("/udp/192.168.122.252/8888"));
    client_set_header(&harray[4], &hbuf, V(":authority"),
                                              V("142.250.191.78:443"));
    client_set_header(&harray[5], &hbuf, V("user-agent"), V("h3cli/lsquic"));

    if (0 == lsquic_stream_send_headers(stream, &headers, 0))
    {
        lsquic_stream_shutdown(stream, 1);
        lsquic_stream_wantread(stream, 1);
    }
    else
    {
        LOG("ERROR: lsquic_stream_send_headers failed: %s", strerror(errno));
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }
    // ssize_t nw;
    // conn = lsquic_stream_conn(stream);
    // struct lsquic_conn_ctx *conn_ctx = lsquic_conn_get_ctx(conn);

    // nw = lsquic_stream_write(stream, client_ctx->buf, client_ctx->sz);

    // if (nw > 0)
    // {
    //     client_ctx->sz -= (size_t) nw;
    //     if (client_ctx->sz == 0)
    //     {
    //         LOG("wrote all %zd bytes to stream, switch to reading",
    //                                                         (size_t) nw);
    //         lsquic_stream_shutdown(stream, 1);  /* This flushes as well */
    //         lsquic_stream_wantread(stream, 1);
    //     }
    //     else
    //     {
    //         memmove(client_ctx->buf, client_ctx->buf + nw, client_ctx->sz);
    //         LOG("wrote %zd bytes to stream, still have %zd bytes to write",
    //                                             (size_t) nw, client_ctx->sz);
    //     }
    // }
    // else
    // {
    //     /* When `on_write()' is called, the library guarantees that at least
    //      * something can be written.  If not, that's an error whether 0 or -1
    //      * is returned.
    //      */
    //     LOG("stream_write() returned %ld, abort connection", (long) nw);
    //     lsquic_conn_abort(lsquic_stream_conn(stream));
    // }
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

// union {
//     struct sockaddr     sa;
//     struct sockaddr_in  addr4;
//     struct sockaddr_in6 addr6;
// } proxy_addr;

// union {
//     struct sockaddr     sa;
//     struct sockaddr_in  addr4;
//     struct sockaddr_in6 addr6;
// } local_addr;

// union {
//     struct sockaddr     sa;
//     struct sockaddr_in  addr4;
//     struct sockaddr_in6 addr6;
// } target_addr;
struct sockaddr_in proxy_sa;
struct sockaddr_in target_sa;

static void
cli_usage () {
    fprintf(stdout,
"Usage:./client [options]\n"
"\n"
"   -t ip_addr      Set target server's IPv4 address\n"
"   -p ip_addr      Set proxy server's IPv4 address\n"
"   -f log_file     Set external file for logs\n"
"   -l level        Set library-wide log level.  Defaults to 'warning'.\n"
"                   Acceptable values are debug, info, notice, warning, error, alert, emerg, crit\n"
"   -v              Verbose: log program messages as well.\n"
// "   -M METHOD       Method.  GET by default.\n"
// "   -o opt=val      Set lsquic engine setting to some value, overriding the\n"
// "                     defaults.  For example,\n"
// "                           -o version=ff00001c -o cc_algo=2\n"
// "   -G DIR          Log TLS secrets to a file in directory DIR.\n"
"   -h              Print this help screen and exit.\n");
}

void argument_parser(int argc, char** argv) {
    int opt;
    while ((opt = getopt(argc, argv, "c:k:l:f:p:t:m:hv")) != -1) {
        switch(opt) {
            case 'm':
                printf("%s\n", optarg);
                break;
            case 'l':
                if (0 != lsquic_set_log_level(optarg)) {
                    fprintf(stderr, "error processing log-level: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
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
                if (inet_pton(AF_INET, optarg, &proxy_sa.sin_addr) != 1) {
                    fprintf(stderr, "Invalid proxy server IP address <%s>\n", optarg);
                    exit(EXIT_FAILURE);
                }
                // char ip_str[INET_ADDRSTRLEN];
                // inet_ntop(AF_INET, &proxy_addr.addr4, ip_str, INET_ADDRSTRLEN);
                // printf("%s\n", ip_str);
                break;
            case 't':
                if (inet_pton(AF_INET, optarg, &target_sa.sin_addr) != 1) {
                    fprintf(stderr, "Invalid target server IP address <%s>\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'c':
                cert_file = optarg;
                break;
            case 'k':
                key_file = optarg;
                break;
            case 'h':
                cli_usage();
                exit(EXIT_SUCCESS);
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
    socklen_t socklen;

    log_file = stderr;
    char errbuf[0x100];

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT)) {
        fprintf(stderr, "lsquic global initialisation failed");
        exit(EXIT_FAILURE);
    }

    memset(&client_ctx, 0, sizeof(client_ctx));
    memset(&target_sa, 0, sizeof(target_sa));
    memset(&proxy_sa, 0, sizeof(proxy_sa));
    proxy_sa.sin_family = AF_INET;
    proxy_sa.sin_addr.s_addr = inet_addr("192.168.122.51");  /*www.proxy.com*/
    proxy_sa.sin_port = 51813;

    int fd;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    client_ctx.sockfd = fd;

    if (0 != client_set_nonblocking(fd))
    {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }


    socklen = sizeof(client_ctx.local_sa);
    if (0 != bind((client_ctx.sockfd), (struct sockaddr *)&(client_ctx.local_sa), socklen))
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    getsockname((client_ctx.sockfd), &(client_ctx.local_sa), &socklen);
    fprintf(stderr, "Socket bound to port %d and fd: %d\n", ntohs(client_ctx.local_sa.sin_port), client_ctx.sockfd);

    argument_parser(argc, argv);

    if (!(cert_file && key_file)) {
        if (0 != client_load_cert(cert_file, key_file)) {
            LOG("Cannot load certificate");
            exit(EXIT_FAILURE);
        }
    }

    lsquic_engine_init_settings(&settings, LSENG_HTTP);
    // settings.es_ql_bits = 0;

    if (0 != lsquic_engine_check_settings(&settings, 0, errbuf, sizeof(errbuf))) {
        LOG("invalid settings: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    setvbuf(log_file, NULL, _IOLBF, 0);
    lsquic_logger_init(&logger_if, log_file, LLTS_HHMMSSUS);
    // lsquic_set_log_level("warnung");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    

    memset(&engine_api, 0, sizeof(engine_api));
    engine_api.ea_packets_out = client_packets_out;
    engine_api.ea_packets_out_ctx = (void *) &fd;
    engine_api.ea_stream_if = &my_client_callbacks;
    engine_api.ea_stream_if_ctx = &client_ctx;
    engine_api.ea_get_ssl_ctx   = my_client_get_ssl_ctx;
    engine_api.ea_settings = &settings;
    // engine_api.ea_hsi_if = 1;

    LOG("Creating a new engine");
    engine = lsquic_engine_new(LSENG_HTTP, &engine_api);
    if (!engine) {
        LOG("cannot create engine\n");
        exit(EXIT_FAILURE);
    }
    memcpy(&(client_ctx.engine), &engine, sizeof(engine));
    if ((client_ctx.engine) != engine) {
        printf("fuck this shit\n");
        exit(EXIT_FAILURE);
    }
    
    struct lsquic_conn_ctx conn_ctx;
    conn_ctx.client_ctx = &client_ctx;

    /*lsquic_conn_t *lsquic_engine_connect(lsquic_engine_t *engine, enum lsquic_
        version version, const struct sockaddr *local_sa, const struct sockaddr *peer_sa, 
        void *peer_ctx, lsquic_conn_ctx_t *conn_ctx, const char *sni, unsigned short base_plpmtu, 
        const unsigned char *sess_resume, size_t sess_resume_len, const unsigned char *token, 
        size_t token_sz) */
    LOG("Connecting to peer");
    lsquic_conn_t *conn = lsquic_engine_connect(engine, N_LSQVER, &(client_ctx.local_sa), &proxy_sa, NULL,
                                    &conn_ctx, NULL, 0, NULL, 0, NULL, 0);
    
    conn_ctx.conn = conn;
    if (!conn_ctx.conn)
    {
        LOG("cannot create connection");
        exit(EXIT_FAILURE);
    }
    lsquic_engine_process_conns(engine);
    
    // struct event_base *base = event_base_new();
    // if (!base) {
    //     perror("Couldn't create event_base");
    //     return 1;
    // }

    // // Create event for the socket with a timeout of 30 seconds
    // struct event *socket_event = event_new(
    //     base, client_ctx.sockfd, EV_READ | EV_PERSIST, read_socket, &client_ctx);
    // event_add(socket_event, NULL);

    // Event loop that keeps the program running until connection succeeds/fails
    
    // event_base_dispatch(base);


    // LOG("engine_process_conns called");
    while (1) read_socket(fd);
    
    if (conn_ctx.conn) {
        LOG("Closing connection");
        lsquic_conn_going_away(conn_ctx.conn);
        lsquic_conn_close(conn_ctx.conn);
    }

    if (client_ctx.engine) {
        LOG("Destroying engine");
        lsquic_engine_destroy(client_ctx.engine);
    }
    // free(&client_ctx);
    LOG("Did everything, exiting...");
    lsquic_global_cleanup();
    return 0;
}
