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
#include <fcntl.h> 

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

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define PORT 4443
#define BUF_SIZE 1024

static ssize_t s_pwritev;

static FILE *log_file;

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

struct server_ctx
{
    struct lsquic_conn_ctx  *conn_h;
    lsquic_engine_t *engine;
    struct sockaddr_in local_sa;
    int sockfd;
    unsigned max_conn;
    unsigned n_conn;
    unsigned n_current_conns;
    unsigned delay_resp_sec;
    char *method;
    char *protocol;
    char *scheme;
    char * path;
    char *authority;
};

struct server_ctx server_ctx;
struct lsquic_engine_api engine_api;
    struct lsquic_engine_settings settings;

struct lsquic_conn_ctx
{
    lsquic_conn_t *conn;
    struct server_ctx *server_ctx;
    enum {
        RECEIVED_GOAWAY = 1 << 0,
        HANDSHK_DONE = 1 << 1,
    }                    flags;
};

struct resp
{
    unsigned char *buf;
    size_t sz;
    off_t off;
};

struct req
{
    // enum method {
    //     UNSET, GET, POST, UNSUPPORTED,
    // }            method;
    enum {
        HAVE_XHDR   = 1 << 0,
    }            flags;
    enum {
        PH_AUTHORITY    = 1 << 0,
        PH_METHOD       = 1 << 1,
        PH_PATH         = 1 << 2,
    }            pseudo_headers;
    char        *path;
    char        *method;
    char        *authority;
    char        *scheme;
    char        *protocol;
    // char        *qif;
    // size_t       qif;
    struct lsxpack_header
                 xhdr;
    size_t       decode_off;
    char         decode_buf[MIN(LSXPACK_MAX_STRLEN + 1, 64 * 1024)];
};

struct lsquic_stream_ctx {
    lsquic_stream_t     *stream;
    struct server_ctx   *server_ctx;
    unsigned char *buf;
    size_t sz;
    off_t off;
    enum {
        SH_HEADERS_SENT = (1 << 0),
        SH_DELAYED      = (1 << 1),
        SH_HEADERS_READ = (1 << 2),
    }                    flags;
    struct lsquic_reader reader;
    int                  file_fd;   /* Used by pwritev */

    
    struct req          *req;
    const char          *resp_status;
    // union {
    //     struct index_html_ctx   ihc;
    //     struct ver_head_ctx     vhc;
    //     struct md5sum_ctx       md5c;
    //     struct gen_file_ctx     gfc;
        struct {
            char buf[0x100];
            struct resp resp;
        }                       err;
    // }                    interop_u;
    struct event        *resume_resp;
    size_t               written;
    size_t               file_size; /* Used by pwritev */
};

struct sockaddr_in client_sa;
struct sockaddr_in target_sa;

static int
server_set_nonblocking (int fd)
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
server_load_cert (const char *cert_file, const char *key_file)
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
my_server_get_ssl_ctx (void *peer_ctx)
{
    return s_ssl_ctx;
}

// static void *
// keylog_open (void *ctx, lsquic_conn_t *conn) {
//     const char *const dir = ctx ? ctx : ".";
//     const lsquic_cid_t *cid;
//     FILE *fh;
//     int sz;
//     unsigned i;
//     char id_str[MAX_CID_LEN * 2 + 1];
//     char path[PATH_MAX];
//     static const char b2c[16] = "0123456789ABCDEF";

//     cid = lsquic_conn_id(conn);
//     for (i = 0; i < cid->len; ++i)
//     {
//         id_str[i * 2 + 0] = b2c[ cid->idbuf[i] >> 4 ];
//         id_str[i * 2 + 1] = b2c[ cid->idbuf[i] & 0xF ];
//     }
//     id_str[i * 2] = '\0';
//     sz = snprintf(path, sizeof(path), "%s/%s.keys", dir, id_str);
//     if ((size_t) sz >= sizeof(path))
//     {
//         LOG("WARN: %s: file too long", __func__);
//         return NULL;
//     }
//     fh = fopen(path, "wb");
//     if (!fh)
//         LOG("WARN: could not open %s for writing: %s", path, strerror(errno));
//     return fh;
// }

// static void
// keylog_log_line (void *handle, const char *line) {
//     fputs(line, handle);
//     fputs("\n", handle);
//     fflush(handle);
// }

// static void
// keylog_close (void *handle) {
//     fclose(handle);
// }

// static const struct lsquic_keylog_if *keylog_if =
// {
//     .kli_open       = keylog_open,
//     .kli_log_line   = keylog_log_line,
//     .kli_close      = keylog_close,
// };

int send_udp_data(struct sockaddr_in *target_addr, const char *data_buf, size_t buf_len) {
    int sockfd;

    // Create a UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        return -1;
    }
    // Send the data to the target
    ssize_t sent_len = sendto(sockfd, data_buf, buf_len, 0, (const struct sockaddr *)&target_addr, sizeof(target_addr));
    if (sent_len < 0) {
        perror("sendto failed");
        close(sockfd);
        return -1;
    }

    LOG("Sent %zd bytes", sent_len);

    // Close the socket
    close(sockfd);
    return 0;
}

static lsquic_conn_ctx_t *server_on_new_conn(void *stream_if_ctx, struct lsquic_conn *conn) {
    LOG("on_new_conn called");
    struct server_ctx *server_ctx = stream_if_ctx;
    // const char *sni;

    // sni = lsquic_conn_get_sni(conn);
    // LOG("new connection, SNI: %s", sni ? sni : "<not set>");

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
    LOG("received GOAWAY");
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
    struct lsquic_stream_ctx *st_h = malloc(sizeof(*st_h));
    if (!st_h)
    {
        LOG("cannot allocate server stream context");
        lsquic_conn_abort(lsquic_stream_conn(stream));
        return NULL;
    }
    st_h->stream = stream;
    st_h->server_ctx = stream_if_ctx;
    lsquic_stream_wantread(stream, 1);
    return st_h;
}

static int parse_request(struct lsquic_stream *stream, lsquic_stream_ctx_t *st_h) {
    int found_method = 0, found_protocol = 0, found_scheme = 0, found_path = 0, found_authority = 0;
    char *line, *key, *value;
    line = strtok(st_h->buf, "\r\n");
    while (line != NULL) {
        // Split the header line into key and value
        key = strtok(line, ": ");
        value = strtok(NULL, "\r\n");

        if (key && value) {
            // Check for required headers
            if (strcasecmp(key, ":method") == 0 && !found_method) {
                strncpy(st_h->req->method, value, sizeof(st_h->req->method) - 1);
                found_method = 1;
            } else if (strcasecmp(key, ":protocol") == 0 && !found_protocol) {
                strncpy(st_h->req->protocol, value, sizeof(st_h->req->protocol) - 1);
                found_protocol = 1;
            } else if (strcasecmp(key, ":scheme") == 0 && !found_scheme) {
                strncpy(st_h->req->scheme, value, sizeof(st_h->req->scheme) - 1);
                found_scheme = 1;
            } else if (strcasecmp(key, ":path") == 0 && !found_path) {
                strncpy(st_h->req->path, value, sizeof(st_h->req->path) - 1);
                found_path = 1;
            } else if (strcasecmp(key, ":authority") == 0 && !found_authority) {
                strncpy(st_h->req->authority, value, sizeof(st_h->req->authority) - 1);
                found_authority = 1;
            }
            // Add parsing logic for other headers as needed
        }

        line = strtok(NULL, "\r\n"); // Get the next line
    }

    if (found_method && found_protocol && found_scheme && found_path && found_authority) {
        // All required headers found
        return 0; // Success
    }

    
    // Reached end of headers without finding all required headers, or error occurred
    return -1; // Error
}

// static int process_request(struct lsquic_stream *stream, lsquic_stream_ctx_t *st_h) {
//     if (st_h->req->protocol == "connect-udp") {
//         send_udp_data();
//     }
// }

static void server_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *h) {
    struct lsquic_stream_ctx *st_h = h;
    ssize_t nread;
    unsigned char buf[1024];

    nread = lsquic_stream_read(stream, buf, sizeof(buf));
    if (nread > 0) {
        st_h->buf = &buf[0];
        st_h->sz++;
    }
    else if (nread == 0) {
        LOG("got request: `%.*s'", (int) st_h->sz, st_h->buf);
        // parse_request(stream, st_h);
        // process_request(stream, st_h);
        // free(st_h->buf);
        lsquic_stream_shutdown(stream, 0);
    }
    else {
        LOG("error reading: %s", strerror(errno));
        lsquic_stream_close(stream);
    }
}

struct header_buf
{
    unsigned    off;
    char        buf[UINT16_MAX];
};

int
header_set_ptr (struct lsxpack_header *hdr, struct header_buf *header_buf,
                const char *name, size_t name_len,
                const char *val, size_t val_len)
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

static int
send_headers (struct lsquic_stream *stream, lsquic_stream_ctx_t *st_h)
{
    struct header_buf hbuf;

    struct lsxpack_header headers_arr[1];

    hbuf.off = 0;
    header_set_ptr(&headers_arr[0], &hbuf, ":status", 7, "200", 3);
    lsquic_http_headers_t headers = {
        .count = sizeof(headers_arr) / sizeof(headers_arr[0]),
        .headers = headers_arr,
    };
    if (0 != lsquic_stream_send_headers(stream, &headers, 0))
    {
        LOG("cannot send headers: %s", strerror(errno));
        return -1;
    }

    st_h->flags |= SH_HEADERS_SENT;
    return 0;
}

static void server_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *h) {
    struct lsquic_stream_ctx *st_h = h;

    if (st_h->flags && SH_HEADERS_SENT) {
        if (0 != send_headers(stream, st_h)) exit(EXIT_FAILURE);
        return;
    }

    // const size_t left = tssc->tssc_sz;
    ssize_t nw;
    assert(st_h->sz > 0);
    nw = lsquic_stream_write(stream, st_h->buf+st_h->off, st_h->sz-st_h->off);
    if (nw > 0) {
        st_h->off += nw;
        if (st_h->off == st_h->sz)
        {
            LOG("wrote all %zd bytes to stream, close stream",
                                                            (size_t) nw);
            lsquic_stream_close(stream);
        }
        else
            LOG("wrote %zd bytes to stream, still have %zd bytes to write",
                                (size_t) nw, st_h->sz - st_h->off);
    }
    else {
        LOG("stream_write() returned %ld, abort connection", (long) nw);
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }
}

static void server_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *h) {
    LOG("stream closed");
}

static struct lsquic_stream_if my_server_callbacks =
{
    .on_new_conn        = server_on_new_conn,
    // .on_hsk_done        = server_on_hsk_done,
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
    while ((opt = getopt(argc, argv, "c:k:G:l:p:f:v")) != -1) {
        switch(opt) {
            case 'p':
                break;
            case 'c':
                cert_file = optarg;
                break;
            case 'k':
                key_file = optarg;
                break;
            case 'G':
                key_log_dir = optarg;
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
            default:
                fprintf(stderr, "Unknown option\n");
                exit(EXIT_FAILURE);
                break;
        }
    }
}

/* Return number of packets sent or -1 on error */
static int
send_packets_out (void *packets_out_ctx, const struct lsquic_out_spec *specs, unsigned n_specs) {
    struct server_ctx *server_ctx = packets_out_ctx;
    struct msghdr msg;
    int sockfd;
    unsigned n;

    memset(&msg, 0, sizeof(msg));
    sockfd = (int) server_ctx->sockfd;

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
    // struct server_ctx *server_ctx = (struct server_ctx*)arg;
    // lsquic_engine_t *engine = (lsquic_engine_t *)arg;
    ssize_t nread;
    struct sockaddr_storage peer_addr_storage;
    struct sockaddr *peer_sa = (struct sockaddr *)&peer_addr_storage;
    unsigned char *buf = malloc(4096);
    struct iovec iov[1] = {{ buf, 4096 }};
    unsigned char ctl_buf[1024];

    struct msghdr msg = {
        .msg_name       = peer_sa,
        .msg_namelen    = sizeof(peer_addr_storage),
        .msg_iov        = iov,
        .msg_iovlen     = 1,
        .msg_control    = ctl_buf,
        .msg_controllen = 1024,
    };
    
    nread = recvmsg(fd, &msg, 0);
    if (0 > nread) {
        LOG("got -1 from recvmsg");
        if (!(EAGAIN == errno || EWOULDBLOCK == errno || ECONNRESET == errno)) {
            LOG("recvmsg: %s", strerror(errno));
            return;
        }
    }

    if (nread == 0) return;
    if (s_verbose) print_packet_hex(buf, nread);
    int ecn = 0;
    // tut_proc_ancillary(&msg, &local_sas, &ecn);
    LOG("Providing packets to engine");
    lsquic_engine_packet_in(server_ctx.engine, buf, nread,
        (struct sockaddr *) &(server_ctx.local_sa),
        peer_sa, NULL, ecn);
    
    int diff = 0;
    LOG("adv_tick");
    while (lsquic_engine_earliest_adv_tick(server_ctx.engine, &diff) == 1) {
        if (diff <= 0) {
            LOG("process_conn");
            lsquic_engine_process_conns(server_ctx.engine);
        }
    }
    LOG("read_socket enf");
}

int main(int argc, char** argv) {
    const char *key_log_dir = NULL;
    // struct lsquic_engine_api engine_api;
    // struct lsquic_engine_settings settings;
    // struct server_ctx server_ctx;
    int sockfd;

    log_file = stderr;
    char errbuf[0x100];

    argument_parser(argc, argv);

    if (!(cert_file && key_file)) {
        LOG("Specify both cert (-c) and key (-k) files");
        exit(EXIT_FAILURE);
    }
    
    if (0 != server_load_cert(cert_file, key_file)) {
        LOG("Cannot load certificate");
        exit(EXIT_FAILURE);
    }

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_SERVER)) {
        fprintf(stderr, "Global init failed\n");
        exit(EXIT_FAILURE);
    }

    memset(&server_ctx, 0, sizeof(server_ctx));
    memset(&engine_api, 0, sizeof(engine_api));
    
    printf("hello\n");
    lsquic_engine_init_settings(&settings, LSENG_SERVER);
    settings.es_ql_bits = 0;

    if (0 != lsquic_engine_check_settings(&settings, LSENG_SERVER, errbuf, sizeof(errbuf))) {
        LOG("invalid settings: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
    server_ctx.sockfd = sockfd;

    if (0 != server_set_nonblocking(sockfd))
    {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }

    server_ctx.local_sa.sin_family = AF_INET;
    server_ctx.local_sa.sin_addr.s_addr = inet_addr("192.168.122.51");
    server_ctx.local_sa.sin_port = 51813;

    if (0 != bind(sockfd, (struct sockaddr *)&(server_ctx.local_sa), sizeof(server_ctx.local_sa)))
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    getsockname(sockfd, (struct sockaddr *)&(server_ctx.local_sa), sizeof(server_ctx.local_sa));
    fprintf(stderr, "bound to port:%d, sockfd:%d\n", server_ctx.local_sa.sin_port, sockfd);

    setvbuf(log_file, NULL, _IOLBF, 0);
    lsquic_logger_init(&logger_if, log_file, LLTS_HHMMSSUS);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    engine_api.ea_packets_out = send_packets_out;
    engine_api.ea_packets_out_ctx = &server_ctx;
    engine_api.ea_stream_if = &my_server_callbacks;
    engine_api.ea_stream_if_ctx = &server_ctx;
    engine_api.ea_get_ssl_ctx   = my_server_get_ssl_ctx;
    // if (key_log_dir)
    // {
    //     engine_api.ea_keylog_if = keylog_if;
    //     engine_api.ea_keylog_ctx = (void *) key_log_dir;
    // }
    engine_api.ea_settings = &settings;

    server_ctx.engine = lsquic_engine_new(LSENG_SERVER|LSENG_HTTP, &engine_api);
    if (!server_ctx.engine) {
        fprintf(stderr, "cannot create engine\n");
        exit(EXIT_FAILURE);
    }

    struct event_base *base = event_base_new();
    if (!base) {
        perror("Couldn't create event_base");
        exit(EXIT_FAILURE);
    }

    struct event *socket_event = event_new(
        base, sockfd, EV_READ | EV_PERSIST, read_socket, (void*) &server_ctx);
    event_add(socket_event, NULL);
    
    event_base_dispatch(base);
    // while (1) read_socket(server_ctx.sockfd);
    if(server_ctx.engine) lsquic_engine_destroy(server_ctx.engine);
    lsquic_global_cleanup();
    return 0;
}