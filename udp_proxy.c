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
#include <sys/queue.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "lsquic.h"
#include "../src/liblsquic/lsquic_logger.h"
#include "../src/liblsquic/lsquic_hash.h"
#include "../src/liblsquic/lsquic_int_types.h"
#include "../src/liblsquic/lsquic_util.h"
#include "lsxpack_header.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

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
    struct sockaddr_storage local_sas;
    int sockfd;
    unsigned max_conn;
    unsigned n_conn;
    unsigned n_current_conns;
    unsigned delay_resp_sec;
    struct event_base *server_eb;
    struct event *ev;
    struct event *server_timer;
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
    enum method {
        UNSET, GET, POST, CONNECT, UNSUPPORTED,
    }            method_e;
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
    struct req          *req;
    const char          *resp_status;
};

struct sockaddr_in target_sa;
struct sockaddr_in local_sa;

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

struct ssl_ctx_st *s_ssl_ctx;
struct lsquic_hash *prog_certs;

struct server_cert
{
    char                *ce_sni;
    struct ssl_ctx_st   *ce_ssl_ctx;
    struct lsquic_hash_elem ce_hash_el;
};

static char s_alpn[0x100];

static int
select_alpn (SSL *ssl, const unsigned char **out, unsigned char *outlen,
                    const unsigned char *in, unsigned int inlen, void *arg)
{
    int r;

    r = SSL_select_next_proto((unsigned char **) out, outlen, in, inlen,
                                    (unsigned char *) s_alpn, strlen(s_alpn));
    if (r == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    else
    {
        LSQ_WARN("no supported protocol can be selected from %.*s",
                                                    (int) inlen, (char *) in);
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
}

int
load_cert (struct lsquic_hash *certs, const char *optarg)
{
    int rv = -1;
    char *sni, *cert_file, *key_file;
    struct server_cert *cert = NULL;
    EVP_PKEY *pkey = NULL;
    FILE *f = NULL;

    sni = strdup(optarg);
    cert_file = strchr(sni, ',');
    if (!cert_file)
        goto end;
    *cert_file = '\0';
    ++cert_file;
    key_file = strchr(cert_file, ',');
    if (!key_file)
        goto end;
    *key_file = '\0';
    ++key_file;

    cert = calloc(1, sizeof(*cert));
    cert->ce_sni = strdup(sni);

    cert->ce_ssl_ctx = SSL_CTX_new(TLS_method());
    if (!cert->ce_ssl_ctx)
    {
        LSQ_ERROR("SSL_CTX_new failed");
        goto end;
    }
    SSL_CTX_set_min_proto_version(cert->ce_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(cert->ce_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(cert->ce_ssl_ctx);
    SSL_CTX_set_alpn_select_cb(cert->ce_ssl_ctx, select_alpn, NULL);
    {
        const char *const s = getenv("LSQUIC_ENABLE_EARLY_DATA");
        if (!s || atoi(s))
            SSL_CTX_set_early_data_enabled(cert->ce_ssl_ctx, 1);    /* XXX */
    }
    if (1 != SSL_CTX_use_certificate_chain_file(cert->ce_ssl_ctx, cert_file))
    {
        LSQ_ERROR("SSL_CTX_use_certificate_chain_file failed: %s", cert_file);
        goto end;
    }

    if (strstr(key_file, ".pkcs8"))
    {
        f = fopen(key_file, "r");
        if (!f)
        {
            LSQ_ERROR("fopen(%s) failed: %s", cert_file, strerror(errno));
            goto end;
        }
        pkey = d2i_PrivateKey_fp(f, NULL);
        fclose(f);
        f = NULL;
        if (!pkey)
        {
            LSQ_ERROR("Reading private key from %s failed", key_file);
            goto end;
        }
        if (!SSL_CTX_use_PrivateKey(cert->ce_ssl_ctx, pkey))
        {
            LSQ_ERROR("SSL_CTX_use_PrivateKey failed");
            goto end;
        }
    }
    else if (1 != SSL_CTX_use_PrivateKey_file(cert->ce_ssl_ctx, key_file,
                                                            SSL_FILETYPE_PEM))
    {
        LSQ_ERROR("SSL_CTX_use_PrivateKey_file failed");
        goto end;
    }

    const int was = SSL_CTX_set_session_cache_mode(cert->ce_ssl_ctx, 1);
    LSQ_DEBUG("set SSL session cache mode to 1 (was: %d)", was);

    if (lsquic_hash_insert(certs, cert->ce_sni, strlen(cert->ce_sni), cert,
                                                            &cert->ce_hash_el))
        rv = 0;
    else
        LSQ_WARN("cannot insert cert for %s into hash table", cert->ce_sni);

  end:
    free(sni);
    if (rv != 0)
    {   /* Error: free cert and its components */
        if (cert)
        {
            free(cert->ce_sni);
            free(cert);
        }
    }
    return rv;
}

struct ssl_ctx_st *
lookup_cert (void *cert_lu_ctx, const struct sockaddr *sa_UNUSED,
             const char *sni)
{
    struct lsquic_hash_elem *el;
    struct server_cert *server_cert;

    if (!cert_lu_ctx)
        return NULL;

    if (sni)
        el = lsquic_hash_find(cert_lu_ctx, sni, strlen(sni));
    else
    {
        LSQ_INFO("SNI is not set");
        el = lsquic_hash_first(cert_lu_ctx);
    }

    if (el)
    {
        server_cert = lsquic_hashelem_getdata(el);
        if (server_cert)
            return server_cert->ce_ssl_ctx;
    }

    return NULL;
}
// const char *cert_file = NULL, *key_file = NULL;
// const char *key_log_dir = NULL;

// static int
// server_load_cert (const char *cert_file, const char *key_file)
// {
//     int rv = -1;

//     s_ssl_ctx = SSL_CTX_new(TLS_method());
//     if (!s_ssl_ctx)
//     {
//         LOG("SSL_CTX_new failed");
//         goto end;
//     }
//     SSL_CTX_set_min_proto_version(s_ssl_ctx, TLS1_3_VERSION);
//     SSL_CTX_set_max_proto_version(s_ssl_ctx, TLS1_3_VERSION);
//     SSL_CTX_set_default_verify_paths(s_ssl_ctx);
//     if (1 != SSL_CTX_use_certificate_chain_file(s_ssl_ctx, cert_file))
//     {
//         LOG("SSL_CTX_use_certificate_chain_file failed");
//         goto end;
//     }
//     if (1 != SSL_CTX_use_PrivateKey_file(s_ssl_ctx, key_file,
//                                                             SSL_FILETYPE_PEM))
//     {
//         LOG("SSL_CTX_use_PrivateKey_file failed");
//         goto end;
//     }
//     rv = 0;

//   end:
//     if (rv != 0)
//     {
//         if (s_ssl_ctx)
//             SSL_CTX_free(s_ssl_ctx);
//         s_ssl_ctx = NULL;
//     }
//     return rv;
// }


// static SSL_CTX *
// my_server_get_ssl_ctx (void *peer_ctx)
// {
//     return s_ssl_ctx;
// }

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
    // lsquic_conn_push_stream(stream);
    lsquic_stream_wantread(stream, 1);
    return st_h;
}

static int parse_request(lsquic_stream_ctx_t *st_h) {
#define PATH_PREFIX "/udp/"
#define PATH_DELIMITER "/"
    char *path = st_h->req->path;
    char ip[INET_ADDRSTRLEN];
    char port_str[6];
    int port;

    if (strncmp(path, PATH_PREFIX, strlen(PATH_PREFIX)) != 0) {
        fprintf(stderr, "Error: Invalid path prefix\n");
        return -1; // Error
    }

    path += strlen(PATH_PREFIX);

    char *ip_end = strchr(path, PATH_DELIMITER);
    if (!ip_end || (ip_end - path) >= INET_ADDRSTRLEN) {
        fprintf(stderr, "Error: Invalid IP address in path\n");
        return -1;
    }
    strncpy(ip, path, ip_end - path);
    ip[ip_end - path] = '\0'; 

    path = ip_end + 1;
    char *port_end = strchr(path, PATH_DELIMITER);
    if (!port_end || (port_end - path) >= sizeof(port_str)) {
        fprintf(stderr, "Error: Invalid port in path\n");
        return -1;
    }
    strncpy(port_str, path, port_end - path);
    port_str[port_end - path] = '\0';
    port = atoi(port_str);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Error: Invalid port number\n");
        return -1;
    }

    memset(&target_sa, 0, sizeof(target_sa));
    target_sa.sin_family = AF_INET;
    target_sa.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &(target_sa.sin_addr)) != 1) {
        perror("inet_pton");
        return -1;
    }

    return 0;
}

static int process_request(lsquic_stream_ctx_t *st_h) {
    if (st_h->req->protocol == "connect-udp") {
        if (0 != send_udp_data(&target_sa, st_h->buf, st_h->sz)) {
            return 0;
        }
    }
    return -1;
}

static void server_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *st_h) {
    ssize_t nread;
    unsigned char buf[0x400];

    if (!(st_h->flags & SH_HEADERS_READ)) {
        st_h->flags |= SH_HEADERS_READ;
        st_h->req = lsquic_stream_get_hset(stream);
        if (!st_h->req)
            LOG("Internal error: cannot fetch header set from stream");
        else if (!st_h->req->method == "CONNECT")
            LOG("Method is not supported");
        else if (!st_h->req->path)
            LOG("Path is not specified");
        // else if (!(map = find_handler(st_h->req->method, st_h->req->path, matches)))
        //     ERROR_RESP(404, "No handler found for method: %s; path: %s",
                // st_h->req->method, st_h->req->path);
        else
        {
            /*TODO: Implement this*/
            if (0 != parse_request(st_h)) {
                LSQ_ERROR("failed to parse request");
            }
        }
    }
    else {
        nread = lsquic_stream_read(stream, buf, sizeof(buf));
        if (nread > 0) {
            st_h->buf = buf;
            st_h->sz += nread;
        }
        else if (nread == 0) {
            LOG("got request: `%.*s'", (int) st_h->sz, st_h->buf);
            /*TODO: send payload*/
            process_request(st_h);
            free(st_h->buf);
            lsquic_stream_shutdown(stream, 0);
        }
        else {
            LOG("error reading: %s", strerror(errno));
            lsquic_stream_close(stream);
        }
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
                prog_certs = lsquic_hash_create();
                if (0 != load_cert(prog_certs, optarg)) {
                    LOG("Connot load certificate");
                    exit(EXIT_FAILURE);
                }
            //     cert_file = optarg;
            //     break;
            // case 'k':
            //     key_file = optarg;
                break;
            // case 'G':
            //     key_log_dir = optarg;
            //     break;
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

void server_process_conns() {
    int diff;
    struct timeval timeout;
    lsquic_engine_process_conns(server_ctx.engine);
    if (lsquic_engine_earliest_adv_tick(server_ctx.engine, &diff)) {
        if (diff < 0 || (unsigned) diff < engine_api.ea_settings->es_clock_granularity) {
	    timeout.tv_sec = 0;
	    timeout.tv_usec = engine_api.ea_settings->es_clock_granularity;
	}
	else {
	    timeout.tv_sec = (unsigned) diff / 1000000;
	    timeout.tv_usec = (unsigned) diff % 1000000;
	}
	event_add(server_ctx.server_timer, &timeout);
    }
}

int read_socket(evutil_socket_t fd, short flags, void *arg) {
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

    if (s_verbose) print_packet_hex(buf, nread);
    int ecn = 0;
    // tut_proc_ancillary(&msg, &local_sas, &ecn);
    LOG("Providing packets to engine");
    lsquic_engine_packet_in(server_ctx.engine, buf, nread,
        (struct sockaddr *) &(server_ctx.local_sas),
        peer_sa, NULL, ecn);
    if (nread > 0) server_process_conns();
    LOG("read_socket enf");
}

static void server_timer_handler (int fd, short events, void *arg) {
    server_process_conns();
}

static void *
interop_server_hset_create (void *hsi_ctx, lsquic_stream_t *stream,
                            int is_push_promise)
{
    struct req *req;

    req = malloc(sizeof(struct req));
    memset(req, 0, offsetof(struct req, decode_buf));

    return req;
}


static struct lsxpack_header *
interop_server_hset_prepare_decode (void *hset_p, struct lsxpack_header *xhdr,
                                                                size_t req_space)
{
    struct req *req = hset_p;

    if (xhdr)
    {
        LSQ_WARN("we don't reallocate headers: can't give more");
        return NULL;
    }

    if (req->flags & HAVE_XHDR)
    {
        if (req->decode_off + lsxpack_header_get_dec_size(&req->xhdr)
                                                    >= sizeof(req->decode_buf))
        {
            LSQ_WARN("Not enough room in header");
            return NULL;
        }
        req->decode_off += lsxpack_header_get_dec_size(&req->xhdr);
    }
    else
        req->flags |= HAVE_XHDR;

    lsxpack_header_prepare_decode(&req->xhdr, req->decode_buf,
                req->decode_off, sizeof(req->decode_buf) - req->decode_off);
    return &req->xhdr;
}


static int
interop_server_hset_add_header (void *hset_p, struct lsxpack_header *xhdr)
{
    struct req *req = hset_p;
    const char *name, *value;
    unsigned name_len, value_len;

    if (!xhdr)
        return 0;

    name = lsxpack_header_get_name(xhdr);
    value = lsxpack_header_get_value(xhdr);
    name_len = xhdr->name_len;
    value_len = xhdr->val_len;

    if (5 == name_len && 0 == strncmp(name, ":path", 5))
    {
        if (req->path)
            return 1;
        req->path = strndup(value, value_len);
        if (!req->path)
            return -1;
        return 0;
    }

    if (7 == name_len && 0 == strncmp(name, ":method", 7))
    {
        req->method = strndup(value, value_len);
        if (!req->method)
            return -1;
        return 0;
    }



    if (10 == name_len && 0 == strncmp(name, ":authority", 10))
    {
        req->authority = strndup(value, value_len);
        if (!req->authority)
            return -1;
        return 0;
    }

    return 0;
}


static void
interop_server_hset_destroy (void *hset_p)
{
    struct req *req = hset_p;
    free(req->path);
    free(req->method);
    free(req->authority);
    free(req);
}


static const struct lsquic_hset_if header_bypass_api =
{
    .hsi_create_header_set  = interop_server_hset_create,
    .hsi_prepare_decode     = interop_server_hset_prepare_decode,
    .hsi_process_header     = interop_server_hset_add_header,
    .hsi_discard_header_set = interop_server_hset_destroy,
};

int main(int argc, char** argv) {
    int sockfd;

    log_file = stderr;
    char errbuf[0x100];

    argument_parser(argc, argv);

    // if (!(cert_file && key_file)) {
    //     LOG("Specify both cert (-c) and key (-k) files");
    //     exit(EXIT_FAILURE);
    // }
    
    // if (0 != server_load_cert(cert_file, key_file)) {
    //     LOG("Cannot load certificate");
    //     exit(EXIT_FAILURE);
    // }

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_SERVER)) {
        fprintf(stderr, "Global init failed\n");
        exit(EXIT_FAILURE);
    }

    setvbuf(log_file, NULL, _IOLBF, 0);
    lsquic_logger_init(&logger_if, log_file, LLTS_HHMMSSUS);
                                                                   
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    memset(&server_ctx, 0, sizeof(server_ctx));
    memset(&engine_api, 0, sizeof(engine_api));
    
    lsquic_engine_init_settings(&settings, LSENG_SERVER|LSENG_HTTP);
    settings.es_versions = LSQUIC_DF_VERSIONS;

    if (0 != lsquic_engine_check_settings(&settings, LSENG_SERVER|LSENG_HTTP, errbuf, sizeof(errbuf))) {
        LOG("invalid settings: %s", errbuf);
        exit(EXIT_FAILURE);
    }


    if (((server_ctx.sockfd) = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    if (0 != server_set_nonblocking((server_ctx.sockfd)))
    {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }

    int on = 1;
    if (0 != setsockopt((server_ctx.sockfd), IPPROTO_IP, IP_RECVORIGDSTADDR, &on, sizeof(on))) {
        perror("setsockopt");
	exit(EXIT_FAILURE);
    }

    struct sockaddr_in *const sa4 = (void *) &(server_ctx.local_sas);

    sa4->sin_family = AF_INET;
    sa4->sin_addr.s_addr = inet_addr("192.168.122.51");
    sa4->sin_port = htons(443);

    if (0 != bind(server_ctx.sockfd, (struct sockaddr *)&(server_ctx.local_sas), sizeof((server_ctx.local_sas))))
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "bound to port:%d, sockfd:%d\n", (int)(sa4->sin_port), server_ctx.sockfd);

    engine_api.ea_settings = &settings;
    engine_api.ea_packets_out = send_packets_out;
    engine_api.ea_packets_out_ctx = &server_ctx;
    engine_api.ea_stream_if = &my_server_callbacks;
    engine_api.ea_stream_if_ctx = &server_ctx;
    // engine_api.ea_get_ssl_ctx   = my_server_get_ssl_ctx;
    engine_api.ea_lookup_cert = lookup_cert;
    engine_api.ea_cert_lu_ctx = prog_certs;
    engine_api.ea_hsi_if = &header_bypass_api;
    engine_api.ea_hsi_ctx = NULL;
    /* TODO
     * set ea_lookup_cert
     * set ea_cert_lu_ctx 
     * set keylog_dir */

    server_ctx.server_eb = event_base_new();
    if (!server_ctx.server_eb) {
        perror("Couldn't create event base");
	exit(EXIT_FAILURE);
    }
    server_ctx.engine = lsquic_engine_new(LSENG_SERVER|LSENG_HTTP, &engine_api);
    if (!server_ctx.engine) {
        fprintf(stderr, "cannot create engine\n");
        exit(EXIT_FAILURE);
    }

   server_ctx.server_timer = event_new(server_ctx.server_eb, -1, 0, server_timer_handler, NULL);
   server_ctx.ev = event_new(server_ctx.server_eb, server_ctx.sockfd, EV_READ|EV_PERSIST, read_socket, NULL);
   if (server_ctx.ev) event_add(server_ctx.ev, NULL);

   event_base_loop(server_ctx.server_eb, 0);

    //struct event_base *base = event_base_new();
    //if (!base) {
    //    perror("Couldn't create event_base");
    //    exit(EXIT_FAILURE);
    //}

    //struct event *socket_event = event_new(
    //    base, sockfd, EV_READ | EV_PERSIST, read_socket, (void*) &server_ctx);
    //event_add(socket_event, NULL);
    
    //event_base_dispatch(base);

    if(server_ctx.engine) lsquic_engine_destroy(server_ctx.engine);
    event_base_free(server_ctx.server_eb);
    lsquic_global_cleanup();
    return 0;
}
