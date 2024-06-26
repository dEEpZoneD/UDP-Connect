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
#include <sys/stat.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "lsquic.h"
#include "lsxpack_header.h"
#include "../src/liblsquic/lsquic_logger.h"
#include "../src/liblsquic/lsquic_int_types.h"
#include "../src/liblsquic/lsquic_util.h"

#define HTTP_PORT 443
#define TARGET_PORT 8888

#define MAX(a, b) ((a) > (b) ? (a) : (b))

static FILE *log_file;
int s_discard_response = 0;

struct lsquic_http_headers headers;

struct proxy_client_ctx
{
    const lsquic_engine_t *engine;
    // char payload_sizep[20];
    int sockfd;
    struct sockaddr_in local_sa;
    struct sockaddr_storage local_sas;
    struct lsquic_conn *conn;
    size_t              sz;         /* Size of bytes read is stored here */
    char                buf[0x100]; /* Read up to this many bytes */
    const char *hostname;
    const char *method;
    const char *path;
    const char *protocol;
    const char *scheme;
    const char *authority;
    const char *payload;
    char payload_size[20];
    struct event_base *client_eb;
    struct event *client_timer;
    struct event *ev;

    const char *qif_file;
    FILE *qif_fh;
};

struct proxy_client_ctx client_ctx;
lsquic_engine_t *engine;
struct lsquic_engine_api engine_api;
struct lsquic_engine_settings settings;

struct lsquic_conn_ctx {
    lsquic_conn_t *conn;
    struct proxy_client_ctx *client_ctx;
};


struct hset
{
    size_t                      nalloc;
    struct lsxpack_header       xhdr;
};

static int s_display_cert_chain;

static void
hset_dump (const struct hset *hset, FILE *out) {
    const struct hset *el;

    
    if (el->xhdr.flags & (LSXPACK_HPACK_VAL_MATCHED|LSXPACK_QPACK_IDX))
        fprintf(out, "%.*s (%s static table idx %u): %.*s\n",
            (int) el->xhdr.name_len, lsxpack_header_get_name(&el->xhdr),
            el->xhdr.flags & LSXPACK_HPACK_VAL_MATCHED ? "hpack" : "qpack",
            el->xhdr.flags & LSXPACK_HPACK_VAL_MATCHED ? el->xhdr.hpack_index
                                                : el->xhdr.qpack_index,
            (int) el->xhdr.val_len, lsxpack_header_get_value(&el->xhdr));
    else
        fprintf(out, "%.*s: %.*s\n",
            (int) el->xhdr.name_len, lsxpack_header_get_name(&el->xhdr),
            (int) el->xhdr.val_len, lsxpack_header_get_value(&el->xhdr));

    fprintf(out, "\n");
    fflush(out);
}

static void *
hset_create (void *hsi_ctx, lsquic_stream_t *stream, int is_push_promise)
{
    struct hset *hset;

    if (s_discard_response)
        return (void *) 1;
    else if ((hset = malloc(sizeof(*hset))))
    {
        return hset;
    }
    else
        return NULL;
}

static struct lsxpack_header *
hset_prepare_decode (void *hset_p, struct lsxpack_header *xhdr,
                                                        size_t req_space)
{
    struct hset *const hset = hset_p;
    struct hset *el;
    char *buf;

    if (0 == req_space)
        req_space = 0x100;

    if (req_space > LSXPACK_MAX_STRLEN)
    {
        LSQ_WARN("requested space for header is too large: %zd bytes",
                                                                    req_space);
        return NULL;
    }

    if (!xhdr)
    {
        buf = malloc(req_space);
        if (!buf)
        {
            LSQ_WARN("cannot allocate buf of %zd bytes", req_space);
            return NULL;
        }
        el = malloc(sizeof(*el));
        if (!el)
        {
            LSQ_WARN("cannot allocate hset");
            free(buf);
            return NULL;
        }
        memcpy(el, hset, sizeof(*el));
        lsxpack_header_prepare_decode(&el->xhdr, buf, 0, req_space);
        el->nalloc = req_space;
    }
    else
    {
        el = (struct hset *) ((char *) xhdr
                                        - offsetof(struct hset, xhdr));
        if (req_space <= el->nalloc)
        {
            LSQ_ERROR("requested space is smaller than already allocated");
            return NULL;
        }
        if (req_space < el->nalloc * 2)
            req_space = el->nalloc * 2;
        buf = realloc(el->xhdr.buf, req_space);
        if (!buf)
        {
            LSQ_WARN("cannot reallocate hset buf");
            return NULL;
        }
        el->xhdr.buf = buf;
        el->xhdr.val_len = req_space;
        el->nalloc = req_space;
    }

    return &el->xhdr;
}


static int
hset_add_header (void *hset_p, struct lsxpack_header *xhdr)
{
    unsigned name_len, value_len;
    /* Not much to do: the header value are in xhdr */

    if (xhdr)
    {
        name_len = xhdr->name_len;
        value_len = xhdr->val_len;   /* ": \r\n" */
    }


    return 0;
}

static void
hset_destroy (void *hset_p) {
    struct hset *el = hset_p;

    if (!s_discard_response)
    {
            
        free(el->xhdr.buf);
        free(el);
    }
}

static const struct lsquic_hset_if header_bypass_api =
{
    .hsi_create_header_set  = hset_create,
    .hsi_prepare_decode     = hset_prepare_decode,
    .hsi_process_header     = hset_add_header,
    .hsi_discard_header_set = hset_destroy,
};

static void
display_cert_chain (lsquic_conn_t *conn) {
    STACK_OF(X509) *chain;
    X509_NAME *name;
    X509 *cert;
    unsigned i;
    char buf[100];

    chain = lsquic_conn_get_server_cert_chain(conn);
    if (!chain)
    {
        LSQ_WARN("could not get server certificate chain");
        return;
    }

    for (i = 0; i < sk_X509_num(chain); ++i)
    {
        cert = sk_X509_value(chain, i);
        name = X509_get_subject_name(cert);
        LSQ_INFO("cert #%u: name: %s", i,
                            X509_NAME_oneline(name, buf, sizeof(buf)));
        X509_free(cert);
    }

    sk_X509_free(chain);
}

struct reader_ctx
{
    size_t  file_size;
    size_t  nread;
    int     fd;
};


size_t
test_reader_size (void *void_ctx)
{
    struct reader_ctx *const ctx = void_ctx;
    return ctx->file_size - ctx->nread;
}


size_t
test_reader_read (void *void_ctx, void *buf, size_t count)
{
    struct reader_ctx *const ctx = void_ctx;
    ssize_t nread;

    if (count > test_reader_size(ctx))
        count = test_reader_size(ctx);

    nread = read(ctx->fd, buf, count);

    if (nread >= 0)
    {
        ctx->nread += nread;
        return nread;
    }
    else
    {
        LSQ_WARN("%s: error reading from file: %s", __func__, strerror(errno));
        ctx->nread = ctx->file_size = 0;
        return 0;
    }
}


struct reader_ctx *
create_lsquic_reader_ctx (const char *filename)
{
    int fd;
    struct stat st;


    fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        LSQ_ERROR("cannot open %s for reading: %s", filename, strerror(errno));
        return NULL;
    }

    if (0 != fstat(fd, &st))
    {
        LSQ_ERROR("cannot fstat(%s) failed: %s", filename, strerror(errno));
        (void) close(fd);
        return NULL;
    }
    struct reader_ctx *ctx = malloc(sizeof(*ctx));
    ctx->file_size = st.st_size;
    ctx->nread = 0;
    ctx->fd = fd;
    return ctx;
}

struct lsquic_stream_ctx {
    lsquic_stream_t     *stream;
    struct proxy_client_ctx   *client_ctx;
    const char *path;
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
    lsquic_time_t        sh_created;
    lsquic_time_t        sh_ttfb;
    unsigned             count;
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

void client_process_conns() {
    int diff;
    struct timeval timeout;
    lsquic_engine_process_conns(engine);
    if (lsquic_engine_earliest_adv_tick(engine, &diff)) {
        if (diff < 0 || (unsigned) diff < engine_api.ea_settings->es_clock_granularity) {
	    timeout.tv_sec = 0;
	    timeout.tv_usec = engine_api.ea_settings->es_clock_granularity;
	}
	else {
	    timeout.tv_sec = (unsigned) diff / 1000000;
	    timeout.tv_usec = (unsigned) diff % 1000000;
	}
	event_add(client_ctx.client_timer, &timeout);
    }
}

static void client_timer_handler (int fd, short events, void *arg) {
    client_process_conns();
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
    nread = recvmsg(fd, &msg, 0);
    if (0 > nread) {
        if (!(EAGAIN == errno || EWOULDBLOCK == errno || ECONNRESET == errno)){
            LOG("recvmsg: %s", strerror(errno));
            return;
        }
    }
    if (nread > 0) {
        if (s_verbose) print_packet_hex(buf, nread);
        LOG("Providing packets to engine");
        (void) lsquic_engine_packet_in(engine, buf, nread,
            (struct sockaddr *) &(client_ctx.local_sa),
            peer_sa, (void*) &fd, 0);
        client_process_conns();
    }
}

static int client_packets_out(void *packets_out_ctx, const struct lsquic_out_spec *specs, unsigned count) {
    struct proxy_client_ctx *packets_out = packets_out_ctx;
    unsigned n;
    int fd, s = 0;
    struct msghdr msg;

    if (0 == count) 
        return 0;
    fd = client_ctx.sockfd;
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
    struct proxy_client_ctx *stream_if = stream_if_ctx;
    LOG("NEW CONN");
    lsquic_conn_ctx_t *conn_h = calloc(1, sizeof(*conn_h));
    conn_h->conn = conn;
    conn_h->client_ctx = stream_if_ctx;
    lsquic_conn_make_stream(conn);
    return conn_h;
}

static void my_client_on_conn_closed (struct lsquic_conn *conn) {
    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    free(conn_h);
    LOG("Connection closed");
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
    st_h->sh_created = lsquic_time_now();
    st_h->path = st_h->client_ctx->path;
    if (st_h->client_ctx->payload)
    {
        st_h->reader.lsqr_read = test_reader_read;
        st_h->reader.lsqr_size = test_reader_size;
        st_h->reader.lsqr_ctx = create_lsquic_reader_ctx(st_h->client_ctx->payload);
        if (!st_h->reader.lsqr_ctx)
            exit(1);
    }
    else
        st_h->reader.lsqr_ctx = NULL;
    LOG("created new stream, we want to write");
    lsquic_stream_wantwrite(stream, 1);
    return st_h;
}

static size_t
discard (void *ctx, const unsigned char *buf, size_t sz, int fin)
{
    return sz;
}

static void my_client_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *st_h) {
    struct http_client_ctx *const read_ctx = st_h->client_ctx;
    struct hset *hset;
    ssize_t nread;
    unsigned nreads = 0;
    unsigned char buf[0x1000];

    do
    {
        if (!(st_h->sh_flags & PROCESSED_HEADERS)) {
            hset = lsquic_stream_get_hset(stream);
            if (!hset)
            {
                LSQ_ERROR("could not get header set from stream");
                exit(2);
            }
            if (s_discard_response)
                LSQ_DEBUG("discard response: do not dump headers");
            else
                hset_dump(hset, stdout);
            hset_destroy(hset);
            st_h->sh_flags |= PROCESSED_HEADERS;
        }
        else if (nread = (s_discard_response
                            ? lsquic_stream_readf(stream, discard, NULL)
                            : lsquic_stream_read(stream, buf, sizeof(buf))),
                    nread > 0)
        {
            fwrite(buf, 1, nread, stdout);
            fflush(stdout);
            if (!(st_h->sh_flags & PROCESSED_HEADERS))
            {
                /* First read is assumed to be the first byte */
                st_h->sh_ttfb = lsquic_time_now();
                update_sample_stats(&s_stat_ttfb,
                                    st_h->sh_ttfb - st_h->sh_created);
                st_h->sh_flags |= PROCESSED_HEADERS;
            }
            if (!s_discard_response)
                fwrite(buf, 1, nread, stdout);
        }
        else if (0 == nread) {
            lsquic_stream_shutdown(stream, 0);
            break;
        }
        else
        {
            LSQ_ERROR("could not read: %s", strerror(errno));
            exit(2);
        }
    } while (settings.es_rw_once
            && nreads++ < 3);
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

static void my_client_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *st_h) {
    ssize_t nw;

    if (st_h->sh_flags & HEADERS_SENT) {
        if (st_h->client_ctx->payload && test_reader_size(st_h->reader.lsqr_ctx) > 0) {    
	    nw = lsquic_stream_writef(stream, &st_h->reader);
            if (nw < 0)
            {
                LSQ_ERROR("write error: %s", strerror(errno));
                exit(1);
            }
            if (test_reader_size(st_h->reader.lsqr_ctx) > 0)
            {
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
    else {
        struct header_buf hbuf;
        struct lsxpack_header harray[5];

        hbuf.off = 0;
#define V(v) (v), strlen(v)
        client_set_header(&harray[0], &hbuf, V(":method"), V(client_ctx.method));
        client_set_header(&harray[1], &hbuf, V(":protocol"), V(client_ctx.protocol));
        client_set_header(&harray[2], &hbuf, V(":scheme"), V(client_ctx.scheme));
        client_set_header(&harray[3], &hbuf, V(":path"), V(client_ctx.path));
        client_set_header(&harray[4], &hbuf, V(":authority"),
                                                V(client_ctx.authority));
        client_set_header(&harray[5], &hbuf, V("user-agent"), V("h3cli/lsquic"));
        client_set_header(&harray[6], &hbuf, V("content-type"), V("application/octet-stream"));
        client_set_header(&harray[7], &hbuf, V("content-length"), V(st_h->client_ctx->payload_size));

        lsquic_http_headers_t headers = {
            .count = sizeof(harray) / sizeof(harray[0]),
            .headers = harray,
        };
        if (!st_h->client_ctx->payload)
            headers.count -= 2;
        if (0 != lsquic_stream_send_headers(st_h->stream, &headers,
                                        st_h->client_ctx->payload == NULL))
        {
            LSQ_ERROR("cannot send headers: %s", strerror(errno));
            exit(1);
        }
        st_h->sh_flags |= HEADERS_SENT;
    }
}

static void my_client_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *st_h) {
    if (st_h->reader.lsqr_ctx)
        destroy_lsquic_reader_ctx(st_h->reader.lsqr_ctx);
    free(st_h);
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

struct sockaddr_in proxy_sa;
struct sockaddr_in target_sa;

static void
cli_usage () {
    fprintf(stdout,
"Usage:./client [options]\n"
"\n"
"   -p path         Set path (eg. /udp/192.168.255.255/443)\n"
"   -f log_file     Set external file for logs\n"
"   -l level        Set library-wide log level.  Defaults to 'warning'.\n"
"                   Acceptable values are debug, info, notice, warning, error, alert, emerg, crit\n"
"   -v              Verbose: log program messages as well.\n"
"   -P file         Payload file\n"
"   -h              Print this help screen and exit.\n");
}

void argument_parser(int argc, char** argv) {
    int opt;
    while ((opt = getopt(argc, argv, "c:k:l:f:p:t:m:P:hv")) != -1) {
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
                client_ctx.path = optarg;
                break;
	    case 'P':
		client_ctx.payload = optarg;
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
    socklen_t socklen;
    const char *token = NULL;

    log_file = stderr;
    char errbuf[0x100];

    memset(&client_ctx, 0, sizeof(client_ctx));
    memset(&engine_api, 0, sizeof(engine_api));

    memset(&target_sa, 0, sizeof(target_sa));
    memset(&proxy_sa, 0, sizeof(proxy_sa));
    proxy_sa.sin_family = AF_INET;
    proxy_sa.sin_addr.s_addr = inet_addr("192.168.200.194");  /*www.proxy.com*/
    proxy_sa.sin_port = 51813;
    client_ctx.local_sa.sin_family = AF_INET;
    client_ctx.local_sa.sin_addr.s_addr = inet_addr("192.168.201.194");
    client_ctx.local_sa.sin_port = 51813;

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

    client_ctx.method = "CONNECT";
    client_ctx.protocol = "connect-udp";
    client_ctx.scheme = "https";
    client_ctx.authority = "example.org";

    // if ((cert_file && key_file)) {
    //     if (0 != client_load_cert(cert_file, key_file)) {
    //         LOG("Cannot load certificate");
    //         exit(EXIT_FAILURE);
    //     }
    // }
    // else LOG("Certificate and key files not specified");

    lsquic_engine_init_settings(&settings, LSENG_HTTP);
    // settings.es_ql_bits = 0;
    settings.es_ua = "lsquic" "/" "2" "." "18" "." "1";

    setvbuf(log_file, NULL, _IOLBF, 0);
    lsquic_logger_init(&logger_if, log_file, LLTS_HHMMSSUS);
    // lsquic_set_log_level("warnung");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    

    memset(&engine_api, 0, sizeof(engine_api));
    engine_api.ea_packets_out = client_packets_out;
    engine_api.ea_packets_out_ctx = (void *) &client_ctx;
    engine_api.ea_stream_if = &my_client_callbacks;
    engine_api.ea_stream_if_ctx = &client_ctx;
    engine_api.ea_hsi_if = &header_bypass_api;
    engine_api.ea_hsi_ctx = NULL;
    // engine_api.ea_get_ssl_ctx = my_client_get_ssl_ctx;
    engine_api.ea_settings = &settings;
    // engine_api.ea_hsi_if = 1;

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT)) {
        fprintf(stderr, "lsquic global initialisation failed");
        exit(EXIT_FAILURE);
    }

    if (!client_ctx.path) {
        fprintf(stderr, "specify atleast one path using the -p option\n");
        exit(EXIT_FAILURE);
    }

    if (0 != lsquic_engine_check_settings(&settings, 0, errbuf, sizeof(errbuf))) {
        LOG("invalid settings: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    client_ctx.client_eb = event_base_new();

    LOG("Creating a new engine");
    engine = lsquic_engine_new(LSENG_HTTP, &engine_api);
    client_ctx.engine = engine;
    if (!client_ctx.engine) {
        LOG("cannot create engine\n");
        exit(EXIT_FAILURE);
    }
    printf("engine: %p", client_ctx.engine);
    
    struct lsquic_conn_ctx conn_ctx;

    client_ctx.client_timer = event_new(client_ctx.client_eb, -1, 0, client_timer_handler, NULL);

   if (0 != connect(fd,(struct sockaddr *) &proxy_sa, sizeof(proxy_sa))) {
        close(fd);
        perror("connect");
        exit(EXIT_FAILURE);
    }

    client_ctx.ev = event_new(client_ctx.client_eb, client_ctx.sockfd, EV_READ|EV_PERSIST, read_socket, NULL);
   if (client_ctx.ev) event_add(client_ctx.ev, NULL);
    
    /*lsquic_conn_t *lsquic_engine_connect(lsquic_engine_t *engine, enum lsquic_
        version version, const struct sockaddr *local_sa, const struct sockaddr *peer_sa, 
        void *peer_ctx, lsquic_conn_ctx_t *conn_ctx, const char *sni, unsigned short base_plpmtu, 
        const unsigned char *sess_resume, size_t sess_resume_len, const unsigned char *token, 
        size_t token_sz) */
    LOG("Connecting to peer");
    lsquic_conn_t *conn = lsquic_engine_connect(client_ctx.engine, N_LSQVER, &(client_ctx.local_sa), &proxy_sa, NULL,
                                    &conn_ctx, NULL, 0, NULL, 0, NULL, 0);
    conn_ctx.conn = conn;
    conn_ctx.client_ctx = &client_ctx;
    if (!conn_ctx.conn)
    {
        LOG("cannot create connection");
        exit(EXIT_FAILURE);
    }
    lsquic_engine_process_conns(engine);
    
    event_base_loop(client_ctx.client_eb, 0);
    
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
