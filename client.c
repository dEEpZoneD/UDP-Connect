#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
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

static FILE *log_file;

typedef struct
{
    lsquic_engine_t *cli_engine;
}cli;

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

static int cli_packets_out();

static lsquic_conn_ctx_t *my_client_on_new_conn(struct lsquic_conn *conn);
static void my_client_on_hsk_done (lsquic_conn_t *conn, enum lsquic_hsk_status status);
static void my_client_on_conn_closed (struct lsquic_conn *conn);
static lsquic_stream_ctx_t *my_client_on_new_stream (void *stream_if_ctx, struct lsquic_stream *stream);
static void my_client_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *h);
static void my_client_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *h) {
    lsquic_conn_t *conn;
    cli *cli;
    ssize_t nw;
    conn = lsquic_stream_conn(stream);cli = (void *) lsquic_conn_get_ctx(conn);

    nw = lsquic_stream_write(stream, tut->tut_u.c.buf, tut->tut_u.c.sz);
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
    engine_api.ea_packets_out = cli_packets_out;
    engine_api.ea_packets_out_ctx = NULL;
    engine_api.ea_stream_if = my_client_callbacks;
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
