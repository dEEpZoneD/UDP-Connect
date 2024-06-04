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

static FILE *s_log_fh;

static int
my_log_buf (void *ctx, const char *buf, size_t len)
{
    FILE *out = ctx;
    fwrite(buf, 1, len, out);
    fflush(out);
    return 0;
}
static const struct lsquic_logger_if logger_if = { my_log_buf, };


static int s_verbose;
static void
LOG (const char *fmt, ...)
{
    if (s_verbose)
    {
        va_list ap;
        fprintf(s_log_fh, "LOG: ");
        va_start(ap, fmt);
        (void) vfprintf(s_log_fh, fmt, ap);
        va_end(ap);
        fprintf(s_log_fh, "\n");
    }
}

// static lsquic_conn_ctx_t *my_client_on_new_conn(struct lsquic_conn *conn) {}
// static void my_client_on_hsk_done (lsquic_conn_t *conn, enum lsquic_hsk_status status) {}
// static void my_client_on_conn_closed (struct lsquic_conn *conn) {}
// static lsquic_stream_ctx_t *my_client_on_new_stream (void *stream_if_ctx, struct lsquic_stream *stream) {}
// static void my_client_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *h) {}
// static void my_client_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *h) {}
// static void my_client_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *h) {}

// static struct lsquic_streamy_m_if my_client_callbacks =
// {
//     .on_new_conn        = my_client_on_new_conn,
//     .on_hsk_done        = my_client_on_hsk_done,
//     .on_conn_closed     = my_client_on_conn_closed,
//     .on_new_stream      = my_client_on_new_stream,
//     .on_read            = my_client_on_read,
//     .on_write           = my_client_on_write,
//     .on_close           = my_client_on_close,
// };

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
    while ((opt = getopt(argc, argv, "f:p:t:")) != -1) {
        switch(opt) {
            case 'f':
                s_log_fh = fopen(optarg, "ab");
                if (!s_log_fh)
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
    s_log_fh = stderr;
    if (0 != lsquic_global_init(LSQUIC_GLOBAL_SERVER|LSQUIC_GLOBAL_CLIENT)) {
        fprintf(stderr, "Lsquic global initialisation failed");
        exit(EXIT_FAILURE);
    }

    argument_parser(argc, argv);

    setvbuf(s_log_fh, NULL, _IOLBF, 0);
    lsquic_logger_init(&logger_if, s_log_fh, LLTS_HHMMSSUS);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    lsquic_engine_t* engine = lsquic_engine_new(LSENG_SERVER|LSENG_HTTP, &engine_api);
    if (!engine) {
        fprintf(stderr, "cannot create engine\n");
        exit(EXIT_FAILURE);
    }
    // lsquic_conn_close(conn);
    // lsquic_engine_destroy(engine);
    lsquic_global_cleanup();
    return 0;
}
