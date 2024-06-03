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
    const char* optstring = "p:t:";
    while (opt = getopt(argc, argv, optstring) != -1) {
        switch(opt) {
            case 'p':
                if (inet_pton(AF_INET, optarg, &proxy_addr.addr4) != 1) {
                    fprintf(stderr, "Invalid IP address %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
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
    if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT)) {
        fprintf(stderr, "Lsquic global initialisation failed");
        exit(EXIT_FAILURE);
    }

    argument_parser(argc, argv);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    lsquic_engine_t* engine = lsquic_engine_new(LSENG_HTTP, &engine_api);

    // lsquic_conn_close(conn);
    lsquic_engine_destroy(engine);
    lsquic_global_cleanup();
    return 0;
}
