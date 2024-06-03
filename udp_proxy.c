#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
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

#define PORT 4443
#define BUF_SIZE 1024

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

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_SERVER)) {
        exit(EXIT_FAILURE);
    }

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
    
    int lsquic_engine_packet_in (lsquic_engine_t *,
        const unsigned char *udp_payload, size_t sz,
        const struct sockaddr *sa_local,
        const struct sockaddr *sa_peer,
        void *peer_ctx, int ecn);

    lsquic_engine_destroy(engine);
    lsquic_global_cleanup();
    return 0;
}