#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

// Function to send data to a specified target using UDP
int send_udp_data(const char *target_host_ip, const char *data_buf, size_t buf_len, uint16_t target_port) {
    int sockfd;
    struct sockaddr_in target_addr;

    // Create a UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        return -1;
    }

    // Initialize the target address structure
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(target_port);

    // Convert the target IP address from text to binary form
    if (inet_pton(AF_INET, target_host_ip, &target_addr.sin_addr) <= 0) {
        perror("inet_pton failed");
        close(sockfd);
        return -1;
    }

    // Send the data to the target
    ssize_t sent_len = sendto(sockfd, data_buf, buf_len, 0, (const struct sockaddr *)&target_addr, sizeof(target_addr));
    if (sent_len < 0) {
        perror("sendto failed");
        close(sockfd);
        return -1;
    }

    printf("Sent %zd bytes to %s:%d\n", sent_len, target_host_ip, target_port);

    // Close the socket
    close(sockfd);
    return 0;
}


int main() {
    const char *target_host_ip = "192.168.122.252";
    const char *data_buf = "Hello, UDP!";
    size_t buf_len = strlen(data_buf);
    uint16_t target_port = 8888;

    if (send_udp_data(target_host_ip, data_buf, buf_len, target_port) < 0) {
        fprintf(stderr, "Failed to send UDP data\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
