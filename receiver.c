#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "crypto.h"

#define BUFFER_SIZE 1024

// ESP Header Structure
struct esp_header {
    uint32_t spi;       // Security Parameters Index
    uint32_t seq_num;   // Sequence number
    unsigned char payload[];  // Placeholder for encrypted payload
};

// IKE Phase 1: Handle key exchange with a pre-shared key
int ike_phase1(int sock, const char *psk, struct sockaddr_in *client_addr) {
    unsigned char buffer[BUFFER_SIZE];
    socklen_t client_len = sizeof(*client_addr);

    // Receive authentication request
    int len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)client_addr, &client_len);
    if (len < 0) {
        perror("IKE Phase 1: Receive failed");
        return -1;
    }

    buffer[len] = '\0';
    printf("IKE Phase 1: Received request: %s\n", buffer);

    // Send a response with the pre-shared key
    snprintf((char *)buffer, sizeof(buffer), "IKE Phase 1: Key exchange response with PSK: %s", psk);
    if (sendto(sock, buffer, strlen((char *)buffer), 0, (struct sockaddr*)client_addr, client_len) < 0) {
        perror("IKE Phase 1: Send failed");
        return -1;
    }
    printf("IKE Phase 1: Response sent\n");

    printf("IKE Phase 1: Key exchange complete with PSK\n");
    return 0;
}

// Set up the UDP socket for receiving packets
int setup_socket(int port) {
    int sock;
    struct sockaddr_in server_addr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Socket bind failed");
        exit(EXIT_FAILURE);
    }

    return sock;
}

// Receive and decrypt ESP packets
void receive_and_decrypt_packet(int sock, unsigned char *key, unsigned char *iv, uint32_t expected_spi) {
    unsigned char buffer[BUFFER_SIZE];
    int len;
    unsigned char decryptedtext[BUFFER_SIZE];
    struct sockaddr_in sender_addr;
    socklen_t sender_len = sizeof(sender_addr);

    len = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&sender_addr, &sender_len);
    if (len < sizeof(struct esp_header)) {
        perror("Received packet too small");
        exit(EXIT_FAILURE);
    }

    struct esp_header *esp_hdr = (struct esp_header *)buffer;
    uint32_t spi = ntohl(esp_hdr->spi);
    uint32_t seq_num = ntohl(esp_hdr->seq_num);

    if (spi != expected_spi) {
        printf("SPI mismatch: expected %u but got %u\n", expected_spi, spi);
        return;
    }
    printf("Received packet with SPI: %u, Sequence number: %u\n", spi, seq_num);

    unsigned char *ciphertext = esp_hdr->payload;
    int ciphertext_len = len - sizeof(struct esp_header);

    // Decrypt the payload
    int decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
    decryptedtext[decryptedtext_len] = '\0';

    printf("Decrypted packet: %s\n", decryptedtext);
}

int main() {
    int port = 12345;
    const char *psk = "sharedsecret";  // Pre-shared key for IKE Phase 1
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    unsigned char *iv = (unsigned char *)"0123456789012345";
    uint32_t expected_spi = 1001;

    int sock = setup_socket(port);
    struct sockaddr_in client_addr;

    // Perform IKE Phase 1 key exchange
    if (ike_phase1(sock, psk, &client_addr) != 0) {
        printf("IKE Phase 1 failed. Exiting.\n");
        close(sock);
        return -1;
    }

    // Receive and decrypt ESP packets
    receive_and_decrypt_packet(sock, key, iv, expected_spi);

    close(sock);
    return 0;
}
