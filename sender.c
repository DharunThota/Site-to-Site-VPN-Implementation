#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "crypto.h"

// ESP Header Structure
struct esp_header {
    uint32_t spi;       // Security Parameters Index
    uint32_t seq_num;   // Sequence number
    unsigned char payload[];  // Placeholder for encrypted payload
};

// Simple IKE Phase 1 key exchange (using pre-shared key)
int ike_phase1(int sock, const char *psk, const char *ip_address, int port) {
    unsigned char buffer[BUFFER_SIZE];
    struct sockaddr_in dest_addr;

    // Set destination address (receiver's address)
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip_address, &dest_addr.sin_addr);

    // Send authentication request (simulating with a pre-shared key)
    snprintf((char *)buffer, sizeof(buffer), "IKE Phase 1: Initiate key exchange with PSK: %s", psk);
    if (sendto(sock, buffer, strlen((char *)buffer), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("IKE Phase 1: Send failed");
        return -1;
    }
    printf("IKE Phase 1: Key exchange initiated with PSK\n");

    // Simulate receiving a response
    int len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
    if (len < 0) {
        perror("IKE Phase 1: Receive failed");
        return -1;
    }

    buffer[len] = '\0';
    printf("IKE Phase 1: Response received: %s\n", buffer);

    // Simulate key exchange success
    printf("IKE Phase 1: Key exchange complete with PSK\n");
    return 0;
}

int setup_socket(const char *ip_address, int port) {
    int sock;
    struct sockaddr_in dest_addr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip_address, &dest_addr.sin_addr);

    return sock;
}

void send_encrypted_packet(int sock, unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, uint32_t spi, uint32_t *seq_num, const char *ip_address, int port) {
    unsigned char ciphertext[BUFFER_SIZE];
    int ciphertext_len = encrypt(plaintext, plaintext_len, key, iv, ciphertext);

    unsigned char esp_packet[sizeof(struct esp_header) + ciphertext_len];
    struct esp_header *esp_hdr = (struct esp_header *)esp_packet;

    esp_hdr->spi = htonl(spi);
    esp_hdr->seq_num = htonl(*seq_num);

    memcpy(esp_hdr->payload, ciphertext, ciphertext_len);

    int packet_len = sizeof(struct esp_header) + ciphertext_len;

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip_address, &dest_addr.sin_addr);

    if (sendto(sock, esp_packet, packet_len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Send failed");
        exit(EXIT_FAILURE);
    }
    printf("Encrypted packet with ESP header sent!\n");

    (*seq_num)++;
}

int main() {
    const char *ip_address = "127.0.0.1";
    int port = 12345;
    const char *psk = "sharedsecret";  // Pre-shared key for IKE Phase 1
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    unsigned char *iv = (unsigned char *)"0123456789012345";
    uint32_t spi = 1001;
    uint32_t seq_num = 1;

    int sock = setup_socket(ip_address, port);

    // Perform IKE Phase 1 key exchange
    if (ike_phase1(sock, psk, ip_address, port) != 0) {
        printf("IKE Phase 1 failed. Exiting.\n");
        close(sock);
        return -1;
    }

    unsigned char *plaintext = (unsigned char *)"This is a test message from the IPsec-like VPN PoC!";
    int plaintext_len = strlen((char *)plaintext);

    send_encrypted_packet(sock, plaintext, plaintext_len, key, iv, spi, &seq_num, ip_address, port);

    close(sock);
    return 0;
}
