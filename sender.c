#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/hmac.h>   // Include for HMAC

#include "crypto.h"

#define HMAC_KEY "supersecrethmackey"  // Key for HMAC, ideally securely stored
#define HMAC_KEY_LEN strlen(HMAC_KEY)
#define HMAC_SIZE 32                   // HMAC-SHA256 output is 32 bytes

// ESP Header Structure
struct esp_header {
    uint32_t spi;       // Security Parameters Index
    uint32_t seq_num;   // Sequence number
    unsigned char payload[];  // Placeholder for encrypted payload
};

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

    if (connect(sock, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Socket connection failed");
        exit(EXIT_FAILURE);
    }

    return sock;
}

void send_encrypted_packet(int sock, unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, uint32_t spi, uint32_t *seq_num) {
    unsigned char ciphertext[BUFFER_SIZE];
    int ciphertext_len = encrypt(plaintext, plaintext_len, key, iv, ciphertext);

    unsigned char esp_packet[sizeof(struct esp_header) + ciphertext_len + HMAC_SIZE];
    struct esp_header *esp_hdr = (struct esp_header *)esp_packet;

    esp_hdr->spi = htonl(spi);
    esp_hdr->seq_num = htonl(*seq_num);

    memcpy(esp_hdr->payload, ciphertext, ciphertext_len);

    // Calculate HMAC for (ESP header + encrypted payload)
    unsigned char *hmac = esp_packet + sizeof(struct esp_header) + ciphertext_len; // HMAC position
    unsigned int hmac_len;
    HMAC(EVP_sha256(), HMAC_KEY, HMAC_KEY_LEN, esp_packet, sizeof(struct esp_header) + ciphertext_len, hmac, &hmac_len);

    // Ensure HMAC is the correct length
    if (hmac_len != HMAC_SIZE) {
        fprintf(stderr, "HMAC calculation failed\n");
        exit(EXIT_FAILURE);
    }

    int packet_len = sizeof(struct esp_header) + ciphertext_len + HMAC_SIZE;
    if (send(sock, esp_packet, packet_len, 0) < 0) {
        perror("Send failed");
        exit(EXIT_FAILURE);
    }
    printf("Encrypted packet with ESP header and HMAC sent!\n");

    (*seq_num)++;
}

int main() {
    const char *ip_address = "127.0.0.1";
    int port = 12345;
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    unsigned char *iv = (unsigned char *)"0123456789012345";
    uint32_t spi = 1001;
    uint32_t seq_num = 1;

    int sock = setup_socket(ip_address, port);

    unsigned char *plaintext = (unsigned char *)"This is a test message from the IPsec-like VPN PoC!";
    int plaintext_len = strlen((char *)plaintext);

    send_encrypted_packet(sock, plaintext, plaintext_len, key, iv, spi, &seq_num);

    close(sock);
    return 0;
}
