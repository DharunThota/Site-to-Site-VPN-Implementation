#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/hmac.h>    // For HMAC

#include "crypto.h"

#define HMAC_KEY "supersecrethmackey"  // Key for HMAC, should be securely stored
#define HMAC_KEY_LEN strlen(HMAC_KEY)
#define HMAC_SIZE 32                   // HMAC-SHA256 output is 32 bytes

// ESP Header Structure
struct esp_header {
    uint32_t spi;       // Security Parameters Index
    uint32_t seq_num;   // Sequence number
    unsigned char payload[];  // Placeholder for encrypted payload
};

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

int verify_hmac(unsigned char *packet, int packet_len, unsigned char *expected_hmac) {
    unsigned char calculated_hmac[HMAC_SIZE];
    unsigned int hmac_len;

    HMAC(EVP_sha256(), HMAC_KEY, HMAC_KEY_LEN, packet, packet_len, calculated_hmac, &hmac_len);

    if (hmac_len != HMAC_SIZE || memcmp(calculated_hmac, expected_hmac, HMAC_SIZE) != 0) {
        return 0;  // HMAC does not match
    }
    return 1;  // HMAC matches
}

void receive_and_decrypt_packet(int sock, unsigned char *key, unsigned char *iv, uint32_t expected_spi) {
    unsigned char buffer[BUFFER_SIZE];
    int len;
    unsigned char decryptedtext[BUFFER_SIZE];

    len = recv(sock, buffer, BUFFER_SIZE, 0);
    if (len < sizeof(struct esp_header) + HMAC_SIZE) {
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

    int payload_len = len - sizeof(struct esp_header) - HMAC_SIZE;
    unsigned char *ciphertext = esp_hdr->payload;
    unsigned char *received_hmac = buffer + len - HMAC_SIZE;

    if (!verify_hmac(buffer, sizeof(struct esp_header) + payload_len, received_hmac)) {
        fprintf(stderr, "HMAC verification failed! Packet discarded.\n");
        return;
    }
    printf("HMAC verified successfully.\n");

    int decryptedtext_len = decrypt(ciphertext, payload_len, key, iv, decryptedtext);
    decryptedtext[decryptedtext_len] = '\0';

    printf("Decrypted packet: %s\n", decryptedtext);
}

int main() {
    int port = 12345;
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    unsigned char *iv = (unsigned char *)"0123456789012345";
    uint32_t expected_spi = 1001;

    int sock = setup_socket(port);
    receive_and_decrypt_packet(sock, key, iv, expected_spi);

    close(sock);
    return 0;
}
