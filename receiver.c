#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "crypto.h"

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

void receive_and_decrypt_packet(int sock, unsigned char *key, unsigned char *iv, uint32_t expected_spi) {
    unsigned char buffer[BUFFER_SIZE];
    int len;
    unsigned char decryptedtext[BUFFER_SIZE];

    len = recv(sock, buffer, BUFFER_SIZE, 0);
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
    printf("Ciphertext: %s\n", ciphertext);
    int ciphertext_len = len - sizeof(struct esp_header);
    int decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
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
