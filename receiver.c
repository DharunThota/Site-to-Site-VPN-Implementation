#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "crypto.h"

#define BUFFER_SIZE 1024
#define MAX_SEQ_NUM 1024

// ESP Header Structure
struct esp_header {
    uint32_t spi;
    uint32_t seq_num;
    unsigned char payload[];
};

int ike_phase1(int sock, const char *psk, struct sockaddr_in *client_addr) {
    unsigned char buffer[BUFFER_SIZE];
    socklen_t client_len = sizeof(*client_addr);

    int len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)client_addr, &client_len);
    if (len < 0) {
        perror("IKE Phase 1: Receive failed");
        return -1;
    }

    buffer[len] = '\0';
    printf("IKE Phase 1: Received request: %s\n", buffer);

    snprintf((char *)buffer, sizeof(buffer), "IKE Phase 1: Key exchange response with PSK: %s", psk);
    if (sendto(sock, buffer, strlen((char *)buffer), 0, (struct sockaddr*)client_addr, client_len) < 0) {
        perror("IKE Phase 1: Send failed");
        return -1;
    }
    printf("IKE Phase 1: Response sent\n");

    printf("IKE Phase 1: Key exchange complete with PSK\n");
    return 0;
}

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

int check_replay_protection(uint32_t seq_num, uint32_t *received_sequences, int *num_received) {
    for (int i = 0; i < *num_received; i++) {
        if (received_sequences[i] == seq_num) {
            return 1;  // Replay detected
        }
    }
    received_sequences[*num_received] = seq_num;
    (*num_received)++;
    return 0;
}

void receive_and_decrypt_packet(int sock, unsigned char *key, unsigned char *iv, uint32_t expected_spi) {
    unsigned char buffer[BUFFER_SIZE];
    unsigned char decryptedtext[BUFFER_SIZE];
    struct sockaddr_in sender_addr;
    socklen_t sender_len = sizeof(sender_addr);
    uint32_t received_sequences[MAX_SEQ_NUM];
    int num_received = 0;

    int len = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&sender_addr, &sender_len);
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

    if (check_replay_protection(seq_num, received_sequences, &num_received)) {
        printf("Replay attack detected for sequence number %u\n", seq_num);
        return;
    }

    unsigned char *ciphertext = esp_hdr->payload;
    int ciphertext_len = len - sizeof(struct esp_header);

    int decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
    decryptedtext[decryptedtext_len] = '\0';

    printf("Decrypted packet (SPI: %u, Seq Num: %u): %s\n", spi, seq_num, decryptedtext);
}

int receive_termination_signal(int sock) {
    unsigned char buffer[BUFFER_SIZE];
    struct sockaddr_in sender_addr;
    socklen_t sender_len = sizeof(sender_addr);

    int len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sender_addr, &sender_len);
    if (len < 0) {
        perror("Error receiving termination signal");
        return 1;
    }

    buffer[len] = '\0';
    if (strcmp((char *)buffer, "Termination Signal: Closing VPN session.") == 0) {
        printf("Termination signal received. Closing connection...\n");
        return 1;
    }
    return 0;
}

int main() {
    int port = 12345;
    const char *psk = "sharedsecret";
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    unsigned char *iv = (unsigned char *)"0123456789012345";
    uint32_t expected_spi = 1001;

    int sock = setup_socket(port);
    struct sockaddr_in client_addr;

    if (ike_phase1(sock, psk, &client_addr) != 0) {
        printf("IKE Phase 1 failed. Exiting.\n");
        close(sock);
        return -1;
    }

    while (1) {
        receive_and_decrypt_packet(sock, key, iv, expected_spi);

        if(receive_termination_signal(sock)) break;
    }

    close(sock);
    return 0;
}
