#include "tun_util.hpp"
#include "crypto_util.hpp"
#include <thread>

int main() {
    int tun_fd = tun_alloc("tun1", IFF_TUN | IFF_NO_PI);
    if (tun_fd < 0) return 1;

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(5555);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    CryptoContext crypto;
    char buffer[1600];
    unsigned char ciphertext[1600];
    unsigned char tag[crypto_aead_chacha20poly1305_IETF_ABYTES];

    while (true) {
        int nread = read(tun_fd, buffer, sizeof(buffer));
        std::cout << "[client] Read " << nread << " bytes from tun1\n";
        unsigned long long cipher_len = 0;

        if (!crypto.encrypt((unsigned char*)buffer, nread, ciphertext, cipher_len, tag)) {
            std::cerr << "[client] Encryption failed\n";
            continue;
        }
        unsigned char packet[1600];
        memcpy(packet, ciphertext, cipher_len);
        memcpy(packet + cipher_len, tag, crypto_aead_chacha20poly1305_IETF_ABYTES);
        int total_len = cipher_len + crypto_aead_chacha20poly1305_IETF_ABYTES;

        sendto(sockfd, packet, total_len, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
        std::cout << "[client] Sent " << total_len << " encrypted bytes to server\n";
    }
    return 0;
}
