#include "../inc/tun_util.hpp"
#include "../inc/crypto_util.hpp"
#include <thread>

int main() {
    int tun_fd = tun_alloc("tun0", IFF_TUN | IFF_NO_PI);
    if (tun_fd < 0) return 1;

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in server_addr{}, client_addr{};
    socklen_t client_len = sizeof(client_addr);

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(5555);

    bind(sockfd, (sockaddr*)&server_addr, sizeof(server_addr));
    unsigned char recv_buf[1600];
    CryptoContext crypto;

    while (true) {
        int recv_len = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (sockaddr*)&client_addr, &client_len);
        std::cout << "[server] Received " << recv_len << " bytes from client\n";

        if (recv_len >= crypto_aead_chacha20poly1305_IETF_ABYTES) {
            unsigned char* ciphertext = recv_buf;
            int ciphertext_len = recv_len - crypto_aead_chacha20poly1305_IETF_ABYTES;
            unsigned char* tag = recv_buf + ciphertext_len;

            unsigned char plaintext[1600];
            unsigned long long plaintext_len;

            if (!crypto.decrypt(ciphertext, ciphertext_len, plaintext, plaintext_len, tag)) {
                std::cerr << "[server] decryption failed\n";
                continue;
            }

            int nwrite = write(tun_fd, plaintext, plaintext_len);
            std::cout << "[server] Wrote " << plaintext_len << " bytes to tun0\n";
        }
        else {
            std::cerr << "[server] decryption failed\n";
        }
    }
    return 0;
}
