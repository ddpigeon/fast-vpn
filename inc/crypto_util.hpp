#pragma once
#include <sodium.h>
#include <cstring>
#include <iostream>

// Key and nonce should be securely generated and shared
const unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES] = {}; // 32 bytes
const unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {}; // 12 bytes

class CryptoContext {
public:
    CryptoContext() {
        if (sodium_init() < 0) {
            std::cerr << "[!] libsodium init failed" << std::endl;
            std::exit(1);
        }
    }

    bool encrypt(const unsigned char* plaintext, unsigned long long plaintext_len,
                 unsigned char* ciphertext, unsigned long long& ciphertext_len,
                 unsigned char* tag) {
        unsigned long long out_len;
        if (crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &out_len,
                plaintext, plaintext_len,
                nullptr, 0, // no additional data
                nullptr, nonce, key) != 0) {
            return false;
        }
        ciphertext_len = out_len - crypto_aead_chacha20poly1305_IETF_ABYTES;
        memcpy(tag, ciphertext + ciphertext_len, crypto_aead_chacha20poly1305_IETF_ABYTES);
        return true;
    }

    bool decrypt(const unsigned char* ciphertext, unsigned long long ciphertext_len,
                 unsigned char* plaintext, unsigned long long& plaintext_len,
                 const unsigned char* tag) {
        unsigned char combined[1500];
        memcpy(combined, ciphertext, ciphertext_len);
        memcpy(combined + ciphertext_len, tag, crypto_aead_chacha20poly1305_IETF_ABYTES);

        unsigned long long out_len;
        if (crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, &out_len,
                nullptr,
                combined, ciphertext_len + crypto_aead_chacha20poly1305_IETF_ABYTES,
                nullptr, 0, // no additional data
                nonce, key) != 0) {
            return false;
        }
        plaintext_len = out_len;
        return true;
    }
};
