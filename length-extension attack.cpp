#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SM3_HASH_SIZE 32 // SM3 输出大小为 256 位，即 32 字节
#define SM3_BLOCK_SIZE 64 // SM3 块大小为 512 位，即 64 字节

// SM3 轮常数
static const uint32_t C[64] = {
    0x79CC4519, 0x7A879D8A, 0x7B7D1D7C, 0x7C15B78D,
    0x7D4A57C6, 0x7E95B1D7, 0x7F166E3B, 0x7F9F9D4D,
    0x7FEE4D9E, 0x7FFCFC78, 0x7FF5C7B9, 0x7F03DA6E,
    0x7F12FF1D, 0x7F32788E, 0x7F3A914D, 0x7F5B8EFD,
    0x7F6D8F6E, 0x7F8E8F4C, 0x7FA78F3D, 0x7FB78F2C,
    0x7FC78F1B, 0x7FD78F0A, 0x7FE78EFA, 0x7FF78EE9,
    0x7FF78ED8, 0x7FF78EC7, 0x7FF78EB6, 0x7FF78EA5,
    0x7FF78E94, 0x7FF78E83, 0x7FF78E72, 0x7FF78E61,
    0x7FF78E50, 0x7FF78E3F, 0x7FF78E2E, 0x7FF78E1D,
    0x7FF78E0C, 0x7FF78DBB, 0x7FF78DAA, 0x7FF78D99,
    0x7FF78D88, 0x7FF78D77, 0x7FF78D66, 0x7FF78D55,
    0x7FF78D44, 0x7FF78D33, 0x7FF78D22, 0x7FF78D11,
    0x7FF78D00, 0x7FF78CF0, 0x7FF78CE0, 0x7FF78CD0,
    0x7FF78CC0, 0x7FF78CB0, 0x7FF78CA0, 0x7FF78C90,
    0x7FF78C80, 0x7FF78C70, 0x7FF78C60, 0x7FF78C50
};

static uint32_t left_rotate(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

static uint32_t P0(uint32_t x) {
    return x ^ left_rotate(x, 9) ^ left_rotate(x, 17);
}

static uint32_t P1(uint32_t x) {
    return x ^ left_rotate(x, 15) ^ left_rotate(x, 23);
}

static void process_block(uint32_t* V, const uint8_t* block) {
    uint32_t W[68];
    uint32_t W1[64];

    for (int i = 0; i < 16; i++) {
        W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }

    for (int i = 16; i < 68; i++) {
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ left_rotate(W[i - 3], 15)) ^ left_rotate(W[i - 13], 7) ^ W[i - 6];
    }

    for (int i = 0; i < 64; i++) {
        W1[i] = W[i] ^ W[i + 4];
    }

    uint32_t A = V[0];
    uint32_t B = V[1];
    uint32_t C = V[2];
    uint32_t D = V[3];
    uint32_t E = V[4];
    uint32_t F = V[5];
    uint32_t G = V[6];
    uint32_t H = V[7];

    for (int j = 0; j < 64; j++) {
        uint32_t SS1 = left_rotate((left_rotate(A, 12) + E + left_rotate(C, 9) + C[j]), 7);
        uint32_t SS2 = SS1 ^ left_rotate(A, 12);
        uint32_t TT1 = (A ^ B ^ C) + D + SS2 + W1[j] + C[j];
        uint32_t TT2 = (E ^ F ^ G) + H + SS1 + W[j];

        D = C;
        C = left_rotate(B, 9);
        B = A;
        A = TT1;

        H = G;
        G = left_rotate(F, 19);
        F = E;
        E = P0(TT2);
    }

    V[0] ^= A;
    V[1] ^= B;
    V[2] ^= C;
    V[3] ^= D;
    V[4] ^= E;
    V[5] ^= F;
    V[6] ^= G;
    V[7] ^= H;
}

void sm3(const uint8_t* message, size_t message_len, uint8_t output[SM3_HASH_SIZE]) {
    uint32_t V[8] = {
        0x73801614, 0xB002417F, 0xA4506C85, 0xA4B2D8B8,
        0xB59A41C4, 0xA3A1D4B2, 0x5F4A43B7, 0x4E4B4A55
    };

    size_t total_len = message_len + 1 + 8;
    size_t padded_len = (total_len + SM3_BLOCK_SIZE - 1) & ~(SM3_BLOCK_SIZE - 1);
    uint8_t* padded_message = (uint8_t*)calloc(padded_len, sizeof(uint8_t));

    memcpy(padded_message, message, message_len);
    padded_message[message_len] = 0x80; 
    uint64_t bit_len = message_len * 8; 
    memcpy(padded_message + padded_len - 8, &bit_len, 8); 

    for (size_t i = 0; i < padded_len; i += SM3_BLOCK_SIZE) {
        process_block(V, padded_message + i);
    }

    memcpy(output, V, SM3_HASH_SIZE);

    free(padded_message);
}

void length_extension_attack(const uint8_t* original_msg, size_t original_len,
    const uint8_t* original_hash,
    const char* additional_data,
    uint8_t* new_hash) {
    size_t additional_len = strlen(additional_data);
    size_t new_len = original_len + additional_len;
    uint8_t* new_msg = (uint8_t*)malloc(new_len);
    memcpy(new_msg, original_msg, original_len);
    memcpy(new_msg + original_len, additional_data, additional_len);
    sm3(new_msg, new_len, new_hash);

    free(new_msg);
}

int main() {
    const char* original_message = "Hello, world!";
    uint8_t original_hash[SM3_HASH_SIZE];
    sm3((const uint8_t*)original_message, strlen(original_message), original_hash);
    printf("Original Message: %s\\n", original_message);
    printf("Original Hash: ");
    for (int i = 0; i < SM3_HASH_SIZE; i++) {
        printf("%02x", original_hash[i]);
    }
    printf("\\n");

    const char* additional_data = " This is additional data.";
    uint8_t new_hash[SM3_HASH_SIZE];
    length_extension_attack((const uint8_t*)original_message, strlen(original_message),
        original_hash, additional_data, new_hash);
    printf("New Hash (after attack attempt): ");
    for (int i = 0; i < SM3_HASH_SIZE; i++) {
        printf("%02x", new_hash[i]);
    }
    printf("\\n");

    return 0;
}
