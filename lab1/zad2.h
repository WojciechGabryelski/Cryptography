#include <iostream>
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls/md5.h"

bool hashesEqual1(unsigned char* m0_1, unsigned char* m1_1, unsigned char* m0_2, unsigned char* m1_2) {
    mbedtls_md5_context ctx_1;
    mbedtls_md5_starts(&ctx_1);
    mbedtls_internal_md5_process(&ctx_1, m0_1);
    mbedtls_internal_md5_process(&ctx_1, m1_1);
    std::cout << std::hex << ctx_1.state[0] << " " << ctx_1.state[1] << " " << ctx_1.state[2] << " " << ctx_1.state[3] << "\n";
    mbedtls_md5_context ctx_2;
    mbedtls_md5_starts(&ctx_2);
    mbedtls_internal_md5_process(&ctx_2, m0_2);
    mbedtls_internal_md5_process(&ctx_2, m1_2);
    std::cout << std::hex << ctx_2.state[0] << " " << ctx_2.state[1] << " " << ctx_2.state[2] << " " << ctx_2.state[3] << "\n";
    return ctx_1.state[0] == ctx_2.state[0] && ctx_1.state[1] == ctx_2.state[1] && ctx_1.state[2] == ctx_2.state[2] && ctx_1.state[3] == ctx_2.state[3];
}

bool hashesEqual2(unsigned char* m0_1, unsigned char* m1_1, unsigned char* m0_2, unsigned char* m1_2) {
    unsigned char m1[128];
    unsigned char m2[128];
    for (int i = 0; i < 64; ++i) {
        m1[i] = m0_1[i];
        m1[64 + i] = m1_1[i];
        m2[i] = m0_2[i];
        m2[64 + i] = m1_2[i];
    }
    unsigned char output1[16];
    unsigned char output2[16];
    mbedtls_md5(m1, 128, output1);
    mbedtls_md5(m2, 128, output2);
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << (int) output1[i];
        if (i % 4 == 3) {
            std::cout << " ";
        }
    }
    std::cout << "\n";
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << (int) output2[i];
        if (i % 4 == 3) {
            std::cout << " ";
        }
    }
    std::cout << "\n";
    for (int i = 0; i < 16; ++i) {
        if (output1[i] != output2[i]) {
            return false;
        }
    }
    return true;
}