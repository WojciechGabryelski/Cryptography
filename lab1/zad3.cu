#include <iostream>
#include <fstream>
#include <random>
#include <string>
#include <map>
#include <curand_kernel.h>
#include "zad2.h"
#include "zad3.h"

std::map<std::pair<int, int>, Condition>* readConditions() {
    std::fstream fs;
    fs.open("conditions2.txt", std::ios::in);
    std::map<std::pair<int, int>, Condition>* conditions = new std::map<std::pair<int, int>, Condition>[64];
    std::map<std::pair<int, int>, Condition>::iterator it;
    std::string s;
    int perm[4] = {0, 3, 2, 1};
    while (fs >> s) {
        int eq_pos = s.find("=");
        int var1 = s[0] - 'a';
        int collon_pos = s.find(",");
        int pos;
        if (s[1] >= 'a') {
            pos = 60 + perm[var1];
            var1 += 5;
        } else {
            int round1;
            round1 = stoi(s.substr(1, collon_pos - 1));
            if (var1 != 4) {
                pos = 4 * round1 - 4 + perm[var1];
            } else {
                pos = round1 - 1;
            }
        }
        auto &m = conditions[pos];
        int bit_pos = stoi(s.substr(collon_pos + 1, eq_pos - collon_pos)) - 1;
        int bit;
        int var2;
        if (s[eq_pos + 1] >= '0' && s[eq_pos + 1] <= '9') {
            var2 = 9;
            bit = s[eq_pos + 1] - '0';
        } else {
            var2 = s[eq_pos + 1] - 'a';
            if (s[eq_pos + 2] >= 'a') {
                var2 += 5;
            }
            int plus_pos = s.find("+");
            if (plus_pos != -1) {
                bit = 1;
            } else {
                bit = 0;
            }
        }
        it = m.find({var1, var2});
        if (it == m.end()) {
            Condition con;
            con.mask = (uint32_t) 1 << bit_pos;
            con.offset = (uint32_t) bit << bit_pos;
            m[{var1, var2}] = con;
        } else {
            it->second.mask |= (uint32_t) 1 << bit_pos;
            it->second.offset |= (uint32_t) bit << bit_pos;
        }
    }
    fs.close();
    return conditions;
}

ConditionList* conditionMapToDeviceConditionList(std::map<std::pair<int, int>, Condition>* conditionMap) {
    ConditionList* conditionList;
    ConditionList null = NULL;
    cudaMalloc(&conditionList, 64 * sizeof(ConditionList));
    for (int i = 0; i < 64; ++i) {
        auto &m = conditionMap[i];
        cudaMemcpy(conditionList + i, &null, sizeof(ConditionList), cudaMemcpyHostToDevice);
        ConditionList* d_tail = conditionList + i;
        for (auto it = m.begin(); it != m.end(); ++it) {
            ConditionNode node;
            node.first = it->first.first;
            node.second = it->first.second;
            node.condition = it->second;
            node.next = NULL;
            ConditionList d_l;
            cudaMalloc(&d_l, sizeof(ConditionNode));
            cudaMemcpy(d_l, &node, sizeof(ConditionNode), cudaMemcpyHostToDevice);
            cudaMemcpy(d_tail, &d_l, sizeof(ConditionList), cudaMemcpyHostToDevice);
            d_tail = &(d_l->next);
        }
        
    }
    return conditionList;
}

__global__ void step2(ConditionList* conditions, mbedtls_md5_context ctx_1, mbedtls_md5_context ctx_2, int* flag, unsigned char* buf, unsigned char* buf_2, unsigned long long seed) {
    unsigned char m1[64];
    unsigned char m2[64];
    curandState state;
    curand_init(seed + blockIdx.x * blockDim.x + threadIdx.x, 0, 0, &state);
    bool conditionsMet;
    int counter = 0;
    do {
        for (int i = 0; i < 64; ++i) {
            // m1[i] = buf[i];
            // m2[i] = buf_2[i];
            m1[i] = (unsigned char)(curand(&state) % 256);
        }
        mbedtls_md5_context ctx_tmp_1 = ctx_1;
        mbedtls_md5_context ctx_tmp_2 = ctx_2;
        conditionsMet = getMessageSatisfyingConditions(conditions, &ctx_tmp_1, &ctx_tmp_2, m1, m2);
        if (conditionsMet && atomicCAS(flag, 0, 1) == 0) {
            ctx_tmp_1 = ctx_1;
            ctx_tmp_2 = ctx_2;
            ctx_tmp_1 = ctx_1;
            for (int i = 0; i < 64; ++i) {
                buf[i] = m1[i];
                buf_2[i] = m2[i];
            }
        }
        ++counter;
    } while (!conditionsMet && atomicAdd(flag, 0) == 0);
}

int main() {
    unsigned char m0_1[64] = {
        0x02, 0xdd, 0x31, 0xd1,
        0xc4, 0xee, 0xe6, 0xc5,
        0x06, 0x9a, 0x3d, 0x69,
        0x5c, 0xf9, 0xaf, 0x98,
        0x87, 0xb5, 0xca, 0x2f,
        0xab, 0x7e, 0x46, 0x12,
        0x3e, 0x58, 0x04, 0x40,
        0x89, 0x7f, 0xfb, 0xb8,
        0x06, 0x34, 0xad, 0x55,
        0x02, 0xb3, 0xf4, 0x09,
        0x83, 0x88, 0xe4, 0x83,
        0x5a, 0x41, 0x71, 0x25,
        0xe8, 0x25, 0x51, 0x08,
        0x9f, 0xc9, 0xcd, 0xf7,
        0xf2, 0xbd, 0x1d, 0xd9,
        0x5b, 0x3c, 0x37, 0x80};
    unsigned char m0_2[64] = {
        0x02, 0xdd, 0x31, 0xd1,
        0xc4, 0xee, 0xe6, 0xc5,
        0x06, 0x9a, 0x3d, 0x69,
        0x5c, 0xf9, 0xaf, 0x98,
        0x07, 0xb5, 0xca, 0x2f,
        0xab, 0x7e, 0x46, 0x12,
        0x3e, 0x58, 0x04, 0x40,
        0x89, 0x7f, 0xfb, 0xb8,
        0x06, 0x34, 0xad, 0x55,
        0x02, 0xb3, 0xf4, 0x09,
        0x83, 0x88, 0xe4, 0x83,
        0x5a, 0x41, 0xf1, 0x25,
        0xe8, 0x25, 0x51, 0x08,
        0x9f, 0xc9, 0xcd, 0xf7,
        0x72, 0xbd, 0x1d, 0xd9,
        0x5b, 0x3c, 0x37, 0x80
    };
    unsigned char m1_1a[64] = {
        // 0xd1, 0x1d, 0x0b, 0x96,
        // 0x9c, 0x7b, 0x41, 0xdc,
        // 0xf4, 0x97, 0xd8, 0xe4,
        // 0xd5, 0x55, 0x65, 0x5a,
        // 0xc7, 0x9a, 0x73, 0x35,
        // 0x0c, 0xfd, 0xeb, 0xf0,
        // 0x66, 0xf1, 0x29, 0x30,
        // 0x8f, 0xb1, 0x09, 0xd1,
        // 0x79, 0x7f, 0x27, 0x75,
        // 0xeb, 0x5c, 0xd5, 0x30,
        // 0xba, 0xad, 0xe8, 0x22,
        // 0x5c, 0x15, 0xcc, 0x79,
        // 0xdd, 0xcb, 0x74, 0xed,
        // 0x6d, 0xd3, 0xc5, 0x5f,
        // 0xd8, 0x0a, 0x9b, 0xb1,
        // 0xe3, 0xa7, 0xcc, 0x35
        0xc7, 0x40, 0x7c, 0x20,
        0xfa, 0xcb, 0x14, 0xd2,
        0xc7, 0x10, 0xcb, 0xf1,
        0xc5, 0xdd, 0x29, 0x6a,
        0xb5, 0x23, 0xae, 0xce,
        0xfe, 0x3a, 0x4e, 0x46,
        0x03, 0x7e, 0x77, 0x58,
        0x8f, 0x95, 0x65, 0x51,
        0x7a, 0xbb, 0x38, 0x39,
        0x67, 0xcb, 0xf6, 0x4b,
        0x09, 0xa2, 0xac, 0x6a,
        0x10, 0x19, 0xd8, 0x87,
        0x77, 0xa8, 0xa4, 0xc2,
        0x5c, 0x94, 0x18, 0x96,
        0x0f, 0xc9, 0x5e, 0xb9,
        0xd9, 0xdd, 0x72, 0xba
    };
    unsigned char m1_2a[64] = {
        // 0xd1, 0x1d, 0x0b, 0x96,
        // 0x9c, 0x7b, 0x41, 0xdc,
        // 0xf4, 0x97, 0xd8, 0xe4,
        // 0xd5, 0x55, 0x65, 0x5a,
        // 0x47, 0x9a, 0x73, 0x35,
        // 0x0c, 0xfd, 0xeb, 0xf0,
        // 0x66, 0xf1, 0x29, 0x30,
        // 0x8f, 0xb1, 0x09, 0xd1,
        // 0x79, 0x7f, 0x27, 0x75,
        // 0xeb, 0x5c, 0xd5, 0x30,
        // 0xba, 0xad, 0xe8, 0x22,
        // 0x5c, 0x15, 0x4c, 0x79,
        // 0xdd, 0xcb, 0x74, 0xed,
        // 0x6d, 0xd3, 0xc5, 0x5f,
        // 0x58, 0x0a, 0x9b, 0xb1,
        // 0xe3, 0xa7, 0xcc, 0x35
        0xc7, 0x40, 0x7c, 0x20,
        0xfa, 0xcb, 0x14, 0xd2,
        0xc7, 0x10, 0xcb, 0xf1,
        0xc5, 0xdd, 0x29, 0x6a,
        0x35, 0x23, 0xae, 0xce,
        0xfe, 0x3a, 0x4e, 0x46,
        0x03, 0x7e, 0x77, 0x58,
        0x8f, 0x95, 0x65, 0x51,
        0x7a, 0xbb, 0x38, 0x39,
        0x67, 0xcb, 0xf6, 0x4b,
        0x09, 0xa2, 0xac, 0x6a,
        0x10, 0x19, 0x58, 0x87,
        0x77, 0xa8, 0xa4, 0xc2,
        0x5c, 0x94, 0x18, 0x96,
        0x07, 0xc9, 0x5e, 0xb9,
        0xd9, 0xdd, 0x72, 0xba
    };
    for (int i = 0; i < 16; ++i) {
        std::swap(m0_1[4 * i], m0_1[4 * i + 3]);
        std::swap(m0_1[4 * i + 1], m0_1[4 * i + 2]);
        std::swap(m1_1a[4 * i], m1_1a[4 * i + 3]);
        std::swap(m1_1a[4 * i + 1], m1_1a[4 * i + 2]);
        std::swap(m0_2[4 * i], m0_2[4 * i + 3]);
        std::swap(m0_2[4 * i + 1], m0_2[4 * i + 2]);
        std::swap(m1_2a[4 * i], m1_2a[4 * i + 3]);
        std::swap(m1_2a[4 * i + 1], m1_2a[4 * i + 2]);
    }

    std::map<std::pair<int, int>, Condition>* conditions = readConditions();
    ConditionList* d_conditions = conditionMapToDeviceConditionList(conditions);
    delete[] conditions;
    mbedtls_md5_context ctx_1;
    mbedtls_md5_starts(&ctx_1);
    mbedtls_internal_md5_process(&ctx_1, m0_1);
    mbedtls_md5_context ctx_2;
    mbedtls_md5_starts(&ctx_2);
    mbedtls_internal_md5_process(&ctx_2, m0_2);
    bool equal;
    unsigned char* d_m1_1;
    unsigned char* d_m1_2;
    int* d_flag;
    cudaMalloc(&d_m1_1, 64 * sizeof(unsigned char));
    cudaMalloc(&d_m1_2, 64 * sizeof(unsigned char));
    cudaMalloc(&d_flag, sizeof(int));
    unsigned char* m1_1 = new unsigned char [64];
    unsigned char* m1_2 = new unsigned char [64];
    // cudaMemcpy(d_m1_1, m1_1a, 64 * sizeof(unsigned char), cudaMemcpyHostToDevice);
    // cudaMemcpy(d_m1_2, m1_2a, 64 * sizeof(unsigned char), cudaMemcpyHostToDevice);
    do {
        int zero = 0;
        cudaMemcpy(d_flag, &zero, sizeof(int), cudaMemcpyHostToDevice);
        std::random_device rd;
        unsigned long long seed = rd() ^ std::time(nullptr);
        step2<<<640, 256>>>(d_conditions, ctx_1, ctx_2, d_flag, d_m1_1, d_m1_2, seed);
        cudaDeviceSynchronize();
        cudaMemcpy(m1_1, d_m1_1, 64 * sizeof(unsigned char), cudaMemcpyDeviceToHost);
        cudaMemcpy(m1_2, d_m1_2, 64 * sizeof(unsigned char), cudaMemcpyDeviceToHost);

        equal = hashesEqual1(m0_1, m1_1, m0_2, m1_2);
        for (int i = 0; i < 16; ++i) {
            std::swap(m1_1[4 * i], m1_1[4 * i + 3]);
            std::swap(m1_1[4 * i + 1], m1_1[4 * i + 2]);
            std::swap(m1_2[4 * i], m1_2[4 * i + 3]);
            std::swap(m1_2[4 * i + 1], m1_2[4 * i + 2]);
        }
        for (int i = 0; i < 64; ++i) {
            printf("%02x", m1_1[i]);
            if (i % 4 == 3) {
                std::cout << " ";
            }
        }
        std::cout << "\n";
        for (int i = 0; i < 64; ++i) {
            printf("%02x", m1_2[i]);
            if (i % 4 == 3) {
                std::cout << " ";
            }
        }
        std::cout << "\n";
    } while (!equal);
    delete[] m1_1;
    delete[] m1_2;
    cudaFree(d_m1_1);
    cudaFree(d_conditions);
    cudaFree(d_flag);
    return 0;
}