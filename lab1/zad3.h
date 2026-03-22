#include <iostream>
#include <map>
#include "common.h"
#include "mbedtls/platform_util.h"
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls/md5.h"

struct Condition {
    uint32_t mask;
    uint32_t offset;
};

struct ConditionNode {
    Condition condition;
    int first;
    int second;
    struct ConditionNode* next;
};

typedef ConditionNode* ConditionList;

#define S(x,n)                                                                                    \
    ( ( (x) << (n) ) | ( ( (x) & 0xFFFFFFFF) >> ( 32 - (n) ) ) )

#define P(a,b,c,d,k,s,t)                                                                          \
    do                                                                                            \
    {                                                                                             \
        (a) += F((b),(c),(d)) + local.X[(k)] + (t);                                               \
        (a) = S((a),(s)) + (b);                                                                   \
        /*ConditionList ptr = conditions[i];                                                        \
        while (ptr != NULL) {                                                                     \
            Condition con = ptr->condition;                                                       \
            uint32_t left;                                                                        \
            uint32_t right;                                                                       \
            if (ptr->first == 4) {                                                                \
                left = F((b),(c),(d));                                                            \
            } else if (ptr->first > 4) {                                                          \
                left = *ptrs[ptr->first - 5] + ctx->state[ptr->first - 5];                        \
            } else {                                                                              \
                left = *ptrs[ptr->first];                                                         \
            }                                                                                     \
            left &= con.mask;                                                                     \
            if (ptr->second == 4) {                                                               \
                right = F((b),(c),(d));                                                           \
            } else if (ptr->second == 9) {                                                        \
                right = 0;                                                                        \
            } else if (ptr->second > 4) {                                                         \
                right = *ptrs[ptr->second - 5] + ctx->state[ptr->second - 5];                     \
            } else {                                                                              \
                right = *ptrs[ptr->second];                                                       \
            }                                                                                     \
            right = right & con.mask ^ con.offset;                                                \
            if (left != right) {                                                                  \
                return false;                                                                     \
            }                                                                                     \
            ptr = ptr->next;                                                                      \
        }                                                                                         \
        ++i;                                                                                      */\
    } while( 0 )

__device__ bool checkConditions(ConditionList* conditions, mbedtls_md5_context *ctx, const unsigned char data[64])
{
    struct
    {
        uint32_t X[16], A, B, C, D;
    } local;

    local.X[ 0] = MBEDTLS_GET_UINT32_LE( data,  0 );
    local.X[ 1] = MBEDTLS_GET_UINT32_LE( data,  4 );
    local.X[ 2] = MBEDTLS_GET_UINT32_LE( data,  8 );
    local.X[ 3] = MBEDTLS_GET_UINT32_LE( data, 12 );
    local.X[ 4] = MBEDTLS_GET_UINT32_LE( data, 16 );
    local.X[ 5] = MBEDTLS_GET_UINT32_LE( data, 20 );
    local.X[ 6] = MBEDTLS_GET_UINT32_LE( data, 24 );
    local.X[ 7] = MBEDTLS_GET_UINT32_LE( data, 28 );
    local.X[ 8] = MBEDTLS_GET_UINT32_LE( data, 32 );
    local.X[ 9] = MBEDTLS_GET_UINT32_LE( data, 36 );
    local.X[10] = MBEDTLS_GET_UINT32_LE( data, 40 );
    local.X[11] = MBEDTLS_GET_UINT32_LE( data, 44 );
    local.X[12] = MBEDTLS_GET_UINT32_LE( data, 48 );
    local.X[13] = MBEDTLS_GET_UINT32_LE( data, 52 );
    local.X[14] = MBEDTLS_GET_UINT32_LE( data, 56 );
    local.X[15] = MBEDTLS_GET_UINT32_LE( data, 60 );

    // int i = 0;
    // uint32_t* ptrs[4] = {&local.A, &local.B, &local.C, &local.D};

    local.A = ctx->state[0];
    local.B = ctx->state[1];
    local.C = ctx->state[2];
    local.D = ctx->state[3];

#define F(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))

    P( local.A, local.B, local.C, local.D,  0,  7, 0xD76AA478 );
    P( local.D, local.A, local.B, local.C,  1, 12, 0xE8C7B756 );
    P( local.C, local.D, local.A, local.B,  2, 17, 0x242070DB );
    P( local.B, local.C, local.D, local.A,  3, 22, 0xC1BDCEEE );
    P( local.A, local.B, local.C, local.D,  4,  7, 0xF57C0FAF );
    P( local.D, local.A, local.B, local.C,  5, 12, 0x4787C62A );
    P( local.C, local.D, local.A, local.B,  6, 17, 0xA8304613 );
    P( local.B, local.C, local.D, local.A,  7, 22, 0xFD469501 );
    P( local.A, local.B, local.C, local.D,  8,  7, 0x698098D8 );
    P( local.D, local.A, local.B, local.C,  9, 12, 0x8B44F7AF );
    P( local.C, local.D, local.A, local.B, 10, 17, 0xFFFF5BB1 );
    P( local.B, local.C, local.D, local.A, 11, 22, 0x895CD7BE );
    P( local.A, local.B, local.C, local.D, 12,  7, 0x6B901122 );
    P( local.D, local.A, local.B, local.C, 13, 12, 0xFD987193 );
    P( local.C, local.D, local.A, local.B, 14, 17, 0xA679438E );
    P( local.B, local.C, local.D, local.A, 15, 22, 0x49B40821 );

#undef F

#define F(x,y,z) ((y) ^ ((z) & ((x) ^ (y))))

    P( local.A, local.B, local.C, local.D,  1,  5, 0xF61E2562 );
    P( local.D, local.A, local.B, local.C,  6,  9, 0xC040B340 );
    P( local.C, local.D, local.A, local.B, 11, 14, 0x265E5A51 );
    P( local.B, local.C, local.D, local.A,  0, 20, 0xE9B6C7AA );
    P( local.A, local.B, local.C, local.D,  5,  5, 0xD62F105D );
    P( local.D, local.A, local.B, local.C, 10,  9, 0x02441453 );
    P( local.C, local.D, local.A, local.B, 15, 14, 0xD8A1E681 );
    P( local.B, local.C, local.D, local.A,  4, 20, 0xE7D3FBC8 );
    P( local.A, local.B, local.C, local.D,  9,  5, 0x21E1CDE6 );
    P( local.D, local.A, local.B, local.C, 14,  9, 0xC33707D6 );
    P( local.C, local.D, local.A, local.B,  3, 14, 0xF4D50D87 );
    P( local.B, local.C, local.D, local.A,  8, 20, 0x455A14ED );
    P( local.A, local.B, local.C, local.D, 13,  5, 0xA9E3E905 );
    P( local.D, local.A, local.B, local.C,  2,  9, 0xFCEFA3F8 );
    P( local.C, local.D, local.A, local.B,  7, 14, 0x676F02D9 );
    P( local.B, local.C, local.D, local.A, 12, 20, 0x8D2A4C8A );

#undef F

#define F(x,y,z) ((x) ^ (y) ^ (z))

    P( local.A, local.B, local.C, local.D,  5,  4, 0xFFFA3942 );
    P( local.D, local.A, local.B, local.C,  8, 11, 0x8771F681 );
    P( local.C, local.D, local.A, local.B, 11, 16, 0x6D9D6122 );
    P( local.B, local.C, local.D, local.A, 14, 23, 0xFDE5380C );
    P( local.A, local.B, local.C, local.D,  1,  4, 0xA4BEEA44 );
    P( local.D, local.A, local.B, local.C,  4, 11, 0x4BDECFA9 );
    P( local.C, local.D, local.A, local.B,  7, 16, 0xF6BB4B60 );
    P( local.B, local.C, local.D, local.A, 10, 23, 0xBEBFBC70 );
    P( local.A, local.B, local.C, local.D, 13,  4, 0x289B7EC6 );
    P( local.D, local.A, local.B, local.C,  0, 11, 0xEAA127FA );
    P( local.C, local.D, local.A, local.B,  3, 16, 0xD4EF3085 );
    P( local.B, local.C, local.D, local.A,  6, 23, 0x04881D05 );
    P( local.A, local.B, local.C, local.D,  9,  4, 0xD9D4D039 );
    P( local.D, local.A, local.B, local.C, 12, 11, 0xE6DB99E5 );
    P( local.C, local.D, local.A, local.B, 15, 16, 0x1FA27CF8 );
    P( local.B, local.C, local.D, local.A,  2, 23, 0xC4AC5665 );

#undef F

#define F(x,y,z) ((y) ^ ((x) | ~(z)))

    P( local.A, local.B, local.C, local.D,  0,  6, 0xF4292244 );
    P( local.D, local.A, local.B, local.C,  7, 10, 0x432AFF97 );
    P( local.C, local.D, local.A, local.B, 14, 15, 0xAB9423A7 );
    P( local.B, local.C, local.D, local.A,  5, 21, 0xFC93A039 );
    P( local.A, local.B, local.C, local.D, 12,  6, 0x655B59C3 );
    P( local.D, local.A, local.B, local.C,  3, 10, 0x8F0CCC92 );
    P( local.C, local.D, local.A, local.B, 10, 15, 0xFFEFF47D );
    P( local.B, local.C, local.D, local.A,  1, 21, 0x85845DD1 );
    P( local.A, local.B, local.C, local.D,  8,  6, 0x6FA87E4F );
    P( local.D, local.A, local.B, local.C, 15, 10, 0xFE2CE6E0 );
    P( local.C, local.D, local.A, local.B,  6, 15, 0xA3014314 );
    P( local.B, local.C, local.D, local.A, 13, 21, 0x4E0811A1 );
    P( local.A, local.B, local.C, local.D,  4,  6, 0xF7537E82 );
    P( local.D, local.A, local.B, local.C, 11, 10, 0xBD3AF235 );
    P( local.C, local.D, local.A, local.B,  2, 15, 0x2AD7D2BB );
    P( local.B, local.C, local.D, local.A,  9, 21, 0xEB86D391 );

#undef F

    ctx->state[0] += local.A;
    ctx->state[1] += local.B;
    ctx->state[2] += local.C;
    ctx->state[3] += local.D;

    return true;
}

// Single message modification:
// ((a + F(b,c,d) + m + k) <<< s + b) & mask = offset
// ((a + F(b,c,d) + m + k) <<< s + b) & ~mask = x
// (a + F(b,c,d) + m + k) <<< s + b = offset | x
// a + F(b,c,d) + m + k = ((offset | x) - b) >>> s
// m = ((offset | x) - b) >>> s - a - F(b,c,d) - k

// Multi message modification:
// ((a_1 + m_1) <<< s_1 + b_1) = offset_1 | x_1 (offset_1 & x_1 = 0)
// ((a_2 + m_2) <<< s_2 + b_2) = offset_2 | x_2 (offset_2 & x_2 = 0)
// m_1 = ((offset_1 | x_1) - b_1) >>> s_1 - a_1
// m_2 = ((offset_2 | x_2) - b_2) >>> s_2 - a_2
// zadanie: znajdź x_1 i x_2 takie, aby m_1=m_2
// pytanie: które bity m_1 i m_2 możemy kontrolować?
// odpowiedź: te, które nie są istotnymi bitami offset_1 >>> s_1 i offset_2 >>> s_2

__device__ bool getMessageSatisfyingConditions(ConditionList* conditions, mbedtls_md5_context *ctx, mbedtls_md5_context *ctx_2, unsigned char data[64], unsigned char data_2[64])
{
    struct
    {
        uint32_t X[16], A, B, C, D;
    } local;

    local.X[ 0] = MBEDTLS_GET_UINT32_LE( data,  0 );
    local.X[ 1] = MBEDTLS_GET_UINT32_LE( data,  4 );
    local.X[ 2] = MBEDTLS_GET_UINT32_LE( data,  8 );
    local.X[ 3] = MBEDTLS_GET_UINT32_LE( data, 12 );
    local.X[ 4] = MBEDTLS_GET_UINT32_LE( data, 16 );
    local.X[ 5] = MBEDTLS_GET_UINT32_LE( data, 20 );
    local.X[ 6] = MBEDTLS_GET_UINT32_LE( data, 24 );
    local.X[ 7] = MBEDTLS_GET_UINT32_LE( data, 28 );
    local.X[ 8] = MBEDTLS_GET_UINT32_LE( data, 32 );
    local.X[ 9] = MBEDTLS_GET_UINT32_LE( data, 36 );
    local.X[10] = MBEDTLS_GET_UINT32_LE( data, 40 );
    local.X[11] = MBEDTLS_GET_UINT32_LE( data, 44 );
    local.X[12] = MBEDTLS_GET_UINT32_LE( data, 48 );
    local.X[13] = MBEDTLS_GET_UINT32_LE( data, 52 );
    local.X[14] = MBEDTLS_GET_UINT32_LE( data, 56 );
    local.X[15] = MBEDTLS_GET_UINT32_LE( data, 60 );

    int i = 0;
    uint32_t* ptrs[4] = {&local.A, &local.B, &local.C, &local.D};

#define Q(a,b,c,d,k,s,t)                                                                  \
    do                                                                                    \
    {                                                                                     \
        uint32_t offset = S((a) + F((b),(c),(d)) + local.X[(k)] + (t), (s)) + (b);        \
        ConditionList ptr = conditions[i];                                                \
        while (ptr != NULL) {                                                             \
            Condition con = ptr->condition;                                               \
            offset &= ~con.mask;                                                          \
            if (ptr->second == 9) {                                                       \
                offset |= con.offset;                                                     \
            } else {                                                                      \
                offset |= *ptrs[ptr->second] & con.mask ^ con.offset;                     \
            }                                                                             \
            ptr = ptr->next;                                                              \
        }                                                                                 \
        local.X[(k)] = S((offset - (b)), (32 - s)) - (a) - F((b),(c),(d)) - (t);          \
        (a) += F((b),(c),(d)) + local.X[(k)] + (t);                                       \
        (a) = S((a),(s)) + (b);                                                           \
        ++i;                                                                              \
    } while( 0 )

    local.A = ctx->state[0];
    local.B = ctx->state[1];
    local.C = ctx->state[2];
    local.D = ctx->state[3];

#define F(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))

    Q( local.A, local.B, local.C, local.D,  0,  7, 0xD76AA478 );
    Q( local.D, local.A, local.B, local.C,  1, 12, 0xE8C7B756 );
    Q( local.C, local.D, local.A, local.B,  2, 17, 0x242070DB );
    Q( local.B, local.C, local.D, local.A,  3, 22, 0xC1BDCEEE );
    Q( local.A, local.B, local.C, local.D,  4,  7, 0xF57C0FAF );
    Q( local.D, local.A, local.B, local.C,  5, 12, 0x4787C62A );
    Q( local.C, local.D, local.A, local.B,  6, 17, 0xA8304613 );
    Q( local.B, local.C, local.D, local.A,  7, 22, 0xFD469501 );
    Q( local.A, local.B, local.C, local.D,  8,  7, 0x698098D8 );
    Q( local.D, local.A, local.B, local.C,  9, 12, 0x8B44F7AF );
    Q( local.C, local.D, local.A, local.B, 10, 17, 0xFFFF5BB1 );
    Q( local.B, local.C, local.D, local.A, 11, 22, 0x895CD7BE );
    Q( local.A, local.B, local.C, local.D, 12,  7, 0x6B901122 );
    Q( local.D, local.A, local.B, local.C, 13, 12, 0xFD987193 );
    Q( local.C, local.D, local.A, local.B, 14, 17, 0xA679438E );
    Q( local.B, local.C, local.D, local.A, 15, 22, 0x49B40821 );

#undef F

#define F(x,y,z) ((y) ^ ((z) & ((x) ^ (y))))

    P( local.A, local.B, local.C, local.D,  1,  5, 0xF61E2562 );
    P( local.D, local.A, local.B, local.C,  6,  9, 0xC040B340 );
    P( local.C, local.D, local.A, local.B, 11, 14, 0x265E5A51 );
    P( local.B, local.C, local.D, local.A,  0, 20, 0xE9B6C7AA );
    P( local.A, local.B, local.C, local.D,  5,  5, 0xD62F105D );
    P( local.D, local.A, local.B, local.C, 10,  9, 0x02441453 );
    P( local.C, local.D, local.A, local.B, 15, 14, 0xD8A1E681 );
    P( local.B, local.C, local.D, local.A,  4, 20, 0xE7D3FBC8 );
    P( local.A, local.B, local.C, local.D,  9,  5, 0x21E1CDE6 );
    P( local.D, local.A, local.B, local.C, 14,  9, 0xC33707D6 );
    P( local.C, local.D, local.A, local.B,  3, 14, 0xF4D50D87 );
    P( local.B, local.C, local.D, local.A,  8, 20, 0x455A14ED );
    P( local.A, local.B, local.C, local.D, 13,  5, 0xA9E3E905 );
    P( local.D, local.A, local.B, local.C,  2,  9, 0xFCEFA3F8 );
    P( local.C, local.D, local.A, local.B,  7, 14, 0x676F02D9 );
    P( local.B, local.C, local.D, local.A, 12, 20, 0x8D2A4C8A );

#undef F

#define F(x,y,z) ((x) ^ (y) ^ (z))

    P( local.A, local.B, local.C, local.D,  5,  4, 0xFFFA3942 );
    P( local.D, local.A, local.B, local.C,  8, 11, 0x8771F681 );
    P( local.C, local.D, local.A, local.B, 11, 16, 0x6D9D6122 );
    P( local.B, local.C, local.D, local.A, 14, 23, 0xFDE5380C );
    P( local.A, local.B, local.C, local.D,  1,  4, 0xA4BEEA44 );
    P( local.D, local.A, local.B, local.C,  4, 11, 0x4BDECFA9 );
    P( local.C, local.D, local.A, local.B,  7, 16, 0xF6BB4B60 );
    P( local.B, local.C, local.D, local.A, 10, 23, 0xBEBFBC70 );
    P( local.A, local.B, local.C, local.D, 13,  4, 0x289B7EC6 );
    P( local.D, local.A, local.B, local.C,  0, 11, 0xEAA127FA );
    P( local.C, local.D, local.A, local.B,  3, 16, 0xD4EF3085 );
    P( local.B, local.C, local.D, local.A,  6, 23, 0x04881D05 );
    P( local.A, local.B, local.C, local.D,  9,  4, 0xD9D4D039 );
    P( local.D, local.A, local.B, local.C, 12, 11, 0xE6DB99E5 );
    P( local.C, local.D, local.A, local.B, 15, 16, 0x1FA27CF8 );
    P( local.B, local.C, local.D, local.A,  2, 23, 0xC4AC5665 );

#undef F

#define F(x,y,z) ((y) ^ ((x) | ~(z)))

    P( local.A, local.B, local.C, local.D,  0,  6, 0xF4292244 );
    P( local.D, local.A, local.B, local.C,  7, 10, 0x432AFF97 );
    P( local.C, local.D, local.A, local.B, 14, 15, 0xAB9423A7 );
    P( local.B, local.C, local.D, local.A,  5, 21, 0xFC93A039 );
    P( local.A, local.B, local.C, local.D, 12,  6, 0x655B59C3 );
    P( local.D, local.A, local.B, local.C,  3, 10, 0x8F0CCC92 );
    P( local.C, local.D, local.A, local.B, 10, 15, 0xFFEFF47D );
    P( local.B, local.C, local.D, local.A,  1, 21, 0x85845DD1 );
    P( local.A, local.B, local.C, local.D,  8,  6, 0x6FA87E4F );
    P( local.D, local.A, local.B, local.C, 15, 10, 0xFE2CE6E0 );
    P( local.C, local.D, local.A, local.B,  6, 15, 0xA3014314 );
    P( local.B, local.C, local.D, local.A, 13, 21, 0x4E0811A1 );
    P( local.A, local.B, local.C, local.D,  4,  6, 0xF7537E82 );
    P( local.D, local.A, local.B, local.C, 11, 10, 0xBD3AF235 );
    P( local.C, local.D, local.A, local.B,  2, 15, 0x2AD7D2BB );
    P( local.B, local.C, local.D, local.A,  9, 21, 0xEB86D391 );

#undef F

    ctx->state[0] += local.A;
    ctx->state[1] += local.B;
    ctx->state[2] += local.C;
    ctx->state[3] += local.D;

    for (i = 0; i < 64; ++i) {
        data[i] = (unsigned char) ((local.X[i / 4] >> (8 * (i % 4))) & 0xff);
    }

    local.X[4] += (uint32_t) 1 << 31;
    local.X[11] -= (uint32_t) 1 << 15;
    local.X[14] += (uint32_t) 1 << 31;
    for (i = 0; i < 64; ++i) {
        data_2[i] = (unsigned char) ((local.X[i / 4] >> (8 * (i % 4))) & 0xff);
    }

    checkConditions(conditions, ctx_2, data_2);
    return ctx->state[0] == ctx_2->state[0] && ctx->state[1] == ctx_2->state[1] && ctx->state[2] == ctx_2->state[2] && ctx->state[3] == ctx_2->state[3];
}