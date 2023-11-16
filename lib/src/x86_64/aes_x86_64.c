/*
 * Copyright 2023 LINE Corporation
 *
 * LINE Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include "aes_x86_64.h"

#ifdef TARGET_PLATFORM_X86_64

#include <string.h>

#include "utils.h"

#ifdef __GNUC__
#define AESNI __attribute__((target("sse2,aes")))
#else
#define AESNI
#endif

#define AESKEYGEN(a, b)              _mm_aeskeygenassist_si128((a), (b))
#define KEY_EXP_HELPER(k0, k1, r, s) XOR(TSHIFT_ADD((k0)), SPLIT(AESKEYGEN((k1), (r)), (s)))
#define KEY_EXP_128(k, i, r)         KEY_EXP_HELPER((k)[(i)], (k)[(i)], (r), 0xff)
#define KEY_EXP_256_1(k, i, r)       KEY_EXP_HELPER((k)[(i)], (k)[(i) + 1], (r), 0xff)
#define KEY_EXP_256_2(k, i)          KEY_EXP_HELPER((k)[(i)], (k)[(i) + 1], 0x00, 0xaa)
#define SHIFT_ADD(a)                 _mm_xor_si128((a), _mm_slli_si128((a), 4))
#define SPLIT(a, b)                  _mm_shuffle_epi32((a), (b))
#define TSHIFT_ADD(a)                SHIFT_ADD(SHIFT_ADD(SHIFT_ADD((a))))
#define XOR(a, b)                    _mm_xor_si128((a), (b))

#define AES_ROUND_X2(b, k)                                                                         \
    do {                                                                                           \
        (b)[0] = _mm_aesenc_si128((b)[0], (k));                                                    \
        (b)[1] = _mm_aesenc_si128((b)[1], (k));                                                    \
    } while (0)

#define AES_LAST_ROUND_X2(b, k)                                                                    \
    do {                                                                                           \
        (b)[0] = _mm_aesenclast_si128((b)[0], (k));                                                \
        (b)[1] = _mm_aesenclast_si128((b)[1], (k));                                                \
    } while (0)

#define AES_ROUND_X3(b, k)                                                                         \
    do {                                                                                           \
        (b)[0] = _mm_aesenc_si128((b)[0], (k));                                                    \
        (b)[1] = _mm_aesenc_si128((b)[1], (k));                                                    \
        (b)[2] = _mm_aesenc_si128((b)[2], (k));                                                    \
    } while (0)

#define AES_LAST_ROUND_X3(b, k)                                                                    \
    do {                                                                                           \
        (b)[0] = _mm_aesenclast_si128((b)[0], (k));                                                \
        (b)[1] = _mm_aesenclast_si128((b)[1], (k));                                                \
        (b)[2] = _mm_aesenclast_si128((b)[2], (k));                                                \
    } while (0)

#define AES_ROUND_X4(b, k)                                                                         \
    do {                                                                                           \
        (b)[0] = _mm_aesenc_si128((b)[0], (k));                                                    \
        (b)[1] = _mm_aesenc_si128((b)[1], (k));                                                    \
        (b)[2] = _mm_aesenc_si128((b)[2], (k));                                                    \
        (b)[3] = _mm_aesenc_si128((b)[3], (k));                                                    \
    } while (0)

#define AES_LAST_ROUND_X4(b, k)                                                                    \
    do {                                                                                           \
        (b)[0] = _mm_aesenclast_si128((b)[0], (k));                                                \
        (b)[1] = _mm_aesenclast_si128((b)[1], (k));                                                \
        (b)[2] = _mm_aesenclast_si128((b)[2], (k));                                                \
        (b)[3] = _mm_aesenclast_si128((b)[3], (k));                                                \
    } while (0)

static inline __m128i aes_encrypt(struct aes_x86_64 *ctx, __m128i block);
static inline void aes_encrypt_x2(struct aes_x86_64 *ctx,
                                  const __m128i plain[2],
                                  __m128i cipher[2]);
static inline void aes_encrypt_x3(struct aes_x86_64 *ctx,
                                  const __m128i plain[3],
                                  __m128i cipher[3]);
static inline void aes_encrypt_x4(struct aes_x86_64 *ctx,
                                  const __m128i plain[4],
                                  __m128i cipher[4]);

AESNI
void aes_x86_64_init(struct aes_x86_64 *ctx)
{
    if (NULL == ctx) {
        return;
    }

    memset(ctx, 0x00, sizeof(*ctx));
}

AESNI
void aes_x86_64_free(struct aes_x86_64 *ctx)
{
    if (NULL == ctx) {
        return;
    }

    aes_gcmsiv_zeroize(ctx, sizeof(*ctx));
}

AESNI
aes_gcmsiv_status_t aes_x86_64_set_key(struct aes_x86_64 *ctx, const uint8_t *key, size_t key_sz)
{
    if (NULL == ctx || (NULL == key && 0 != key_sz)) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    if (16 != key_sz && 32 != key_sz) {
        return AES_GCMSIV_INVALID_KEY_SIZE;
    }

    ctx->key_sz = key_sz;

    switch (ctx->key_sz) {
    case 16:
        ctx->key[0] = _mm_loadu_si128((const __m128i_u *)key);
        ctx->key[5] = KEY_EXP_128(ctx->key, 0, 0x01);
        ctx->key[6] = KEY_EXP_128(ctx->key, 5, 0x02);
        ctx->key[7] = KEY_EXP_128(ctx->key, 6, 0x04);
        ctx->key[8] = KEY_EXP_128(ctx->key, 7, 0x08);
        ctx->key[9] = KEY_EXP_128(ctx->key, 8, 0x10);
        ctx->key[10] = KEY_EXP_128(ctx->key, 9, 0x20);
        ctx->key[11] = KEY_EXP_128(ctx->key, 10, 0x40);
        ctx->key[12] = KEY_EXP_128(ctx->key, 11, 0x80);
        ctx->key[13] = KEY_EXP_128(ctx->key, 12, 0x1b);
        ctx->key[14] = KEY_EXP_128(ctx->key, 13, 0x36);
        break;
    case 32:
        ctx->key[0] = _mm_loadu_si128((const __m128i_u *)key);
        ctx->key[1] = _mm_loadu_si128((const __m128i_u *)(key + 16));
        ctx->key[2] = KEY_EXP_256_1(ctx->key, 0, 0x01);
        ctx->key[3] = KEY_EXP_256_2(ctx->key, 1);
        ctx->key[4] = KEY_EXP_256_1(ctx->key, 2, 0x02);
        ctx->key[5] = KEY_EXP_256_2(ctx->key, 3);
        ctx->key[6] = KEY_EXP_256_1(ctx->key, 4, 0x04);
        ctx->key[7] = KEY_EXP_256_2(ctx->key, 5);
        ctx->key[8] = KEY_EXP_256_1(ctx->key, 6, 0x08);
        ctx->key[9] = KEY_EXP_256_2(ctx->key, 7);
        ctx->key[10] = KEY_EXP_256_1(ctx->key, 8, 0x10);
        ctx->key[11] = KEY_EXP_256_2(ctx->key, 9);
        ctx->key[12] = KEY_EXP_256_1(ctx->key, 10, 0x20);
        ctx->key[13] = KEY_EXP_256_2(ctx->key, 11);
        ctx->key[14] = KEY_EXP_256_1(ctx->key, 12, 0x40);
        break;
    }

    return AES_GCMSIV_SUCCESS;
}

AESNI
aes_gcmsiv_status_t aes_x86_64_ecb_encrypt(struct aes_x86_64 *ctx,
                                           const uint8_t input[AES_BLOCK_SIZE],
                                           uint8_t output[AES_BLOCK_SIZE])
{
    if (NULL == ctx || NULL == input || NULL == output) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    __m128i block = _mm_loadu_si128((const __m128i_u *)input);
    block = aes_encrypt(ctx, block);
    _mm_storeu_si128((__m128i_u *)output, block);

    return AES_GCMSIV_SUCCESS;
}

AESNI
aes_gcmsiv_status_t aes_x86_64_ctr(struct aes_x86_64 *ctx,
                                   const uint8_t nonce[AES_BLOCK_SIZE],
                                   const uint8_t *input,
                                   size_t input_sz,
                                   uint8_t *output)
{
    const __m128i one = _mm_set_epi32(0, 0, 0, 1);
    __m128i counter[4];
    __m128i block[4];
    size_t num_blocks;
    struct {
        __m128i stream[4];
        uint8_t tmp[AES_BLOCK_SIZE];
    } stack;

    if (NULL == ctx || ((NULL == input || NULL == output) && 0 != input_sz)) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    // Set nonce
    counter[0] = _mm_loadu_si128((const __m128i_u *)nonce);
    counter[1] = _mm_add_epi32(counter[0], one);
    counter[2] = _mm_add_epi32(counter[1], one);
    counter[3] = _mm_add_epi32(counter[2], one);

    // Process 4 blocks at a time
    while (input_sz >= 4 * AES_BLOCK_SIZE) {
        aes_encrypt_x4(ctx, counter, stack.stream);
        counter[0] = _mm_add_epi32(counter[3], one);
        counter[1] = _mm_add_epi32(counter[0], one);
        counter[2] = _mm_add_epi32(counter[1], one);
        counter[3] = _mm_add_epi32(counter[2], one);

        block[0] = _mm_loadu_si128((const __m128i_u *)(input + 0 * AES_BLOCK_SIZE));
        block[1] = _mm_loadu_si128((const __m128i_u *)(input + 1 * AES_BLOCK_SIZE));
        block[2] = _mm_loadu_si128((const __m128i_u *)(input + 2 * AES_BLOCK_SIZE));
        block[3] = _mm_loadu_si128((const __m128i_u *)(input + 3 * AES_BLOCK_SIZE));

        block[0] = XOR(block[0], stack.stream[0]);
        block[1] = XOR(block[1], stack.stream[1]);
        block[2] = XOR(block[2], stack.stream[2]);
        block[3] = XOR(block[3], stack.stream[3]);

        _mm_storeu_si128((__m128i_u *)(output + 0 * AES_BLOCK_SIZE), block[0]);
        _mm_storeu_si128((__m128i_u *)(output + 1 * AES_BLOCK_SIZE), block[1]);
        _mm_storeu_si128((__m128i_u *)(output + 2 * AES_BLOCK_SIZE), block[2]);
        _mm_storeu_si128((__m128i_u *)(output + 3 * AES_BLOCK_SIZE), block[3]);

        input += 4 * AES_BLOCK_SIZE;
        input_sz -= 4 * AES_BLOCK_SIZE;
        output += 4 * AES_BLOCK_SIZE;
    }

    // From this point, there are less than 4 full blocks, and the nonce is already updated
    if (input_sz > 0) {
        num_blocks = input_sz / AES_BLOCK_SIZE;

        // Process the remaining 1, 2, or 3 blocks at once
        switch (num_blocks) {
        case 0:
            stack.stream[0] = aes_encrypt(ctx, counter[0]);
            break;
        case 1:
            aes_encrypt_x2(ctx, counter, stack.stream);

            block[0] = _mm_loadu_si128((const __m128i_u *)input);

            block[0] = XOR(block[0], stack.stream[0]);

            _mm_storeu_si128((__m128i_u *)output, block[0]);

            input += AES_BLOCK_SIZE;
            output += AES_BLOCK_SIZE;
            break;
        case 2:
            aes_encrypt_x3(ctx, counter, stack.stream);

            block[0] = _mm_loadu_si128((const __m128i_u *)(input + 0 * AES_BLOCK_SIZE));
            block[1] = _mm_loadu_si128((const __m128i_u *)(input + 1 * AES_BLOCK_SIZE));

            block[0] = XOR(block[0], stack.stream[0]);
            block[1] = XOR(block[1], stack.stream[1]);

            _mm_storeu_si128((__m128i_u *)(output + 0 * AES_BLOCK_SIZE), block[0]);
            _mm_storeu_si128((__m128i_u *)(output + 1 * AES_BLOCK_SIZE), block[1]);

            input += 2 * AES_BLOCK_SIZE;
            output += 2 * AES_BLOCK_SIZE;
            break;
        case 3:
            aes_encrypt_x4(ctx, counter, stack.stream);

            block[0] = _mm_loadu_si128((const __m128i_u *)(input + 0 * AES_BLOCK_SIZE));
            block[1] = _mm_loadu_si128((const __m128i_u *)(input + 1 * AES_BLOCK_SIZE));
            block[2] = _mm_loadu_si128((const __m128i_u *)(input + 2 * AES_BLOCK_SIZE));

            block[0] = XOR(block[0], stack.stream[0]);
            block[1] = XOR(block[1], stack.stream[1]);
            block[2] = XOR(block[2], stack.stream[2]);

            _mm_storeu_si128((__m128i_u *)(output + 0 * AES_BLOCK_SIZE), block[0]);
            _mm_storeu_si128((__m128i_u *)(output + 1 * AES_BLOCK_SIZE), block[1]);
            _mm_storeu_si128((__m128i_u *)(output + 2 * AES_BLOCK_SIZE), block[2]);

            input += 3 * AES_BLOCK_SIZE;
            output += 3 * AES_BLOCK_SIZE;
            break;
        }

        input_sz -= num_blocks * AES_BLOCK_SIZE;

        // Process the remaining bytes
        if (input_sz > 0) {
            memcpy(stack.tmp, input, input_sz);
            memset(stack.tmp + input_sz, 0x00, sizeof(stack.tmp) - input_sz);

            block[0] = _mm_loadu_si128((const __m128i_u *)stack.tmp);
            block[0] = XOR(block[0], stack.stream[num_blocks]);
            _mm_storeu_si128((__m128i_u *)stack.tmp, block[0]);

            memcpy(output, stack.tmp, input_sz);
        }
    }

    aes_gcmsiv_zeroize(&stack, sizeof(stack));

    return AES_GCMSIV_SUCCESS;
}

AESNI
__m128i aes_encrypt(struct aes_x86_64 *ctx, __m128i block)
{
    // Initial round
    block = _mm_xor_si128(block, ctx->key[0]);

    switch (ctx->key_sz) {
    case 16:
        goto aes_128;
    case 32:
        goto aes_256;
    }

aes_256:
    // 13 rounds
    block = _mm_aesenc_si128(block, ctx->key[1]);
    block = _mm_aesenc_si128(block, ctx->key[2]);
    block = _mm_aesenc_si128(block, ctx->key[3]);
    block = _mm_aesenc_si128(block, ctx->key[4]);
aes_128:
    // 11 rounds
    block = _mm_aesenc_si128(block, ctx->key[5]);
    block = _mm_aesenc_si128(block, ctx->key[6]);
    block = _mm_aesenc_si128(block, ctx->key[7]);
    block = _mm_aesenc_si128(block, ctx->key[8]);
    block = _mm_aesenc_si128(block, ctx->key[9]);
    block = _mm_aesenc_si128(block, ctx->key[10]);
    block = _mm_aesenc_si128(block, ctx->key[11]);
    block = _mm_aesenc_si128(block, ctx->key[12]);
    block = _mm_aesenc_si128(block, ctx->key[13]);

    // Last round
    block = _mm_aesenclast_si128(block, ctx->key[14]);

    return block;
}

AESNI
void aes_encrypt_x2(struct aes_x86_64 *ctx, const __m128i plain[2], __m128i cipher[2])
{
    // Initial round
    cipher[0] = _mm_xor_si128(plain[0], ctx->key[0]);
    cipher[1] = _mm_xor_si128(plain[1], ctx->key[0]);

    switch (ctx->key_sz) {
    case 16:
        goto aes_128;
    case 32:
        goto aes_256;
    }

aes_256:
    // 13 rounds
    AES_ROUND_X2(cipher, ctx->key[1]);
    AES_ROUND_X2(cipher, ctx->key[2]);
    AES_ROUND_X2(cipher, ctx->key[3]);
    AES_ROUND_X2(cipher, ctx->key[4]);
aes_128:
    // 11 rounds
    AES_ROUND_X2(cipher, ctx->key[5]);
    AES_ROUND_X2(cipher, ctx->key[6]);
    AES_ROUND_X2(cipher, ctx->key[7]);
    AES_ROUND_X2(cipher, ctx->key[8]);
    AES_ROUND_X2(cipher, ctx->key[9]);
    AES_ROUND_X2(cipher, ctx->key[10]);
    AES_ROUND_X2(cipher, ctx->key[11]);
    AES_ROUND_X2(cipher, ctx->key[12]);
    AES_ROUND_X2(cipher, ctx->key[13]);

    // Last round
    AES_LAST_ROUND_X2(cipher, ctx->key[14]);
}

AESNI
void aes_encrypt_x3(struct aes_x86_64 *ctx, const __m128i plain[3], __m128i cipher[3])
{
    // Initial round
    cipher[0] = _mm_xor_si128(plain[0], ctx->key[0]);
    cipher[1] = _mm_xor_si128(plain[1], ctx->key[0]);
    cipher[2] = _mm_xor_si128(plain[2], ctx->key[0]);

    switch (ctx->key_sz) {
    case 16:
        goto aes_128;
    case 32:
        goto aes_256;
    }

aes_256:
    // 13 rounds
    AES_ROUND_X3(cipher, ctx->key[1]);
    AES_ROUND_X3(cipher, ctx->key[2]);
    AES_ROUND_X3(cipher, ctx->key[3]);
    AES_ROUND_X3(cipher, ctx->key[4]);
aes_128:
    // 11 rounds
    AES_ROUND_X3(cipher, ctx->key[5]);
    AES_ROUND_X3(cipher, ctx->key[6]);
    AES_ROUND_X3(cipher, ctx->key[7]);
    AES_ROUND_X3(cipher, ctx->key[8]);
    AES_ROUND_X3(cipher, ctx->key[9]);
    AES_ROUND_X3(cipher, ctx->key[10]);
    AES_ROUND_X3(cipher, ctx->key[11]);
    AES_ROUND_X3(cipher, ctx->key[12]);
    AES_ROUND_X3(cipher, ctx->key[13]);

    // Last round
    AES_LAST_ROUND_X3(cipher, ctx->key[14]);
}

AESNI
void aes_encrypt_x4(struct aes_x86_64 *ctx, const __m128i plain[4], __m128i cipher[4])
{
    // Initial round
    cipher[0] = _mm_xor_si128(plain[0], ctx->key[0]);
    cipher[1] = _mm_xor_si128(plain[1], ctx->key[0]);
    cipher[2] = _mm_xor_si128(plain[2], ctx->key[0]);
    cipher[3] = _mm_xor_si128(plain[3], ctx->key[0]);

    switch (ctx->key_sz) {
    case 16:
        goto aes_128;
    case 32:
        goto aes_256;
    }

aes_256:
    // 13 rounds
    AES_ROUND_X4(cipher, ctx->key[1]);
    AES_ROUND_X4(cipher, ctx->key[2]);
    AES_ROUND_X4(cipher, ctx->key[3]);
    AES_ROUND_X4(cipher, ctx->key[4]);
aes_128:
    // 11 rounds
    AES_ROUND_X4(cipher, ctx->key[5]);
    AES_ROUND_X4(cipher, ctx->key[6]);
    AES_ROUND_X4(cipher, ctx->key[7]);
    AES_ROUND_X4(cipher, ctx->key[8]);
    AES_ROUND_X4(cipher, ctx->key[9]);
    AES_ROUND_X4(cipher, ctx->key[10]);
    AES_ROUND_X4(cipher, ctx->key[11]);
    AES_ROUND_X4(cipher, ctx->key[12]);
    AES_ROUND_X4(cipher, ctx->key[13]);

    // Last round
    AES_LAST_ROUND_X4(cipher, ctx->key[14]);
}

#endif /* TARGET_PLATFORM_X86_64 */
