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

#include "aes_arm64.h"

#ifdef TARGET_PLATFORM_ARM64

#include <string.h>

#include "utils.h"

#if __GNUC__ && !__clang__
#define CRYPTO __attribute__((target("+crypto")))
#else
#define CRYPTO
#endif

#define AES_BLOCK_SIZE_X4      (AES_BLOCK_SIZE * 4)

#define ADD(a, b)              vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8((a)), (b)))
#define KEY_EXP_256_1(k, i, r) XOR3(TSHIFT_ADD((k)[(i)]), SUBWORD(ROTWORD((k)[(i) + 1])), RCON((r)))
#define KEY_EXP_128(k, i, r)   XOR3(TSHIFT_ADD((k)[(i)]), SUBWORD(ROTWORD((k)[(i)])), RCON((r)))
#define KEY_EXP_256_2(k, i)    XOR(TSHIFT_ADD((k)[(i)]), SUBWORD(NOROTWORD((k)[(i) + 1])))
#define NOROTWORD(a)           vqtbl1q_u8((a), vreinterpretq_u8_u32(vdupq_n_u32(0x0f0e0d0c)))
#define RCON(a)                vreinterpretq_u8_u32(vdupq_n_u32((a)))
#define ROTWORD(a)             vqtbl1q_u8((a), vreinterpretq_u8_u32(vdupq_n_u32(0x0c0f0e0d)))
#define SHIFT_ADD(a)           veorq_u8((a), vextq_u8(vdupq_n_u8(0x00), (a), 12))
#define SUBWORD(a)             vaeseq_u8((a), vdupq_n_u8(0x00))
#define TSHIFT_ADD(a)          SHIFT_ADD(SHIFT_ADD(SHIFT_ADD((a))))
#define UINT32x4_C(a)          vextq_u32(vdupq_n_u32((a)), vdupq_n_u32(0x00000000), 3);
#define XOR(a, b)              veorq_u8((a), (b))
#define XOR3(a, b, c)          veorq_u8((a), veorq_u8((b), (c)))

#define AES_ROUND(b, k)                                                                            \
    do {                                                                                           \
        (b) = vaeseq_u8((b), (k));                                                                 \
        (b) = vaesmcq_u8((b));                                                                     \
    } while (0)

#define AES_LAST_ROUND(b, k0, k1)                                                                  \
    do {                                                                                           \
        (b) = vaeseq_u8((b), (k0));                                                                \
        (b) = veorq_u8((b), (k1));                                                                 \
    } while (0)

#define AES_ROUND_X2(b, k)                                                                         \
    do {                                                                                           \
        (b).val[0] = vaeseq_u8((b).val[0], (k));                                                   \
        (b).val[1] = vaeseq_u8((b).val[1], (k));                                                   \
        (b).val[0] = vaesmcq_u8((b).val[0]);                                                       \
        (b).val[1] = vaesmcq_u8((b).val[1]);                                                       \
    } while (0)

#define AES_LAST_ROUND_X2(b, k0, k1)                                                               \
    do {                                                                                           \
        (b).val[0] = vaeseq_u8((b).val[0], (k0));                                                  \
        (b).val[1] = vaeseq_u8((b).val[1], (k0));                                                  \
        (b).val[0] = veorq_u8((b).val[0], (k1));                                                   \
        (b).val[1] = veorq_u8((b).val[1], (k1));                                                   \
    } while (0)

#define AES_ROUND_X3(b, k)                                                                         \
    do {                                                                                           \
        (b).val[0] = vaeseq_u8((b).val[0], (k));                                                   \
        (b).val[1] = vaeseq_u8((b).val[1], (k));                                                   \
        (b).val[2] = vaeseq_u8((b).val[2], (k));                                                   \
        (b).val[0] = vaesmcq_u8((b).val[0]);                                                       \
        (b).val[1] = vaesmcq_u8((b).val[1]);                                                       \
        (b).val[2] = vaesmcq_u8((b).val[2]);                                                       \
    } while (0)

#define AES_LAST_ROUND_X3(b, k0, k1)                                                               \
    do {                                                                                           \
        (b).val[0] = vaeseq_u8((b).val[0], (k0));                                                  \
        (b).val[1] = vaeseq_u8((b).val[1], (k0));                                                  \
        (b).val[2] = vaeseq_u8((b).val[2], (k0));                                                  \
        (b).val[0] = veorq_u8((b).val[0], (k1));                                                   \
        (b).val[1] = veorq_u8((b).val[1], (k1));                                                   \
        (b).val[2] = veorq_u8((b).val[2], (k1));                                                   \
    } while (0)

#define AES_ROUND_X4(b, k)                                                                         \
    do {                                                                                           \
        (b).val[0] = vaeseq_u8((b).val[0], (k));                                                   \
        (b).val[1] = vaeseq_u8((b).val[1], (k));                                                   \
        (b).val[2] = vaeseq_u8((b).val[2], (k));                                                   \
        (b).val[3] = vaeseq_u8((b).val[3], (k));                                                   \
        (b).val[0] = vaesmcq_u8((b).val[0]);                                                       \
        (b).val[1] = vaesmcq_u8((b).val[1]);                                                       \
        (b).val[2] = vaesmcq_u8((b).val[2]);                                                       \
        (b).val[3] = vaesmcq_u8((b).val[3]);                                                       \
    } while (0)

#define AES_LAST_ROUND_X4(b, k0, k1)                                                               \
    do {                                                                                           \
        (b).val[0] = vaeseq_u8((b).val[0], (k0));                                                  \
        (b).val[1] = vaeseq_u8((b).val[1], (k0));                                                  \
        (b).val[2] = vaeseq_u8((b).val[2], (k0));                                                  \
        (b).val[3] = vaeseq_u8((b).val[3], (k0));                                                  \
        (b).val[0] = veorq_u8((b).val[0], (k1));                                                   \
        (b).val[1] = veorq_u8((b).val[1], (k1));                                                   \
        (b).val[2] = veorq_u8((b).val[2], (k1));                                                   \
        (b).val[3] = veorq_u8((b).val[3], (k1));                                                   \
    } while (0)

static inline uint8x16_t aes_encrypt(struct aes_arm64 *ctx, uint8x16_t input);
static inline uint8x16x4_t aes_encrypt_x2(struct aes_arm64 *ctx, uint8x16x4_t block);
static inline uint8x16x4_t aes_encrypt_x3(struct aes_arm64 *ctx, uint8x16x4_t block);
static inline uint8x16x4_t aes_encrypt_x4(struct aes_arm64 *ctx, uint8x16x4_t block);

CRYPTO
void aes_arm64_init(struct aes_arm64 *ctx)
{
    if (NULL == ctx) {
        return;
    }

    memset(ctx, 0x00, sizeof(*ctx));
}

CRYPTO
void aes_arm64_free(struct aes_arm64 *ctx)
{
    if (NULL == ctx) {
        return;
    }

    aes_gcmsiv_zeroize(ctx, sizeof(*ctx));
}

CRYPTO
aes_gcmsiv_status_t aes_arm64_set_key(struct aes_arm64 *ctx, const uint8_t *key, size_t key_sz)
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
        ctx->key[4] = vld1q_u8(key);
        ctx->key[5] = KEY_EXP_128(ctx->key, 4, 0x01);
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
        ctx->key[0] = vld1q_u8(key);
        ctx->key[1] = vld1q_u8(key + 16);
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

CRYPTO
aes_gcmsiv_status_t aes_arm64_ecb_encrypt(struct aes_arm64 *ctx,
                                          const uint8_t plain[AES_BLOCK_SIZE],
                                          uint8_t cipher[AES_BLOCK_SIZE])
{
    uint8x16_t block;

    if (NULL == ctx || NULL == plain || NULL == cipher) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    block = vld1q_u8(plain);
    block = aes_encrypt(ctx, block);
    vst1q_u8(cipher, block);

    return AES_GCMSIV_SUCCESS;
}

CRYPTO
aes_gcmsiv_status_t aes_arm64_ctr(struct aes_arm64 *ctx,
                                  const uint8_t nonce[AES_BLOCK_SIZE],
                                  const uint8_t *input,
                                  size_t input_sz,
                                  uint8_t *output)
{
    const uint32x4_t one = UINT32x4_C(1);
    const uint32x4_t four = UINT32x4_C(4);
    uint8x16x4_t counter;
    union {
        uint8x16x4_t x4;
        uint8x16x3_t x3;
        uint8x16x2_t x2;
        uint8x16_t x1;
    } block;
    size_t num_blocks;
    struct {
        uint8x16x4_t stream;
        uint8_t tmp[AES_BLOCK_SIZE];
    } stack;

    if (NULL == ctx || ((NULL == input || NULL == output) && 0 != input_sz)) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    // Set nonce
    counter.val[0] = vld1q_u8(nonce);
    counter.val[1] = ADD(counter.val[0], one);
    counter.val[2] = ADD(counter.val[1], one);
    counter.val[3] = ADD(counter.val[2], one);

    // Process 4 blocks at a time
    while (input_sz >= AES_BLOCK_SIZE_X4) {
        stack.stream = aes_encrypt_x4(ctx, counter);
        counter.val[0] = ADD(counter.val[0], four);
        counter.val[1] = ADD(counter.val[1], four);
        counter.val[2] = ADD(counter.val[2], four);
        counter.val[3] = ADD(counter.val[3], four);

        block.x4 = vld1q_u8_x4(input);
        block.x4.val[0] = XOR(block.x4.val[0], stack.stream.val[0]);
        block.x4.val[1] = XOR(block.x4.val[1], stack.stream.val[1]);
        block.x4.val[2] = XOR(block.x4.val[2], stack.stream.val[2]);
        block.x4.val[3] = XOR(block.x4.val[3], stack.stream.val[3]);
        vst1q_u8_x4(output, block.x4);

        input += AES_BLOCK_SIZE_X4;
        output += AES_BLOCK_SIZE_X4;
        input_sz -= AES_BLOCK_SIZE_X4;
    }

    // From this point, there are less than 4 full blocks, and the nonce is already updated
    if (input_sz > 0) {
        num_blocks = input_sz / AES_BLOCK_SIZE;

        // Process the remaining 1, 2, or 3 blocks at once
        switch (num_blocks) {
        case 0:
            stack.stream.val[0] = aes_encrypt(ctx, counter.val[0]);
            break;
        case 1:
            stack.stream = aes_encrypt_x2(ctx, counter);

            block.x1 = vld1q_u8(input);
            block.x1 = XOR(block.x1, stack.stream.val[0]);
            vst1q_u8(output, block.x1);
            break;
        case 2:
            stack.stream = aes_encrypt_x3(ctx, counter);

            block.x2 = vld1q_u8_x2(input);
            block.x2.val[0] = XOR(block.x2.val[0], stack.stream.val[0]);
            block.x2.val[1] = XOR(block.x2.val[1], stack.stream.val[1]);
            vst1q_u8_x2(output, block.x2);
            break;
        case 3:
            stack.stream = aes_encrypt_x4(ctx, counter);

            block.x3 = vld1q_u8_x3(input);
            block.x3.val[0] = XOR(block.x3.val[0], stack.stream.val[0]);
            block.x3.val[1] = XOR(block.x3.val[1], stack.stream.val[1]);
            block.x3.val[2] = XOR(block.x3.val[2], stack.stream.val[2]);
            vst1q_u8_x3(output, block.x3);
            break;
        }

        input += AES_BLOCK_SIZE * num_blocks;
        output += AES_BLOCK_SIZE * num_blocks;
        input_sz -= AES_BLOCK_SIZE * num_blocks;

        // Process the remaining bytes
        if (input_sz > 0) {
            memset(stack.tmp, 0x00, sizeof(stack.tmp));
            memcpy(stack.tmp, input, input_sz);

            block.x1 = vld1q_u8(stack.tmp);
            block.x1 = XOR(block.x1, stack.stream.val[num_blocks]);
            vst1q_u8(stack.tmp, block.x1);

            memcpy(output, stack.tmp, input_sz);
        }
    }

    aes_gcmsiv_zeroize(&stack, sizeof(stack));

    return AES_GCMSIV_SUCCESS;
}

CRYPTO
uint8x16_t aes_encrypt(struct aes_arm64 *ctx, uint8x16_t block)
{
    switch (ctx->key_sz) {
    case 16:
        goto aes_128;
    case 32:
        goto aes_256;
    }

aes_256:
    AES_ROUND(block, ctx->key[0]);
    AES_ROUND(block, ctx->key[1]);
    AES_ROUND(block, ctx->key[2]);
    AES_ROUND(block, ctx->key[3]);
aes_128:
    AES_ROUND(block, ctx->key[4]);
    AES_ROUND(block, ctx->key[5]);
    AES_ROUND(block, ctx->key[6]);
    AES_ROUND(block, ctx->key[7]);
    AES_ROUND(block, ctx->key[8]);
    AES_ROUND(block, ctx->key[9]);
    AES_ROUND(block, ctx->key[10]);
    AES_ROUND(block, ctx->key[11]);
    AES_ROUND(block, ctx->key[12]);
    AES_LAST_ROUND(block, ctx->key[13], ctx->key[14]);

    return block;
}

CRYPTO
uint8x16x4_t aes_encrypt_x2(struct aes_arm64 *ctx, uint8x16x4_t block)
{
    switch (ctx->key_sz) {
    case 16:
        goto aes_128;
    case 32:
        goto aes_256;
    }

aes_256:
    AES_ROUND_X2(block, ctx->key[0]);
    AES_ROUND_X2(block, ctx->key[1]);
    AES_ROUND_X2(block, ctx->key[2]);
    AES_ROUND_X2(block, ctx->key[3]);
aes_128:
    AES_ROUND_X2(block, ctx->key[4]);
    AES_ROUND_X2(block, ctx->key[5]);
    AES_ROUND_X2(block, ctx->key[6]);
    AES_ROUND_X2(block, ctx->key[7]);
    AES_ROUND_X2(block, ctx->key[8]);
    AES_ROUND_X2(block, ctx->key[9]);
    AES_ROUND_X2(block, ctx->key[10]);
    AES_ROUND_X2(block, ctx->key[11]);
    AES_ROUND_X2(block, ctx->key[12]);
    AES_LAST_ROUND_X2(block, ctx->key[13], ctx->key[14]);

    return block;
}

CRYPTO
uint8x16x4_t aes_encrypt_x3(struct aes_arm64 *ctx, uint8x16x4_t block)
{
    switch (ctx->key_sz) {
    case 16:
        goto aes_128;
    case 32:
        goto aes_256;
    }

aes_256:
    AES_ROUND_X3(block, ctx->key[0]);
    AES_ROUND_X3(block, ctx->key[1]);
    AES_ROUND_X3(block, ctx->key[2]);
    AES_ROUND_X3(block, ctx->key[3]);
aes_128:
    AES_ROUND_X3(block, ctx->key[4]);
    AES_ROUND_X3(block, ctx->key[5]);
    AES_ROUND_X3(block, ctx->key[6]);
    AES_ROUND_X3(block, ctx->key[7]);
    AES_ROUND_X3(block, ctx->key[8]);
    AES_ROUND_X3(block, ctx->key[9]);
    AES_ROUND_X3(block, ctx->key[10]);
    AES_ROUND_X3(block, ctx->key[11]);
    AES_ROUND_X3(block, ctx->key[12]);
    AES_LAST_ROUND_X3(block, ctx->key[13], ctx->key[14]);

    return block;
}

CRYPTO
uint8x16x4_t aes_encrypt_x4(struct aes_arm64 *ctx, uint8x16x4_t block)
{
    switch (ctx->key_sz) {
    case 16:
        goto aes_128;
    case 32:
        goto aes_256;
    }

aes_256:
    AES_ROUND_X4(block, ctx->key[0]);
    AES_ROUND_X4(block, ctx->key[1]);
    AES_ROUND_X4(block, ctx->key[2]);
    AES_ROUND_X4(block, ctx->key[3]);
aes_128:
    AES_ROUND_X4(block, ctx->key[4]);
    AES_ROUND_X4(block, ctx->key[5]);
    AES_ROUND_X4(block, ctx->key[6]);
    AES_ROUND_X4(block, ctx->key[7]);
    AES_ROUND_X4(block, ctx->key[8]);
    AES_ROUND_X4(block, ctx->key[9]);
    AES_ROUND_X4(block, ctx->key[10]);
    AES_ROUND_X4(block, ctx->key[11]);
    AES_ROUND_X4(block, ctx->key[12]);
    AES_LAST_ROUND_X4(block, ctx->key[13], ctx->key[14]);

    return block;
}

#endif /* TARGET_PLATFORM_ARM64 */
