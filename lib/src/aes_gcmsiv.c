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

#include "aes_gcmsiv.h"

#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "utils.h"

#include "generic/aes_generic.h"
#include "generic/polyval_generic.h"

#ifdef TARGET_PLATFORM_ARM64
#include "arm64/aes_arm64.h"
#include "arm64/polyval_arm64.h"
#endif /* TARGET_PLATFORM_ARM64 */

#ifdef TARGET_PLATFORM_X86_64
#include "x86_64/aes_x86_64.h"
#include "x86_64/polyval_x86_64.h"
#endif /* TARGET_PLATFORM_X86_64 */

#define KEY_AUTH_SIZE    16
#define KEY_ENC_MAX_SIZE 32

#define LOCAL            static inline

struct key_context {
    uint8_t auth[KEY_AUTH_SIZE];
    size_t auth_sz;
    uint8_t enc[KEY_ENC_MAX_SIZE];
    size_t enc_sz;
};

struct aes {
    int has_hw;
    union {
        struct generic_aes_context mbedtls;
#ifdef TARGET_PLATFORM_ARM64
        struct aes_arm64 arm64;
#endif /* TARGET_PLATFORM_ARM64 */
#ifdef TARGET_PLATFORM_X86_64
        struct aes_x86_64 x86_64;
#endif /* TARGET_PLATFORM_X86_64 */
    } storage;
};

struct polyval {
    int has_hw;
    union {
        struct polyval_generic generic;
#ifdef TARGET_PLATFORM_ARM64
        struct polyval_arm64 arm64;
#endif /* TARGET_PLATFORM_ARM64 */
#ifdef TARGET_PLATFORM_X86_64
        struct polyval_x86_64 x86_64;
#endif /* TARGET_PLATFORM_X86_64 */
    } storage;
};

// GCM-SIV specific functions
LOCAL void aes_gcmsiv_derive_keys(struct aes *ctx,
                                  size_t key_sz,
                                  const uint8_t *nonce,
                                  struct key_context *key);
LOCAL void aes_gcmsiv_make_tag(const struct key_context *key,
                               const uint8_t *nonce,
                               const uint8_t *plain,
                               size_t plain_sz,
                               const uint8_t *aad,
                               size_t aad_sz,
                               uint8_t *tag);
LOCAL void aes_gcmsiv_aes_ctr(const uint8_t *key,
                              size_t key_sz,
                              const uint8_t tag[AES_GCMSIV_TAG_SIZE],
                              const uint8_t *input,
                              size_t input_sz,
                              uint8_t *output);
LOCAL aes_gcmsiv_status_t aes_gcmsiv_check_tag(const uint8_t lhs[AES_GCMSIV_TAG_SIZE],
                                               const uint8_t rhs[AES_GCMSIV_TAG_SIZE]);

// AES specific functions
LOCAL void aes_init(struct aes *ctx);
LOCAL void aes_free(struct aes *ctx);
LOCAL aes_gcmsiv_status_t aes_set_key(struct aes *ctx, const uint8_t *key, size_t key_sz);

LOCAL aes_gcmsiv_status_t aes_ecb_encrypt(struct aes *ctx,
                                          const uint8_t plain[AES_BLOCK_SIZE],
                                          uint8_t cipher[AES_BLOCK_SIZE]);
LOCAL aes_gcmsiv_status_t aes_ctr(struct aes *ctx,
                                  const uint8_t nonce[AES_BLOCK_SIZE],
                                  const uint8_t *input,
                                  size_t input_sz,
                                  uint8_t *output);

// Polyval specific functions
LOCAL void polyval_init(struct polyval *ctx);
LOCAL void polyval_free(struct polyval *ctx);
LOCAL aes_gcmsiv_status_t polyval_start(struct polyval *ctx, const uint8_t *key, size_t key_sz);
LOCAL aes_gcmsiv_status_t polyval_update(struct polyval *ctx, const uint8_t *data, size_t data_sz);
LOCAL aes_gcmsiv_status_t polyval_finish(struct polyval *ctx,
                                         const uint8_t *nonce,
                                         size_t nonce_sz,
                                         uint8_t tag[POLYVAL_SIZE]);

size_t aes_gcmsiv_context_size(void)
{
    return sizeof(struct aes_gcmsiv_ctx);
}

void aes_gcmsiv_init(struct aes_gcmsiv_ctx *ctx)
{
    if (NULL == ctx) {
        return;
    }

    ctx->key_gen_ctx = NULL;
    ctx->key_sz = 0;
}

void aes_gcmsiv_free(struct aes_gcmsiv_ctx *ctx)
{
    if (NULL == ctx) {
        return;
    }

    if (NULL != ctx->key_gen_ctx) {
        aes_free(ctx->key_gen_ctx);
        free(ctx->key_gen_ctx);
    }

    aes_gcmsiv_zeroize(ctx, sizeof(*ctx));
}

aes_gcmsiv_status_t aes_gcmsiv_set_key(struct aes_gcmsiv_ctx *ctx,
                                       const uint8_t *key,
                                       size_t key_sz)
{
    aes_gcmsiv_status_t res;
    struct aes *key_gen_ctx = NULL;

    // Check parameters
    if (NULL == ctx || NULL == key) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    // Check key size
    if (16 != key_sz && 32 != key_sz) {
        return AES_GCMSIV_INVALID_KEY_SIZE;
    }

    // Allocate and initialize new AES context
    key_gen_ctx = malloc(sizeof(*key_gen_ctx));
    if (NULL == key_gen_ctx) {
        return AES_GCMSIV_OUT_OF_MEMORY;
    }

    aes_init(key_gen_ctx);

    res = aes_set_key(key_gen_ctx, key, key_sz);
    if (AES_GCMSIV_SUCCESS != res) {
        aes_free(key_gen_ctx);
        free(key_gen_ctx);
        return res;
    }

    // Free existing AES context
    if (NULL != ctx->key_gen_ctx) {
        aes_free(ctx->key_gen_ctx);
        free(ctx->key_gen_ctx);
    }

    ctx->key_gen_ctx = key_gen_ctx;
    ctx->key_sz = key_sz;

    return AES_GCMSIV_SUCCESS;
}

aes_gcmsiv_status_t aes_gcmsiv_encrypt_size(size_t plain_sz, size_t aad_sz, size_t *cipher_sz)
{
    size_t needed_sz;

    if (NULL == cipher_sz) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

#if SIZE_MAX > UINT32_MAX
    // Check that plaintext size is less than 2^36
    if (plain_sz > AES_GCMSIV_MAX_PLAINTEXT_SIZE) {
        return AES_GCMSIV_INVALID_PLAINTEXT_SIZE;
    }

    // Check that aad size is less than 2^36
    if (aad_sz > AES_GCMSIV_MAX_AAD_SIZE) {
        return AES_GCMSIV_INVALID_AAD_SIZE;
    }
#else
    ((void)aad_sz);
#endif /* SIZE_MAX > UINT32_MAX */

    // Compute needed output size
    needed_sz = plain_sz + AES_GCMSIV_TAG_SIZE;

    // Check for Integer overflow
    if (needed_sz < plain_sz) {
        return AES_GCMSIV_INVALID_PLAINTEXT_SIZE;
    }

    *cipher_sz = needed_sz;

    return AES_GCMSIV_SUCCESS;
}

aes_gcmsiv_status_t aes_gcmsiv_encrypt_with_tag(struct aes_gcmsiv_ctx *ctx,
                                                const uint8_t *nonce,
                                                size_t nonce_sz,
                                                const uint8_t *plain,
                                                size_t plain_sz,
                                                const uint8_t *aad,
                                                size_t aad_sz,
                                                uint8_t *cipher,
                                                size_t cipher_sz,
                                                size_t *write_sz)
{
    aes_gcmsiv_status_t ret = AES_GCMSIV_FAILURE;
    aes_gcmsiv_status_t res;
    size_t needed_sz = 0;
    struct key_context key;
    uint8_t *tag = NULL;

    // Check if required parameters are NULL
    if (NULL == ctx || (NULL == nonce && 0 != nonce_sz) || (NULL == plain && 0 != plain_sz) ||
        (NULL == aad && 0 != aad_sz) || (NULL == cipher && 0 != cipher_sz) || NULL == write_sz) {
        ret = AES_GCMSIV_INVALID_PARAMETERS;
        goto cleanup;
    }

    // Check that nonce has the correct size
    if (AES_GCMSIV_NONCE_SIZE != nonce_sz) {
        ret = AES_GCMSIV_INVALID_NONCE_SIZE;
        goto cleanup;
    }

    // Compute needed output size
    res = aes_gcmsiv_encrypt_size(plain_sz, aad_sz, &needed_sz);
    if (AES_GCMSIV_SUCCESS != res) {
        ret = res;
        goto cleanup;
    }

    // Update needed size and return to caller
    if (cipher_sz < needed_sz) {
        *write_sz = needed_sz;
        ret = AES_GCMSIV_UPDATE_OUTPUT_SIZE;
        goto cleanup;
    }

    // Derivate message authentication key and message encryption key
    aes_gcmsiv_derive_keys(ctx->key_gen_ctx, ctx->key_sz, nonce, &key);

    // Compute tag (tag is written directly to cipher)
    tag = cipher + plain_sz;
    aes_gcmsiv_make_tag(&key, nonce, plain, plain_sz, aad, aad_sz, tag);

    // Perform encryption
    aes_gcmsiv_aes_ctr(key.enc, key.enc_sz, tag, plain, plain_sz, cipher);

    // Update output size
    *write_sz = needed_sz;

    ret = AES_GCMSIV_SUCCESS;
cleanup:
    // Cleanup resources
    aes_gcmsiv_zeroize(&key, sizeof(key));

    return ret;
}

aes_gcmsiv_status_t aes_gcmsiv_decrypt_size(size_t cipher_sz, size_t aad_sz, size_t *plain_sz)
{
    size_t needed_sz;

    if (NULL == plain_sz) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    // Check that ciphertext is at least tag size
    if (cipher_sz < AES_GCMSIV_TAG_SIZE) {
        return AES_GCMSIV_INVALID_CIPHERTEXT_SIZE;
    }

    // Cannot undeflow anymore
    needed_sz = cipher_sz - AES_GCMSIV_TAG_SIZE;

#if SIZE_MAX > UINT32_MAX
    // Check that plaintext size is less than 2^36
    if (needed_sz > AES_GCMSIV_MAX_PLAINTEXT_SIZE) {
        return AES_GCMSIV_INVALID_CIPHERTEXT_SIZE;
    }

    // Check that aad size is less than 2^36
    if (aad_sz > AES_GCMSIV_MAX_AAD_SIZE) {
        return AES_GCMSIV_INVALID_AAD_SIZE;
    }
#else
    ((void)aad_sz);
#endif /* SIZE_MAX > UINT32_MAX */

    *plain_sz = needed_sz;

    return AES_GCMSIV_SUCCESS;
}

aes_gcmsiv_status_t aes_gcmsiv_decrypt_and_check(struct aes_gcmsiv_ctx *ctx,
                                                 const uint8_t *nonce,
                                                 size_t nonce_sz,
                                                 const uint8_t *cipher,
                                                 size_t cipher_sz,
                                                 const uint8_t *aad,
                                                 size_t aad_sz,
                                                 uint8_t *plain,
                                                 size_t plain_sz,
                                                 size_t *write_sz)
{
    aes_gcmsiv_status_t ret = AES_GCMSIV_FAILURE;
    aes_gcmsiv_status_t res;
    size_t needed_sz = 0;
    struct key_context key;
    const uint8_t *expected_tag = NULL;
    uint8_t tag[AES_GCMSIV_TAG_SIZE];

    // Check if required parameters are NULL
    if (NULL == ctx || (NULL == nonce && 0 != nonce_sz) || (NULL == cipher && 0 != cipher_sz) ||
        (NULL == aad && 0 != aad_sz) || (NULL == plain && 0 != plain_sz) || NULL == write_sz) {
        ret = AES_GCMSIV_INVALID_PARAMETERS;
        goto cleanup;
    }

    // Check that nonce has the correct size
    if (AES_GCMSIV_NONCE_SIZE != nonce_sz) {
        ret = AES_GCMSIV_INVALID_NONCE_SIZE;
        goto cleanup;
    }

    // Compute needed output size
    res = aes_gcmsiv_decrypt_size(cipher_sz, aad_sz, &needed_sz);
    if (AES_GCMSIV_SUCCESS != res) {
        ret = res;
        goto cleanup;
    }

    // Update needed size and return to caller
    if (plain_sz < needed_sz) {
        *write_sz = needed_sz;
        ret = AES_GCMSIV_UPDATE_OUTPUT_SIZE;
        goto cleanup;
    }

    // Derivate message authentication key and message encryption key
    aes_gcmsiv_derive_keys(ctx->key_gen_ctx, ctx->key_sz, nonce, &key);

    // Perform decryption
    expected_tag = cipher + (cipher_sz - AES_GCMSIV_TAG_SIZE);
    aes_gcmsiv_aes_ctr(key.enc, key.enc_sz, expected_tag, cipher, needed_sz, plain);

    // Compute tag (tag is written directly to cipher)
    aes_gcmsiv_make_tag(&key, nonce, plain, needed_sz, aad, aad_sz, tag);

    // Compare actual tag and expected tag, and nullify plaintext if there is a corruption
    res = aes_gcmsiv_check_tag(tag, expected_tag);
    if (AES_GCMSIV_SUCCESS != res) {
        memset(plain, 0x00, needed_sz);
        *write_sz = 0;

        ret = res;
        goto cleanup;
    }

    // Update output size
    *write_sz = needed_sz;

    ret = AES_GCMSIV_SUCCESS;
cleanup:
    // Cleanup resources
    aes_gcmsiv_zeroize(&key, sizeof(key));

    return ret;
}

const char *aes_gcmsiv_get_status_code_msg(aes_gcmsiv_status_t status)
{
    switch (status) {
    case AES_GCMSIV_SUCCESS:
        return "Success";
    case AES_GCMSIV_FAILURE:
        return "Failure";
    case AES_GCMSIV_OUT_OF_MEMORY:
        return "Out of memory";
    case AES_GCMSIV_UPDATE_OUTPUT_SIZE:
        return "Update output size";
    case AES_GCMSIV_INVALID_PARAMETERS:
        return "Invalid parameters";
    case AES_GCMSIV_INVALID_KEY_SIZE:
        return "Unsupported key size";
    case AES_GCMSIV_INVALID_NONCE_SIZE:
        return "Invalid nonce size";
    case AES_GCMSIV_INVALID_PLAINTEXT_SIZE:
        return "Invalid plaintext size";
    case AES_GCMSIV_INVALID_AAD_SIZE:
        return "Invalid additional authenticated data size";
    case AES_GCMSIV_INVALID_CIPHERTEXT_SIZE:
        return "Invalid ciphertext size";
    case AES_GCMSIV_INVALID_TAG:
        return "Invalid tag";
    default:
        return "Unknown error";
    }
}

/*
 * Polyval specific function implementation
 */

void aes_gcmsiv_derive_keys(struct aes *ctx,
                            size_t key_sz,
                            const uint8_t *nonce,
                            struct key_context *key)
{
    struct {
        uint8_t input[AES_BLOCK_SIZE];
        uint8_t output[AES_BLOCK_SIZE];
    } stack;

    // Set keys size
    key->auth_sz = KEY_AUTH_SIZE;
    key->enc_sz = key_sz;

    // Set nonce on the second part of the input block
    memcpy(stack.input + sizeof(uint32_t), nonce, AES_GCMSIV_NONCE_SIZE);

    // Derive message authentication key
    PUT_UINT32_LE(0, stack.input, 0);
    aes_ecb_encrypt(ctx, stack.input, stack.output);
    memcpy(key->auth, stack.output, 8);

    PUT_UINT32_LE(1, stack.input, 0);
    aes_ecb_encrypt(ctx, stack.input, stack.output);
    memcpy(key->auth + 8, stack.output, 8);

    // Derive message encryption key
    PUT_UINT32_LE(2, stack.input, 0);
    aes_ecb_encrypt(ctx, stack.input, stack.output);
    memcpy(key->enc, stack.output, 8);

    PUT_UINT32_LE(3, stack.input, 0);
    aes_ecb_encrypt(ctx, stack.input, stack.output);
    memcpy(key->enc + 8, stack.output, 8);

    // Finish if AES-128
    if (16 == key_sz) {
        goto cleanup;
    }

    // Continue if AES-256
    PUT_UINT32_LE(4, stack.input, 0);
    aes_ecb_encrypt(ctx, stack.input, stack.output);
    memcpy(key->enc + 16, stack.output, 8);

    PUT_UINT32_LE(5, stack.input, 0);
    aes_ecb_encrypt(ctx, stack.input, stack.output);
    memcpy(key->enc + 24, stack.output, 8);

cleanup:
    aes_gcmsiv_zeroize(&stack, sizeof(stack));
}

void aes_gcmsiv_make_tag(const struct key_context *key,
                         const uint8_t *nonce,
                         const uint8_t *plain,
                         size_t plain_sz,
                         const uint8_t *aad,
                         size_t aad_sz,
                         uint8_t *tag)
{
    struct aes ctx;
    struct polyval polyval;
    uint64_t aad_bit_sz;
    uint64_t plain_bit_sz;
    uint8_t length_block[AES_GCMSIV_TAG_SIZE];

    aes_init(&ctx);
    polyval_init(&polyval);

    aes_set_key(&ctx, key->enc, key->enc_sz);

    // Create length block
    aad_bit_sz = ((uint64_t)aad_sz) * 8;
    PUT_UINT64_LE(aad_bit_sz, length_block, 0);

    plain_bit_sz = ((uint64_t)plain_sz) * 8;
    PUT_UINT64_LE(plain_bit_sz, length_block, 8);

    // Generate lookup tables for fast multiplication
    polyval_start(&polyval, key->auth, key->auth_sz);

    // Compute Polyval
    polyval_update(&polyval, aad, aad_sz);
    polyval_update(&polyval, plain, plain_sz);
    polyval_update(&polyval, length_block, sizeof(length_block));

    // Xor result and nonce
    polyval_finish(&polyval, nonce, AES_GCMSIV_NONCE_SIZE, tag);
    tag[15] &= 0x7f;

    // Encrypt result to produce tag
    aes_ecb_encrypt(&ctx, tag, tag);

    // Cleanup resources
    aes_free(&ctx);
    polyval_free(&polyval);
}

void aes_gcmsiv_aes_ctr(const uint8_t *key,
                        size_t key_sz,
                        const uint8_t tag[AES_GCMSIV_TAG_SIZE],
                        const uint8_t *input,
                        size_t input_sz,
                        uint8_t *output)
{
    struct aes ctx;
    uint8_t nonce[AES_BLOCK_SIZE];

    // Initialize AES context
    aes_init(&ctx);
    aes_set_key(&ctx, key, key_sz);

    // Create nonce
    memcpy(nonce, tag, sizeof(nonce));
    nonce[sizeof(nonce) - 1] |= 0x80;

    // Encrypt
    aes_ctr(&ctx, nonce, input, input_sz, output);

    // Cleanup resources
    aes_free(&ctx);
}

aes_gcmsiv_status_t aes_gcmsiv_check_tag(const uint8_t lhs[AES_GCMSIV_TAG_SIZE],
                                         const uint8_t rhs[AES_GCMSIV_TAG_SIZE])
{
    uint8_t sum = 0;

    for (size_t i = 0; i < AES_GCMSIV_TAG_SIZE; ++i) {
        sum |= lhs[i] ^ rhs[i];
    }

    return 0 == sum ? AES_GCMSIV_SUCCESS : AES_GCMSIV_INVALID_TAG;
}

/*
 * AES specific function implementation
 */

void aes_init(struct aes *ctx)
{
    memset(ctx, 0x00, sizeof(*ctx));
    ctx->has_hw = aes_gcmsiv_has_feature(HW_FEATURE_AES);

#ifdef TARGET_PLATFORM_ARM64
    if (ctx->has_hw) {
        return aes_arm64_init(&ctx->storage.arm64);
    }
#endif /* TARGET_PLATFORM_ARM64 */

#ifdef TARGET_PLATFORM_X86_64
    if (ctx->has_hw) {
        return aes_x86_64_init(&ctx->storage.x86_64);
    }
#endif /* TARGET_PLATFORM_X86_64 */

    return generic_aes_init(&ctx->storage.mbedtls);
}

void aes_free(struct aes *ctx)
{
#ifdef TARGET_PLATFORM_ARM64
    if (ctx->has_hw) {
        aes_arm64_free(&ctx->storage.arm64);
        aes_gcmsiv_zeroize(ctx, sizeof(*ctx));
        return;
    }
#endif /* TARGET_PLATFORM_ARM64 */

#ifdef TARGET_PLATFORM_X86_64
    if (ctx->has_hw) {
        aes_x86_64_free(&ctx->storage.x86_64);
        aes_gcmsiv_zeroize(ctx, sizeof(*ctx));
        return;
    }
#endif /* TARGET_PLATFORM_X86_64 */

    generic_aes_free(&ctx->storage.mbedtls);
    aes_gcmsiv_zeroize(ctx, sizeof(*ctx));
}

aes_gcmsiv_status_t aes_set_key(struct aes *ctx, const uint8_t *key, size_t key_sz)
{
#ifdef TARGET_PLATFORM_ARM64
    if (ctx->has_hw) {
        return aes_arm64_set_key(&ctx->storage.arm64, key, key_sz);
    }
#endif /* TARGET_PLATFORM_ARM64 */

#ifdef TARGET_PLATFORM_X86_64
    if (ctx->has_hw) {
        return aes_x86_64_set_key(&ctx->storage.x86_64, key, key_sz);
    }
#endif /* TARGET_PLATFORM_X86_64 */

    return generic_aes_setkey_enc(&ctx->storage.mbedtls, key, key_sz);
}

aes_gcmsiv_status_t aes_ecb_encrypt(struct aes *ctx,
                                    const uint8_t plain[AES_BLOCK_SIZE],
                                    uint8_t cipher[AES_BLOCK_SIZE])
{
#ifdef TARGET_PLATFORM_ARM64
    if (ctx->has_hw) {
        return aes_arm64_ecb_encrypt(&ctx->storage.arm64, plain, cipher);
    }
#endif /* TARGET_PLATFORM_ARM64 */

#ifdef TARGET_PLATFORM_X86_64
    if (ctx->has_hw) {
        return aes_x86_64_ecb_encrypt(&ctx->storage.x86_64, plain, cipher);
    }
#endif /* TARGET_PLATFORM_X86_64 */

    return generic_aes_crypt_ecb(&ctx->storage.mbedtls, plain, cipher);
}

aes_gcmsiv_status_t aes_ctr(struct aes *ctx,
                            const uint8_t nonce[AES_BLOCK_SIZE],
                            const uint8_t *input,
                            size_t input_sz,
                            uint8_t *output)
{
#ifdef TARGET_PLATFORM_ARM64
    if (ctx->has_hw) {
        return aes_arm64_ctr(&ctx->storage.arm64, nonce, input, input_sz, output);
    }
#endif /* TARGET_PLATFORM_ARM64 */

#ifdef TARGET_PLATFORM_X86_64
    if (ctx->has_hw) {
        return aes_x86_64_ctr(&ctx->storage.x86_64, nonce, input, input_sz, output);
    }
#endif /* TARGET_PLATFORM_X86_64 */

    return generic_aes_crypt_ctr(&ctx->storage.mbedtls, nonce, input, input_sz, output);
}

/*
 * Polyval specific function implementation
 */

void polyval_init(struct polyval *ctx)
{
    memset(ctx, 0x00, sizeof(*ctx));
    ctx->has_hw = aes_gcmsiv_has_feature(HW_FEATURE_POLYVAL);
}

void polyval_free(struct polyval *ctx)
{
    aes_gcmsiv_zeroize(ctx, sizeof(*ctx));
}

aes_gcmsiv_status_t polyval_start(struct polyval *ctx, const uint8_t *key, size_t key_sz)
{
#ifdef TARGET_PLATFORM_ARM64
    if (ctx->has_hw) {
        return polyval_arm64_start(&ctx->storage.arm64, key, key_sz);
    }
#endif /* TARGET_PLATFORM_ARM64 */

#ifdef TARGET_PLATFORM_X86_64
    if (ctx->has_hw) {
        return polyval_x86_64_start(&ctx->storage.x86_64, key, key_sz);
    }
#endif /* TARGET_PLATFORM_X86_64 */

    return polyval_generic_start(&ctx->storage.generic, key, key_sz);
}

aes_gcmsiv_status_t polyval_update(struct polyval *ctx, const uint8_t *data, size_t data_sz)
{
#ifdef TARGET_PLATFORM_ARM64
    if (ctx->has_hw) {
        return polyval_arm64_update(&ctx->storage.arm64, data, data_sz);
    }
#endif /* TARGET_PLATFORM_ARM64 */

#ifdef TARGET_PLATFORM_X86_64
    if (ctx->has_hw) {
        return polyval_x86_64_update(&ctx->storage.x86_64, data, data_sz);
    }
#endif /* TARGET_PLATFORM_X86_64 */

    return polyval_generic_update(&ctx->storage.generic, data, data_sz);
}

aes_gcmsiv_status_t polyval_finish(struct polyval *ctx,
                                   const uint8_t *nonce,
                                   size_t nonce_sz,
                                   uint8_t tag[POLYVAL_SIZE])
{
#ifdef TARGET_PLATFORM_ARM64
    if (ctx->has_hw) {
        return polyval_arm64_finish(&ctx->storage.arm64, nonce, nonce_sz, tag);
    }
#endif /* TARGET_PLATFORM_ARM64 */

#ifdef TARGET_PLATFORM_X86_64
    if (ctx->has_hw) {
        return polyval_x86_64_finish(&ctx->storage.x86_64, nonce, nonce_sz, tag);
    }
#endif /* TARGET_PLATFORM_X86_64 */

    return polyval_generic_finish(&ctx->storage.generic, nonce, nonce_sz, tag);
}
