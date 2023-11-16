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

#include "gtest/gtest.h"

#include "utils.h"

#include "aes_gcmsiv.h"

TEST(API, Constants)
{
    EXPECT_EQ(AES_GCMSIV_NONCE_SIZE, 12);
    EXPECT_EQ(AES_GCMSIV_TAG_SIZE, 16);
    EXPECT_EQ(AES_GCMSIV_MAX_PLAINTEXT_SIZE, UINT64_C(68719476736));
    EXPECT_EQ(AES_GCMSIV_MAX_AAD_SIZE, UINT64_C(68719476736));
}

TEST(API, ContextSize)
{
    size_t ctx_sz = aes_gcmsiv_context_size();
    EXPECT_EQ(ctx_sz, sizeof(struct aes_gcmsiv_ctx));
}

TEST(API, Init)
{
    struct aes_gcmsiv_ctx ctx;

    // Test with null ctx (test for memcheck ON)
    aes_gcmsiv_init(nullptr);

    // Test that fields are set to null
    ctx.key_gen_ctx = (void *)1;
    ctx.key_sz = 1;
    aes_gcmsiv_init(&ctx);
    EXPECT_EQ(ctx.key_gen_ctx, nullptr);
    EXPECT_EQ(ctx.key_sz, (size_t)0);
}

TEST(API, Free)
{
    aes_gcmsiv_status_t ret;
    struct aes_gcmsiv_ctx ctx;
    uint8_t key[16];
    size_t key_sz = sizeof(key);

    memset(key, 0x00, sizeof(key));

    // Test with null ctx (test for memcheck ON)
    aes_gcmsiv_free(nullptr);

    // Test without setting key
    aes_gcmsiv_init(&ctx);
    ctx.key_sz = 1;
    aes_gcmsiv_free(&ctx);
    EXPECT_EQ(ctx.key_gen_ctx, nullptr);
    EXPECT_EQ(ctx.key_sz, (size_t)0);

    // Test that structure is well free
    aes_gcmsiv_init(&ctx);
    ret = aes_gcmsiv_set_key(&ctx, key, key_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_NE(ctx.key_gen_ctx, nullptr);
    EXPECT_EQ(ctx.key_sz, key_sz);
    aes_gcmsiv_free(&ctx);
    EXPECT_EQ(ctx.key_gen_ctx, nullptr);
    EXPECT_EQ(ctx.key_sz, (size_t)0);
}

TEST(API, SetKey)
{
    aes_gcmsiv_status_t ret;
    struct aes_gcmsiv_ctx ctx;
    uint8_t key[32];

    memset(key, 0x00, sizeof(key));

    aes_gcmsiv_init(&ctx);

    // Test with null ctx
    ret = aes_gcmsiv_set_key(nullptr, key, 16);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PARAMETERS);
    EXPECT_EQ(ctx.key_gen_ctx, nullptr);
    EXPECT_EQ(ctx.key_sz, (size_t)0);

    // Test with null key
    ret = aes_gcmsiv_set_key(&ctx, nullptr, 16);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PARAMETERS);
    EXPECT_EQ(ctx.key_gen_ctx, nullptr);
    EXPECT_EQ(ctx.key_sz, (size_t)0);

    // Test with key size of 0
    ret = aes_gcmsiv_set_key(&ctx, key, 0);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_KEY_SIZE);
    EXPECT_EQ(ctx.key_gen_ctx, nullptr);
    EXPECT_EQ(ctx.key_sz, (size_t)0);

    // Test with key size neither 16 nor 32
    ret = aes_gcmsiv_set_key(&ctx, key, 24);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_KEY_SIZE);
    EXPECT_EQ(ctx.key_gen_ctx, nullptr);
    EXPECT_EQ(ctx.key_sz, (size_t)0);

    // Test when all goes well (key size of 16)
    ret = aes_gcmsiv_set_key(&ctx, key, 16);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    aes_gcmsiv_free(&ctx);
    aes_gcmsiv_init(&ctx);

    // Test when all goes well (key size of 32)
    ret = aes_gcmsiv_set_key(&ctx, key, 32);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    aes_gcmsiv_free(&ctx);
    aes_gcmsiv_init(&ctx);

    // Test to change key to a new key
    ret = aes_gcmsiv_set_key(&ctx, key, 16);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(ctx.key_sz, (size_t)16);
    ret = aes_gcmsiv_set_key(&ctx, key, 32);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(ctx.key_sz, (size_t)32);

    aes_gcmsiv_free(&ctx);
}

TEST(API, EncryptSize)
{
    aes_gcmsiv_status_t ret;
    size_t plain_sz = 16;
    size_t aad_sz = 16;
    size_t cipher_sz;

    // Null pointer
    ret = aes_gcmsiv_encrypt_size(plain_sz, aad_sz, nullptr);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PARAMETERS);

#if SIZE_MAX > UINT32_MAX
    // Test with plaintext size > 2^36
    ret = aes_gcmsiv_encrypt_size(AES_GCMSIV_MAX_PLAINTEXT_SIZE + 1, aad_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PLAINTEXT_SIZE);

    // Test with AAD size > 2^36
    ret = aes_gcmsiv_encrypt_size(plain_sz, AES_GCMSIV_MAX_AAD_SIZE + 1, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_AAD_SIZE);
#endif

#if SIZE_MAX <= UINT32_MAX
    // Test integer overflow on cipher_sz = plain_sz + tag_sz
    ret = aes_gcmsiv_encrypt_size(UINT32_MAX, aad_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PLAINTEXT_SIZE);
#endif

    // No plaintext, no AAD
    plain_sz = 0;
    aad_sz = 0;
    cipher_sz = 0;

    ret = aes_gcmsiv_encrypt_size(plain_sz, aad_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(cipher_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    // No plaintext, some AAD
    plain_sz = 0;
    aad_sz = 16;
    cipher_sz = 0;

    ret = aes_gcmsiv_encrypt_size(plain_sz, aad_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(cipher_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    // Some plaintext, no AAD
    plain_sz = 16;
    aad_sz = 0;
    cipher_sz = 0;

    ret = aes_gcmsiv_encrypt_size(plain_sz, aad_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(cipher_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    // Some plaintext, some AAD
    plain_sz = 16;
    aad_sz = 16;
    cipher_sz = 0;

    ret = aes_gcmsiv_encrypt_size(plain_sz, aad_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(cipher_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

#if SIZE_MAX > UINT32_MAX
    // Max plaintext size, some AAD
    plain_sz = AES_GCMSIV_MAX_PLAINTEXT_SIZE;
    aad_sz = 16;
    cipher_sz = 0;

    ret = aes_gcmsiv_encrypt_size(plain_sz, aad_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(cipher_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    // Some plaintext, max AAD size
    plain_sz = 16;
    aad_sz = AES_GCMSIV_MAX_AAD_SIZE;
    cipher_sz = 0;

    ret = aes_gcmsiv_encrypt_size(plain_sz, aad_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(cipher_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    // Max plaintext size, max AAD size
    plain_sz = AES_GCMSIV_MAX_PLAINTEXT_SIZE;
    aad_sz = AES_GCMSIV_MAX_AAD_SIZE;
    cipher_sz = 0;

    ret = aes_gcmsiv_encrypt_size(plain_sz, aad_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(cipher_sz, plain_sz + AES_GCMSIV_TAG_SIZE);
#endif
}

TEST(API, EncryptWithTag)
{
    aes_gcmsiv_status_t ret;
    struct aes_gcmsiv_ctx ctx;
    uint8_t key[16];
    size_t key_sz = sizeof(key);
    uint8_t nonce[AES_GCMSIV_NONCE_SIZE];
    size_t nonce_sz = sizeof(nonce);
    uint8_t aad[16];
    size_t aad_sz = sizeof(aad);
    uint8_t plain[16];
    size_t plain_sz = sizeof(plain);
    uint8_t cipher[sizeof(plain) + AES_GCMSIV_TAG_SIZE];
    size_t cipher_sz = sizeof(cipher);
    size_t write_sz;

    memset(key, 0x00, key_sz);
    memset(nonce, 0x01, nonce_sz);
    memset(aad, 0x02, aad_sz);
    memset(plain, 0x03, plain_sz);

    // Initialize context
    aes_gcmsiv_init(&ctx);

    ret = aes_gcmsiv_set_key(&ctx, key, key_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

    // No plaintext, no AAD
    plain_sz = 0;
    aad_sz = 0;

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, nullptr, 0, nullptr, 0, cipher,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(write_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(write_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    // No plaintext, some AAD
    plain_sz = 0;
    aad_sz = sizeof(aad);

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, nullptr, 0, aad, aad_sz, cipher,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(write_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(write_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    // Some plaintext, no AAD
    plain_sz = sizeof(plain);
    aad_sz = 0;

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, nullptr, 0, cipher,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(write_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(write_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    // Some plaintext, some AAD
    plain_sz = sizeof(plain);
    aad_sz = sizeof(aad);

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(write_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    aes_gcmsiv_free(&ctx);
}

TEST(API, EncryptWithTagUpdateSize)
{
    aes_gcmsiv_status_t ret;
    struct aes_gcmsiv_ctx ctx;
    uint8_t key[16];
    size_t key_sz = sizeof(key);
    uint8_t nonce[AES_GCMSIV_NONCE_SIZE];
    size_t nonce_sz = sizeof(nonce);
    uint8_t aad[16];
    size_t aad_sz = sizeof(aad);
    uint8_t plain[16];
    size_t plain_sz = sizeof(plain);
    uint8_t cipher[sizeof(plain) + AES_GCMSIV_TAG_SIZE + 1];
    size_t cipher_sz = sizeof(cipher);
    size_t write_sz;

    memset(key, 0x00, key_sz);
    memset(nonce, 0x01, nonce_sz);
    memset(aad, 0x02, aad_sz);
    memset(plain, 0x03, plain_sz);

    // Initialize context
    aes_gcmsiv_init(&ctx);

    ret = aes_gcmsiv_set_key(&ctx, key, key_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

    // Plaintext size is 0, ciphertext size is 0
    plain_sz = 0;
    cipher_sz = 0;

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_UPDATE_OUTPUT_SIZE);
    EXPECT_EQ(write_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    // Plaintext size is 0, ciphertext size is too small
    plain_sz = 0;
    cipher_sz = plain_sz + AES_GCMSIV_TAG_SIZE - 1;

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_UPDATE_OUTPUT_SIZE);
    EXPECT_EQ(write_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    // Plaintext size is 0, ciphertext size is correct
    plain_sz = 0;
    cipher_sz = plain_sz + AES_GCMSIV_TAG_SIZE;

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(write_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    // Plaintext size is 0, ciphertext size is too large
    plain_sz = 0;
    cipher_sz = plain_sz + AES_GCMSIV_TAG_SIZE + 1;

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(write_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    // Plaintext size is 16, ciphertext size is 0
    plain_sz = sizeof(plain);
    cipher_sz = 0;

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_UPDATE_OUTPUT_SIZE);
    EXPECT_EQ(write_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    // Plaintext size is 16, ciphertext size is too small
    plain_sz = sizeof(plain);
    cipher_sz = plain_sz + AES_GCMSIV_TAG_SIZE - 1;

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_UPDATE_OUTPUT_SIZE);
    EXPECT_EQ(write_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    // Plaintext size is 16, ciphertext size is correct
    plain_sz = sizeof(plain);
    cipher_sz = plain_sz + AES_GCMSIV_TAG_SIZE;

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(write_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    // Plaintext size is 16, ciphertext size is too big
    plain_sz = sizeof(plain);
    cipher_sz = plain_sz + AES_GCMSIV_TAG_SIZE + 1;

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(write_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    aes_gcmsiv_free(&ctx);
}

TEST(API, EncryptWithTagError)
{
    aes_gcmsiv_status_t ret;
    struct aes_gcmsiv_ctx ctx;
    uint8_t key[16];
    size_t key_sz = sizeof(key);
    uint8_t nonce[AES_GCMSIV_NONCE_SIZE];
    size_t nonce_sz = sizeof(nonce);
    uint8_t aad[16];
    size_t aad_sz = sizeof(aad);
    uint8_t plain[16];
    size_t plain_sz = sizeof(plain);
    uint8_t cipher[sizeof(plain) + AES_GCMSIV_TAG_SIZE];
    size_t cipher_sz = sizeof(cipher);
    size_t write_sz;

    memset(key, 0x00, key_sz);
    memset(nonce, 0x01, nonce_sz);
    memset(aad, 0x02, aad_sz);
    memset(plain, 0x03, plain_sz);

    // Initialize context
    aes_gcmsiv_init(&ctx);

    ret = aes_gcmsiv_set_key(&ctx, key, key_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

    // Test with null ctx
    ret = aes_gcmsiv_encrypt_with_tag(nullptr, nonce, nonce_sz, plain, plain_sz, aad, aad_sz,
                                      cipher, cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PARAMETERS);

    // Test with null nonce
    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nullptr, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PARAMETERS);

    // Test with invalid nonce size
    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, AES_GCMSIV_NONCE_SIZE - 1, plain, plain_sz, aad,
                                      aad_sz, cipher, cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_NONCE_SIZE);

    // Test with null plaintext but plaintext size != 0
    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, nullptr, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PARAMETERS);

#if SIZE_MAX > UINT32_MAX
    // Test with plaintext size > 2^36
    ret =
        aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, AES_GCMSIV_MAX_PLAINTEXT_SIZE + 1,
                                    aad, aad_sz, cipher, cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PLAINTEXT_SIZE);
#endif

#if SIZE_MAX <= UINT32_MAX
    // Test integer overflow on cipher_sz = plain_sz + tag_sz
    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain,
                                      SIZE_MAX - AES_GCMSIV_TAG_SIZE + 1, aad, aad_sz, cipher,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PLAINTEXT_SIZE);
#endif

    // Test with null AAD but AAD size != 0
    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, nullptr, aad_sz,
                                      cipher, cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PARAMETERS);

#if SIZE_MAX > UINT32_MAX
    // Test with AAD size > 2^36
    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad,
                                      AES_GCMSIV_MAX_AAD_SIZE + 1, cipher, cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_AAD_SIZE);
#endif

    // Test with null ciphertext
    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, nullptr,
                                      cipher_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PARAMETERS);

    // Test with ciphertext size of 0
    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      0, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_UPDATE_OUTPUT_SIZE);

    // Test with null write size
    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, nullptr);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PARAMETERS);

    aes_gcmsiv_free(&ctx);
}

TEST(API, DecryptSize)
{
    aes_gcmsiv_status_t ret;
    size_t cipher_sz = 16;
    size_t aad_sz = 16;
    size_t plain_sz = 0;

    // Null pointer
    ret = aes_gcmsiv_decrypt_size(cipher_sz, aad_sz, nullptr);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PARAMETERS);

    // Test with ciphertext size = 0
    ret = aes_gcmsiv_decrypt_size(0, aad_sz, &plain_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_CIPHERTEXT_SIZE);

    // Test with ciphertext size < tag size
    ret = aes_gcmsiv_decrypt_size(AES_GCMSIV_TAG_SIZE - 1, aad_sz, &plain_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_CIPHERTEXT_SIZE);

#if SIZE_MAX > UINT32_MAX
    // Test with plaintext size > 2^36
    ret = aes_gcmsiv_decrypt_size(AES_GCMSIV_MAX_PLAINTEXT_SIZE + AES_GCMSIV_TAG_SIZE + 1, aad_sz,
                                  &plain_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_CIPHERTEXT_SIZE);

    // Test with AAD size > 2^36
    ret = aes_gcmsiv_decrypt_size(cipher_sz, AES_GCMSIV_MAX_AAD_SIZE + 1, &plain_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_AAD_SIZE);
#endif

    // No plaintext, no AAD
    cipher_sz = AES_GCMSIV_TAG_SIZE;
    aad_sz = 0;
    plain_sz = 0;

    ret = aes_gcmsiv_decrypt_size(cipher_sz, aad_sz, &plain_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(plain_sz, cipher_sz - AES_GCMSIV_TAG_SIZE);

    // No plaintext, some AAD
    cipher_sz = AES_GCMSIV_TAG_SIZE;
    aad_sz = 16;
    plain_sz = 0;

    ret = aes_gcmsiv_decrypt_size(cipher_sz, aad_sz, &plain_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(plain_sz, cipher_sz - AES_GCMSIV_TAG_SIZE);

    // Some plaintext, no AAD
    cipher_sz = 16 + AES_GCMSIV_TAG_SIZE;
    aad_sz = 0;
    plain_sz = 0;

    ret = aes_gcmsiv_decrypt_size(cipher_sz, aad_sz, &plain_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(plain_sz, cipher_sz - AES_GCMSIV_TAG_SIZE);

    // Some plaintext, some AAD
    cipher_sz = 16 + AES_GCMSIV_TAG_SIZE;
    aad_sz = 16;
    plain_sz = 0;

    ret = aes_gcmsiv_decrypt_size(cipher_sz, aad_sz, &plain_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(plain_sz, cipher_sz - AES_GCMSIV_TAG_SIZE);

#if SIZE_MAX > UINT32_MAX
    // Max plaintext size, some AAD
    cipher_sz = AES_GCMSIV_MAX_PLAINTEXT_SIZE + AES_GCMSIV_TAG_SIZE;
    aad_sz = 16;
    plain_sz = 0;

    ret = aes_gcmsiv_decrypt_size(cipher_sz, aad_sz, &plain_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(plain_sz, cipher_sz - AES_GCMSIV_TAG_SIZE);

    // Some plaintext, max AAD size
    cipher_sz = 16 + AES_GCMSIV_TAG_SIZE;
    aad_sz = AES_GCMSIV_MAX_AAD_SIZE;
    plain_sz = 0;

    ret = aes_gcmsiv_decrypt_size(cipher_sz, aad_sz, &plain_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(plain_sz, cipher_sz - AES_GCMSIV_TAG_SIZE);

    // Max plaintext size, max AAD size
    cipher_sz = AES_GCMSIV_MAX_PLAINTEXT_SIZE + AES_GCMSIV_TAG_SIZE;
    aad_sz = AES_GCMSIV_MAX_AAD_SIZE;
    plain_sz = 0;

    ret = aes_gcmsiv_decrypt_size(cipher_sz, aad_sz, &plain_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(plain_sz, cipher_sz - AES_GCMSIV_TAG_SIZE);
#endif
}

TEST(API, DecryptAndCheck)
{
    aes_gcmsiv_status_t ret;
    struct aes_gcmsiv_ctx ctx;
    uint8_t key[16];
    size_t key_sz = sizeof(key);
    uint8_t nonce[AES_GCMSIV_NONCE_SIZE];
    size_t nonce_sz = sizeof(nonce);
    uint8_t aad[16];
    size_t aad_sz = sizeof(aad);
    uint8_t plain[16];
    size_t plain_sz = sizeof(plain);
    uint8_t cipher[sizeof(plain) + AES_GCMSIV_TAG_SIZE];
    size_t cipher_sz = sizeof(cipher);
    uint8_t decrypt[sizeof(plain)];
    size_t decrypt_sz = sizeof(decrypt);
    size_t write_sz;

    memset(key, 0x00, key_sz);
    memset(nonce, 0x01, nonce_sz);
    memset(aad, 0x02, aad_sz);
    memset(plain, 0x03, plain_sz);

    // Initialize context
    aes_gcmsiv_init(&ctx);

    ret = aes_gcmsiv_set_key(&ctx, key, key_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

    // No plaintext, no AAD
    plain_sz = 0;
    aad_sz = 0;
    cipher_sz = sizeof(cipher);

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, nullptr, 0,
                                       nullptr, 0, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(write_sz, (size_t)0);

    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_TRUE(memeq(decrypt, write_sz, plain, plain_sz));

    // No plaintext, some AAD
    plain_sz = 0;
    aad_sz = sizeof(aad);
    cipher_sz = sizeof(cipher);

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       nullptr, 0, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(write_sz, (size_t)0);

    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_TRUE(memeq(decrypt, write_sz, plain, plain_sz));

    // Some plaintext, no AAD
    plain_sz = sizeof(plain);
    aad_sz = 0;
    cipher_sz = sizeof(cipher);

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, nullptr, 0,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_TRUE(memeq(decrypt, write_sz, plain, plain_sz));

    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_TRUE(memeq(decrypt, write_sz, plain, plain_sz));

    // Some plaintext, some AAD
    plain_sz = sizeof(plain);
    aad_sz = sizeof(aad);
    cipher_sz = sizeof(cipher);

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_TRUE(memeq(decrypt, write_sz, plain, plain_sz));

    aes_gcmsiv_free(&ctx);
}

TEST(API, DecryptAndCheckUpdateSize)
{
    aes_gcmsiv_status_t ret;
    struct aes_gcmsiv_ctx ctx;
    uint8_t key[16];
    size_t key_sz = sizeof(key);
    uint8_t nonce[AES_GCMSIV_NONCE_SIZE];
    size_t nonce_sz = sizeof(nonce);
    uint8_t aad[16];
    size_t aad_sz = sizeof(aad);
    uint8_t plain[16];
    size_t plain_sz = sizeof(plain);
    uint8_t cipher[sizeof(plain) + AES_GCMSIV_TAG_SIZE];
    size_t cipher_sz = sizeof(cipher);
    uint8_t decrypt[sizeof(plain) + 1];
    size_t decrypt_sz = sizeof(decrypt);
    size_t write_sz;

    memset(key, 0x00, key_sz);
    memset(nonce, 0x01, nonce_sz);
    memset(aad, 0x02, aad_sz);
    memset(plain, 0x03, plain_sz);

    // Initialize context
    aes_gcmsiv_init(&ctx);

    ret = aes_gcmsiv_set_key(&ctx, key, key_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

    // Ciphertext size is 16, decrypttext is null
    plain_sz = 0;
    cipher_sz = sizeof(cipher);

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(cipher_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       nullptr, 0, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(write_sz, (size_t)0);

    // Ciphertext size is 16, decrypttext size is 0 (correct)
    plain_sz = 0;
    cipher_sz = sizeof(cipher);
    decrypt_sz = 0;

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(cipher_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(write_sz, plain_sz);

    // Ciphertext size is 16, decrypttext size is too large
    plain_sz = 0;
    cipher_sz = sizeof(cipher);
    decrypt_sz = plain_sz + 1;

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(cipher_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(write_sz, plain_sz);

    // Ciphertext size is 32, decrypttext size is 0
    plain_sz = 32 - AES_GCMSIV_TAG_SIZE;
    cipher_sz = sizeof(cipher);
    decrypt_sz = 0;

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(cipher_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_UPDATE_OUTPUT_SIZE);
    EXPECT_EQ(write_sz, plain_sz);

    // Ciphertext size is 32, decrypttext size is too small
    plain_sz = 32 - AES_GCMSIV_TAG_SIZE;
    cipher_sz = sizeof(cipher);
    decrypt_sz = plain_sz - 1;

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(cipher_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_UPDATE_OUTPUT_SIZE);
    EXPECT_EQ(write_sz, plain_sz);

    // Ciphertext size is 32, decrypttext size is correct
    plain_sz = 32 - AES_GCMSIV_TAG_SIZE;
    cipher_sz = sizeof(cipher);
    decrypt_sz = plain_sz;

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(cipher_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(write_sz, plain_sz);

    // Ciphertext size is 32, decrypttext size is too large
    plain_sz = 32 - AES_GCMSIV_TAG_SIZE;
    cipher_sz = sizeof(cipher);
    decrypt_sz = plain_sz + 1;

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(cipher_sz, plain_sz + AES_GCMSIV_TAG_SIZE);

    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);
    EXPECT_EQ(write_sz, plain_sz);

    aes_gcmsiv_free(&ctx);
}

TEST(API, DecryptAndCheckError)
{
    aes_gcmsiv_status_t ret;
    struct aes_gcmsiv_ctx ctx;
    uint8_t key[16];
    size_t key_sz = sizeof(key);
    uint8_t nonce[AES_GCMSIV_NONCE_SIZE];
    size_t nonce_sz = sizeof(nonce);
    uint8_t aad[16];
    size_t aad_sz = sizeof(aad);
    uint8_t plain[16];
    size_t plain_sz = sizeof(plain);
    uint8_t cipher[sizeof(plain) + AES_GCMSIV_TAG_SIZE];
    size_t cipher_sz = sizeof(cipher);
    size_t write_sz;

    memset(key, 0x00, key_sz);
    memset(nonce, 0x01, nonce_sz);
    memset(aad, 0x02, aad_sz);
    memset(cipher, 0x03, cipher_sz);

    // Initialize context
    aes_gcmsiv_init(&ctx);

    ret = aes_gcmsiv_set_key(&ctx, key, key_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

    // Test with null ctx
    ret = aes_gcmsiv_decrypt_and_check(nullptr, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       plain, plain_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PARAMETERS);

    // Test with null nonce
    ret = aes_gcmsiv_decrypt_and_check(&ctx, nullptr, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       plain, plain_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PARAMETERS);

    // Test with invalid nonce size
    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, AES_GCMSIV_NONCE_SIZE - 1, cipher, cipher_sz,
                                       aad, aad_sz, plain, plain_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_NONCE_SIZE);

    // Test with null ciphertext but ciphertext size != 0
    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, nullptr, cipher_sz, aad, aad_sz,
                                       plain, plain_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PARAMETERS);

    // Test with invalid ciphertext size
    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, AES_GCMSIV_TAG_SIZE - 1, aad,
                                       aad_sz, plain, plain_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_CIPHERTEXT_SIZE);

#if SIZE_MAX > UINT32_MAX
    // Test with ciphertext size > 2^36 + 16 (invalid plaintext size)
    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher,
                                       AES_GCMSIV_MAX_PLAINTEXT_SIZE + AES_GCMSIV_TAG_SIZE + 1, aad,
                                       aad_sz, plain, plain_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_CIPHERTEXT_SIZE);
#endif

    // Test with null AAD but AAD size != 0
    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, nullptr, aad_sz,
                                       plain, plain_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PARAMETERS);

#if SIZE_MAX > UINT32_MAX
    // Test with AAD size > 2^36
    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad,
                                       AES_GCMSIV_MAX_AAD_SIZE + 1, plain, plain_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_AAD_SIZE);
#endif

    // Test with null plaintext
    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       nullptr, plain_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PARAMETERS);

    // Test with plaintext size of 0
    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz, plain,
                                       0, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_UPDATE_OUTPUT_SIZE);

    // Test with null write size
    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz, plain,
                                       plain_sz, nullptr);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_PARAMETERS);

    aes_gcmsiv_free(&ctx);
}

TEST(API, DecryptAndCheckAuthError)
{
    aes_gcmsiv_status_t ret;
    struct aes_gcmsiv_ctx ctx;
    uint8_t key[16];
    size_t key_sz = sizeof(key);
    uint8_t nonce[AES_GCMSIV_NONCE_SIZE];
    size_t nonce_sz = sizeof(nonce);
    uint8_t aad[16];
    size_t aad_sz = sizeof(aad);
    uint8_t plain[16];
    size_t plain_sz = sizeof(plain);
    uint8_t cipher[sizeof(plain) + AES_GCMSIV_TAG_SIZE];
    size_t cipher_sz = sizeof(cipher);
    uint8_t decrypt[sizeof(plain)];
    size_t decrypt_sz = sizeof(decrypt);
    size_t write_sz;
    uint8_t zero[sizeof(plain)];
    size_t zero_sz = sizeof(zero);

    memset(key, 0x00, key_sz);
    memset(nonce, 0x01, nonce_sz);
    memset(aad, 0x02, aad_sz);
    memset(plain, 0x03, plain_sz);
    memset(zero, 0x00, zero_sz);

    // Initialize context
    aes_gcmsiv_init(&ctx);

    ret = aes_gcmsiv_set_key(&ctx, key, key_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

    // No plaintext, no AAD
    plain_sz = 0;
    aad_sz = 0;
    cipher_sz = sizeof(cipher);

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

    // Corrupt tag
    cipher[plain_sz] ^= 0xff;
    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_TAG);
    EXPECT_EQ(write_sz, (size_t)0);
    EXPECT_TRUE(memeq(decrypt, plain_sz, zero, plain_sz));
    cipher[plain_sz] ^= 0xff;

    // No plaintext, some AAD
    plain_sz = 0;
    aad_sz = sizeof(aad);
    cipher_sz = sizeof(cipher);

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

    // Corrupt AAD
    aad[0] ^= 0xff;
    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_TAG);
    EXPECT_EQ(write_sz, (size_t)0);
    EXPECT_TRUE(memeq(decrypt, plain_sz, zero, plain_sz));
    aad[0] ^= 0xff;

    // Corrupt tag
    cipher[plain_sz] ^= 0xff;
    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_TAG);
    EXPECT_EQ(write_sz, (size_t)0);
    EXPECT_TRUE(memeq(decrypt, plain_sz, zero, plain_sz));
    cipher[plain_sz] ^= 0xff;

    // Some plaintext, no AAD
    plain_sz = sizeof(plain);
    aad_sz = 0;
    cipher_sz = sizeof(cipher);

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

    // Corrupt ciphertext
    cipher[0] ^= 0xff;
    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_TAG);
    EXPECT_EQ(write_sz, (size_t)0);
    EXPECT_TRUE(memeq(decrypt, plain_sz, zero, plain_sz));
    cipher[0] ^= 0xff;

    // Corrupt tag
    cipher[plain_sz] ^= 0xff;
    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_TAG);
    EXPECT_EQ(write_sz, (size_t)0);
    EXPECT_TRUE(memeq(decrypt, plain_sz, zero, plain_sz));
    cipher[plain_sz] ^= 0xff;

    // Some plaintext, some AAD
    plain_sz = sizeof(plain);
    aad_sz = sizeof(aad);
    cipher_sz = sizeof(cipher);

    ret = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz, cipher,
                                      cipher_sz, &cipher_sz);
    EXPECT_EQ(ret, AES_GCMSIV_SUCCESS);

    // Corrup AAD
    aad[0] ^= 0xff;
    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_TAG);
    EXPECT_EQ(write_sz, (size_t)0);
    EXPECT_TRUE(memeq(decrypt, plain_sz, zero, plain_sz));
    aad[0] ^= 0xff;

    // Corrup ciphertext
    cipher[0] ^= 0xff;
    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_TAG);
    EXPECT_EQ(write_sz, (size_t)0);
    EXPECT_TRUE(memeq(decrypt, plain_sz, zero, plain_sz));
    cipher[0] ^= 0xff;

    // Corrup tag
    cipher[plain_sz] ^= 0xff;
    ret = aes_gcmsiv_decrypt_and_check(&ctx, nonce, nonce_sz, cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &write_sz);
    EXPECT_EQ(ret, AES_GCMSIV_INVALID_TAG);
    EXPECT_EQ(write_sz, (size_t)0);
    EXPECT_TRUE(memeq(decrypt, plain_sz, zero, plain_sz));
    cipher[plain_sz] ^= 0xff;

    aes_gcmsiv_free(&ctx);
}
