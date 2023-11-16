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

#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "aes_gcmsiv.h"

#define ASSERT(cond)                                                                               \
    if (!(cond)) {                                                                                 \
        goto cleanup;                                                                              \
    }

static int get_random(uint8_t *data, size_t data_sz);

int example_aes_gcm_siv_128(void)
{
    int ret = AES_GCMSIV_FAILURE;
    int res;
    struct aes_gcmsiv_ctx ctx;
    uint8_t key[16];
    uint8_t nonce[AES_GCMSIV_NONCE_SIZE];
    uint8_t *cipher = NULL;
    size_t cipher_sz = 0;
    uint8_t *decrypt = NULL;
    size_t decrypt_sz = 0;

    // Initialize AES-GCM-SIV context
    aes_gcmsiv_init(&ctx);

    // Generate a random 128-bits key
    res = get_random(key, sizeof(key));
    ASSERT(0 == res);

    // Setup AES-GCM-SIV context with the key
    res = aes_gcmsiv_set_key(&ctx, key, sizeof(key));
    ASSERT(AES_GCMSIV_SUCCESS == res);

    // Generate a unique nonce per message
    res = get_random(nonce, sizeof(nonce));
    ASSERT(0 == res);

    // Setup authenticated data and plaintext
    const uint8_t *aad = (const uint8_t *)"Authenticated but not encrypted data";
    size_t aad_sz = strlen((const char *)aad);
    const uint8_t *plain = (const uint8_t *)"Encrypted and authenticated data";
    size_t plain_sz = strlen((const char *)plain);

    // Get needed size for ciphertext and allocate buffer
    res = aes_gcmsiv_encrypt_size(plain_sz, aad_sz, &cipher_sz);
    ASSERT(AES_GCMSIV_SUCCESS == res);

    cipher = malloc(cipher_sz);
    ASSERT(NULL != cipher);

    // Encrypt plaintext and compute authentication tag
    res = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, sizeof(nonce), plain, plain_sz, aad, aad_sz,
                                      cipher, cipher_sz, &cipher_sz);
    ASSERT(AES_GCMSIV_SUCCESS == res);

    // Get needed size for decrypted text and allocate buffer
    res = aes_gcmsiv_decrypt_size(cipher_sz, aad_sz, &decrypt_sz);
    ASSERT(AES_GCMSIV_SUCCESS == res);

    decrypt = malloc(decrypt_sz);
    ASSERT(NULL != decrypt);

    // Decrypt ciphertext and check authenticity
    res = aes_gcmsiv_decrypt_and_check(&ctx, nonce, sizeof(nonce), cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &decrypt_sz);
    ASSERT(AES_GCMSIV_SUCCESS == res);

    // Check that the two messages are equals
    ASSERT(plain_sz == decrypt_sz);
    ASSERT(memcmp(plain, decrypt, plain_sz) == 0);

    ret = AES_GCMSIV_SUCCESS;
cleanup:
    aes_gcmsiv_free(&ctx);
    free(cipher);
    free(decrypt);

    return ret;
}

int example_aes_gcm_siv_256(void)
{
    int ret = AES_GCMSIV_FAILURE;
    int res;
    struct aes_gcmsiv_ctx ctx;
    uint8_t key[32];
    uint8_t nonce[AES_GCMSIV_NONCE_SIZE];
    uint8_t *cipher = NULL;
    size_t cipher_sz = 0;
    uint8_t *decrypt = NULL;
    size_t decrypt_sz = 0;

    // Initialize AES-GCM-SIV context
    aes_gcmsiv_init(&ctx);

    // Generate a random 256-bits key
    res = get_random(key, sizeof(key));
    ASSERT(0 == res);

    // Setup AES-GCM-SIV context with the key
    res = aes_gcmsiv_set_key(&ctx, key, sizeof(key));
    ASSERT(AES_GCMSIV_SUCCESS == res);

    // Generate a unique nonce per message
    res = get_random(nonce, sizeof(nonce));
    ASSERT(0 == res);

    // Setup authenticated data and plaintext
    const uint8_t *aad = (const uint8_t *)"Authenticated but not encrypted data";
    size_t aad_sz = strlen((const char *)aad);
    const uint8_t *plain = (const uint8_t *)"Encrypted and authenticated data";
    size_t plain_sz = strlen((const char *)plain);

    // Get needed size for ciphertext and allocate buffer
    res = aes_gcmsiv_encrypt_size(plain_sz, aad_sz, &cipher_sz);
    ASSERT(AES_GCMSIV_SUCCESS == res);

    cipher = malloc(cipher_sz);
    ASSERT(NULL != cipher);

    // Encrypt plaintext and compute authentication tag
    res = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, sizeof(nonce), plain, plain_sz, aad, aad_sz,
                                      cipher, cipher_sz, &cipher_sz);
    ASSERT(AES_GCMSIV_SUCCESS == res);

    // Get needed size for decrypted text and allocate buffer
    res = aes_gcmsiv_decrypt_size(cipher_sz, aad_sz, &decrypt_sz);
    ASSERT(AES_GCMSIV_SUCCESS == res);

    decrypt = malloc(decrypt_sz);
    ASSERT(NULL != decrypt);

    // Decrypt ciphertext and check authenticity
    res = aes_gcmsiv_decrypt_and_check(&ctx, nonce, sizeof(nonce), cipher, cipher_sz, aad, aad_sz,
                                       decrypt, decrypt_sz, &decrypt_sz);
    ASSERT(AES_GCMSIV_SUCCESS == res);

    // Check that the two messages are equals
    ASSERT(plain_sz == decrypt_sz);
    ASSERT(memcmp(plain, decrypt, plain_sz) == 0);

    ret = AES_GCMSIV_SUCCESS;
cleanup:
    aes_gcmsiv_free(&ctx);
    free(cipher);
    free(decrypt);

    return ret;
}

int main(void)
{
    int ret = EXIT_FAILURE;
    int res;

    res = example_aes_gcm_siv_128();
    ASSERT(AES_GCMSIV_SUCCESS == res)

    res = example_aes_gcm_siv_256();
    ASSERT(AES_GCMSIV_SUCCESS == res)

    ret = EXIT_SUCCESS;
cleanup:
    return ret;
}

int get_random(uint8_t *data, size_t data_sz)
{
    ssize_t read_sz;

    ASSERT(NULL != data || 0 == data_sz);

    int fd = open("/dev/urandom", O_RDONLY);
    ASSERT(-1 != fd);

    while (data_sz > 0) {
        do {
            read_sz = read(fd, data, data_sz);
        } while ((-1 == read_sz) && (EINTR == errno));

        if (read_sz <= 0) {
            break;
        }

        data += read_sz;
        data_sz -= read_sz;
    }

    close(fd);
cleanup:
    return !(data_sz == 0);
}
