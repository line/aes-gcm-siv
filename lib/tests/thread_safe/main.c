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
#include <string.h>

#include <pthread.h>

#include "aes_gcmsiv.h"

#define THREAD_NUM 100
#define LOOP_COUNT 10000

struct thread_ctx {
    pthread_t thread;
    int is_running;
    int exit_code;
    size_t id;
    struct aes_gcmsiv_ctx *aes;
};

int thread_start(struct thread_ctx *ctx, size_t id, struct aes_gcmsiv_ctx *aes);
int thread_join(struct thread_ctx *ctx, int *success);
void *thread_routine(void *arg);

int main(void)
{
    int ret = EXIT_FAILURE;
    int res;
    uint8_t key[16];
    size_t key_sz = sizeof(key);
    struct aes_gcmsiv_ctx ctx;
    struct thread_ctx threads[THREAD_NUM];
    size_t threads_sz = sizeof(threads) / sizeof(threads[0]);
    int success = 1;
    int thread_success;

    aes_gcmsiv_init(&ctx);
    memset(key, 0x00, sizeof(key));
    memset(threads, 0x00, sizeof(threads));

    // Set AES-GCM-SIV key
    res = aes_gcmsiv_set_key(&ctx, key, key_sz);
    if (AES_GCMSIV_SUCCESS != res) {
        fprintf(stderr, "Failed to setup AES-GCM-SIV key...\n");
        goto cleanup;
    }

    // Start threads
    for (size_t i = 0; i < threads_sz; ++i) {
        res = thread_start(&threads[i], i, &ctx);
        if (0 != res) {
            fprintf(stderr, "Failed to start a thread...\n");
            break;
        }
    }

    for (size_t i = 0; i < threads_sz; ++i) {
        thread_success = 0;

        res = thread_join(&threads[i], &thread_success);
        if (0 != res) {
            fprintf(stderr, "Failed to join a thread...\n");
            continue;
        }

        success = success && thread_success;
    }

    if (!success) {
        goto cleanup;
    }

    ret = EXIT_SUCCESS;
cleanup:
    aes_gcmsiv_free(&ctx);

    return ret;
}

int thread_start(struct thread_ctx *ctx, size_t id, struct aes_gcmsiv_ctx *aes)
{
    int ret = 1;
    int res;

    if (NULL == ctx) {
        goto cleanup;
    }

    ctx->thread = 0;
    ctx->is_running = 0;
    ctx->exit_code = 0;

    ctx->id = id;
    ctx->aes = aes;

    res = pthread_create(&ctx->thread, NULL, thread_routine, ctx);
    if (0 != res) {
        fprintf(stderr, "pthread_create failed\n");
        goto cleanup;
    }

    ctx->is_running = 1;

    ret = 0;
cleanup:
    return ret;
}

int thread_join(struct thread_ctx *ctx, int *success)
{
    int ret = 1;
    int res;

    if (NULL == ctx || NULL == success) {
        goto cleanup;
    }

    *success = 0;

    if (!ctx->is_running) {
        ret = 0;
        goto cleanup;
    }

    res = pthread_join(ctx->thread, NULL);
    if (0 != res) {
        fprintf(stderr, "pthread_join failed\n");
        goto cleanup;
    }

    ctx->is_running = 0;

    *success = (ctx->exit_code == 0);

    ret = 0;
cleanup:
    return ret;
}

void *thread_routine(void *arg)
{
    int ret = 1;
    int res;
    struct thread_ctx *ctx = arg;
    uint8_t nonce[AES_GCMSIV_NONCE_SIZE];
    size_t nonce_sz = sizeof(nonce);
    uint8_t aad[256];
    size_t aad_sz = sizeof(aad);
    uint8_t plain[256];
    size_t plain_sz = sizeof(plain);
    uint8_t cipher[256 + AES_GCMSIV_TAG_SIZE];
    size_t cipher_sz = sizeof(cipher);
    uint8_t decrypt[256];
    size_t decrypt_sz = sizeof(decrypt);

    memset(nonce, 0x01, sizeof(nonce));
    memset(plain, 0x02, sizeof(plain));
    memset(aad, 0x03, sizeof(aad));

    if (NULL == ctx) {
        goto cleanup;
    }

    for (size_t i = 0; i < LOOP_COUNT; ++i) {
        cipher_sz = sizeof(cipher);
        memset(cipher, 0x00, cipher_sz);
        decrypt_sz = sizeof(decrypt);
        memset(decrypt, 0x00, decrypt_sz);

        // Encrypt
        res = aes_gcmsiv_encrypt_with_tag(ctx->aes, nonce, nonce_sz, plain, plain_sz, aad, aad_sz,
                                          cipher, cipher_sz, &cipher_sz);
        if (AES_GCMSIV_SUCCESS != res) {
            fprintf(stderr, "aes_gcmsiv_encrypt_with_tag failed\n");
            goto cleanup;
        }

        // Decrypt
        res = aes_gcmsiv_decrypt_and_check(ctx->aes, nonce, nonce_sz, cipher, cipher_sz, aad,
                                           aad_sz, decrypt, decrypt_sz, &decrypt_sz);
        if (AES_GCMSIV_SUCCESS != res) {
            fprintf(stderr, "aes_gcmsiv_decrypt_and_check failed\n");
            goto cleanup;
        }

        // Check result
        if ((plain_sz != decrypt_sz) || (0 != memcmp(plain, decrypt, plain_sz))) {
            fprintf(stderr, "Plaintext and decrypttext mismatch\n");
            goto cleanup;
        }
    }

    ret = 0;
cleanup:
    if (NULL != ctx) {
        ctx->exit_code = ret;
    }

    return NULL;
}
