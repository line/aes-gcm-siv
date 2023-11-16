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

#include <benchmark/benchmark.h>

#include <cstring>

#include "aes_gcmsiv.h"

static void BM_AesGcmSiv_SetKey(size_t key_sz, benchmark::State &state)
{
    int res;
    uint8_t key[32];
    struct aes_gcmsiv_ctx ctx;

    // Initialize resources
    memset(key, 0x00, key_sz);

    // Benchmark
    for (auto _ : state) {
        aes_gcmsiv_init(&ctx);

        res = aes_gcmsiv_set_key(&ctx, key, key_sz);
        if (AES_GCMSIV_SUCCESS != res) {
            state.SkipWithError("Failed to initialize AES-GCM-SIV context");
            break;
        }

        aes_gcmsiv_free(&ctx);
    }
}

static void BM_AesGcmSiv_Encrypt(size_t key_sz,
                                 size_t aad_sz,
                                 size_t plain_sz,
                                 benchmark::State &state)
{
    int res;
    struct aes_gcmsiv_ctx ctx;
    uint8_t key[32];
    uint8_t nonce[AES_GCMSIV_NONCE_SIZE];
    size_t nonce_sz = sizeof(nonce);
    uint8_t *aad = nullptr;
    uint8_t *plain = nullptr;
    uint8_t *cipher = nullptr;
    size_t cipher_sz = 0;
    size_t write_sz;

    // Allocate resources
    aad = new uint8_t[aad_sz];
    plain = new uint8_t[plain_sz];
    cipher = new uint8_t[plain_sz + AES_GCMSIV_TAG_SIZE];
    cipher_sz = plain_sz + AES_GCMSIV_TAG_SIZE;

    // Initialize resources
    memset(key, 0x00, key_sz);
    memset(nonce, 0x01, nonce_sz);
    memset(aad, 0x02, aad_sz);
    memset(plain, 0x03, plain_sz);

    // Initialize AES-GCM-SIV context
    aes_gcmsiv_init(&ctx);

    res = aes_gcmsiv_set_key(&ctx, key, key_sz);
    if (AES_GCMSIV_SUCCESS != res) {
        state.SkipWithError("Failed to initialize AES-GCM-SIV context");
        return;
    }

    // Benchmark
    for (auto _ : state) {
        res = aes_gcmsiv_encrypt_with_tag(&ctx, nonce, nonce_sz, plain, plain_sz, aad, aad_sz,
                                          cipher, cipher_sz, &write_sz);
        if (AES_GCMSIV_SUCCESS != res) {
            state.SkipWithError("Failed to encrypt data");
            break;
        }
    }

    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t((aad_sz + plain_sz)));

    // Free resources
    aes_gcmsiv_free(&ctx);
    delete[] aad;
    delete[] plain;
    delete[] cipher;
}

static void BM_AesGcmSiv_SetKey128(benchmark::State &state)
{
    BM_AesGcmSiv_SetKey(16, state);
}

static void BM_AesGcmSiv_Auth128(benchmark::State &state)
{
    BM_AesGcmSiv_Encrypt(16, state.range(0), 0, state);
}

static void BM_AesGcmSiv_Encrypt128(benchmark::State &state)
{
    BM_AesGcmSiv_Encrypt(16, 0, state.range(0), state);
}

static void BM_AesGcmSiv_SetKey256(benchmark::State &state)
{
    BM_AesGcmSiv_SetKey(32, state);
}

static void BM_AesGcmSiv_Auth256(benchmark::State &state)
{
    BM_AesGcmSiv_Encrypt(32, state.range(0), 0, state);
}

static void BM_AesGcmSiv_Encrypt256(benchmark::State &state)
{
    BM_AesGcmSiv_Encrypt(32, 0, state.range(0), state);
}

// AES-GCM-SIV 128-bits
BENCHMARK(BM_AesGcmSiv_SetKey128);
BENCHMARK(BM_AesGcmSiv_Auth128)->Range(0, 1 << 30);
BENCHMARK(BM_AesGcmSiv_Encrypt128)->Range(0, 1 << 30);

// AES-GCM-SIV 256-bits
BENCHMARK(BM_AesGcmSiv_SetKey256);
BENCHMARK(BM_AesGcmSiv_Auth256)->Range(0, 1 << 30);
BENCHMARK(BM_AesGcmSiv_Encrypt256)->Range(0, 1 << 30);

BENCHMARK_MAIN();
