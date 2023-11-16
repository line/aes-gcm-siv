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

#ifndef AES_GCMSIV_AES_X86_64_H
#define AES_GCMSIV_AES_X86_64_H

#include "common.h"

#ifdef TARGET_PLATFORM_X86_64

#include <emmintrin.h>
#include <immintrin.h>
#include <wmmintrin.h>

#ifdef __cplusplus
extern "C" {
#endif

struct aes_x86_64 {
    __m128i key[15];
    size_t key_sz;
};

void aes_x86_64_init(struct aes_x86_64 *ctx);
void aes_x86_64_free(struct aes_x86_64 *ctx);

aes_gcmsiv_status_t aes_x86_64_set_key(struct aes_x86_64 *ctx, const uint8_t *key, size_t key_sz);

aes_gcmsiv_status_t aes_x86_64_ecb_encrypt(struct aes_x86_64 *ctx,
                                           const uint8_t plain[AES_BLOCK_SIZE],
                                           uint8_t cipher[AES_BLOCK_SIZE]);
aes_gcmsiv_status_t aes_x86_64_ctr(struct aes_x86_64 *ctx,
                                   const uint8_t nonce[AES_BLOCK_SIZE],
                                   const uint8_t *input,
                                   size_t input_sz,
                                   uint8_t *output);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* TARGET_PLATFORM_X86_64 */

#endif /* AES_GCMSIV_AES_X86_64_H */
