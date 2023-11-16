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

#ifndef AES_GCMSIV_POLYVAL_X86_64_H
#define AES_GCMSIV_POLYVAL_X86_64_H

#include "common.h"

#ifdef TARGET_PLATFORM_X86_64

#include <emmintrin.h>
#include <tmmintrin.h>
#include <wmmintrin.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct polyval_x86_64 {
    __m128i s;
    __m128i h_table[8];
};

aes_gcmsiv_status_t polyval_x86_64_start(struct polyval_x86_64 *ctx,
                                         const uint8_t *key,
                                         size_t key_sz);
aes_gcmsiv_status_t polyval_x86_64_update(struct polyval_x86_64 *ctx,
                                          const uint8_t *data,
                                          size_t data_sz);
aes_gcmsiv_status_t polyval_x86_64_finish(struct polyval_x86_64 *ctx,
                                          const uint8_t *nonce,
                                          size_t nonce_sz,
                                          uint8_t tag[POLYVAL_SIZE]);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* TARGET_PLATFORM_X86_64 */

#endif /* AES_GCMSIV_POLYVAL_X86_64_H */
