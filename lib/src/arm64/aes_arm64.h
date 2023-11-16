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

#ifndef AES_GCMSIV_AES_ARM64_H
#define AES_GCMSIV_AES_ARM64_H

#include "common.h"

#ifdef TARGET_PLATFORM_ARM64

#include <arm_neon.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct aes_arm64 {
    uint8x16_t key[15];
    size_t key_sz;
};

void aes_arm64_init(struct aes_arm64 *ctx);
void aes_arm64_free(struct aes_arm64 *ctx);

aes_gcmsiv_status_t aes_arm64_set_key(struct aes_arm64 *ctx, const uint8_t *key, size_t key_sz);

aes_gcmsiv_status_t aes_arm64_ecb_encrypt(struct aes_arm64 *ctx,
                                          const uint8_t plain[AES_BLOCK_SIZE],
                                          uint8_t cipher[AES_BLOCK_SIZE]);
aes_gcmsiv_status_t aes_arm64_ctr(struct aes_arm64 *ctx,
                                  const uint8_t nonce[AES_BLOCK_SIZE],
                                  const uint8_t *input,
                                  size_t input_sz,
                                  uint8_t *output);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* TARGET_PLATFORM_ARM64 */

#endif /* AES_GCMSIV_AES_ARM64_H */
