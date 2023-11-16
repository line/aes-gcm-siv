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

#ifndef AES_GCMSIV_POLYVAL_GENERIC_H
#define AES_GCMSIV_POLYVAL_GENERIC_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct polyval_generic {
    uint8_t S[POLYVAL_SIZE];
    uint64_t HL[16];
    uint64_t HH[16];
};

aes_gcmsiv_status_t polyval_generic_start(struct polyval_generic *ctx,
                                          const uint8_t *key,
                                          size_t key_sz);
aes_gcmsiv_status_t polyval_generic_update(struct polyval_generic *ctx,
                                           const uint8_t *data,
                                           size_t data_sz);
aes_gcmsiv_status_t polyval_generic_finish(struct polyval_generic *ctx,
                                           const uint8_t *nonce,
                                           size_t nonce_sz,
                                           uint8_t tag[POLYVAL_SIZE]);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* AES_GCMSIV_POLYVAL_GENERIC_H */
