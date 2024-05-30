/*
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved.
 *  Modifications copyright (C) 2023, LINE Corporation
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 *
 *  This file has been modified by LINE Corporation. Said modifications are:
 *  - implementations not used in the library have been removed
 *  - parameter checks has been changed to to match with other return codes
 *  - changed mbedtls function names to prevent symbol conflicts with other mbedtls modules
 */

#ifndef AES_GCMSIV_AES_GENERIC_H
#define AES_GCMSIV_AES_GENERIC_H

#include "common.h"

#if (defined(__ARMCC_VERSION) || defined(_MSC_VER)) && !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * \brief The AES context-type definition.
 */
struct aes_generic {
    /* The number of rounds. */
    int nr;
    /* AES round keys. */
    uint32_t *rk;
    /* Unaligned data buffer. This buffer can hold 32 extra Bytes,
     * which can be used for one of the following purposes:
     * - Alignment if VIA padlock is used.
     * - Simplifying key expansion in the 256-bit case by generating an extra round key.
     */
    uint32_t buf[68];
};

void aes_generic_init(struct aes_generic *ctx);
void aes_generic_free(struct aes_generic *ctx);

aes_gcmsiv_status_t aes_generic_set_key(struct aes_generic *ctx, const uint8_t *key, size_t key_sz);

aes_gcmsiv_status_t aes_generic_ecb_encrypt(struct aes_generic *ctx,
                                            const uint8_t plain[AES_BLOCK_SIZE],
                                            uint8_t cipher[AES_BLOCK_SIZE]);
aes_gcmsiv_status_t aes_generic_ctr(struct aes_generic *ctx,
                                    const uint8_t nonce[AES_BLOCK_SIZE],
                                    const uint8_t *input,
                                    size_t input_sz,
                                    uint8_t *output);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* AES_GCMSIV_AES_GENERIC_H */
