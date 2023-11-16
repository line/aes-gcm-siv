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
 */

#ifndef MBEDTLS_AES_H
#define MBEDTLS_AES_H

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
typedef struct mbedtls_aes_context {
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
} mbedtls_aes_context;

void mbedtls_aes_init(mbedtls_aes_context *ctx);
void mbedtls_aes_free(mbedtls_aes_context *ctx);

aes_gcmsiv_status_t mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx,
                                           const uint8_t *key,
                                           size_t key_sz);

aes_gcmsiv_status_t mbedtls_aes_crypt_ecb(mbedtls_aes_context *ctx,
                                          const uint8_t plain[AES_BLOCK_SIZE],
                                          uint8_t cipher[AES_BLOCK_SIZE]);
aes_gcmsiv_status_t mbedtls_aes_crypt_ctr(mbedtls_aes_context *ctx,
                                          const uint8_t nonce[AES_BLOCK_SIZE],
                                          const uint8_t *input,
                                          size_t input_sz,
                                          uint8_t *output);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MBEDTLS_AES_H */
