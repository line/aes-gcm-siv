/*
 *  FIPS-197 compliant AES implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
 *  This file is part of mbed TLS (https://tls.mbed.org)
 *
 *  This file has been modified by LINE Corporation. Said modifications are:
 *  - implementations not used in the library have been removed
 *  - parameter checks has been changed to to match with other return codes
 *  - changed mbedtls function names to prevent symbol conflicts with other mbedtls modules
 */

/*
 *  The AES block cipher was designed by Vincent Rijmen and Joan Daemen.
 *
 *  http://csrc.nist.gov/encryption/aes/rijndael/Rijndael.pdf
 *  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */

#include "aes_generic.h"

#include <string.h>

#include "utils.h"

#ifdef AES_GENERIC_ROM_TABLES

#include "aes_generic_tables.h"

#else

// Forward S-box & tables
static uint8_t FSb[256];
static uint32_t FT0[256];
static uint32_t FT1[256];
static uint32_t FT2[256];
static uint32_t FT3[256];

// Round constants
static uint32_t RCON[10];

static int aes_generic_gen_tables_is_init = 0;
static void aes_generic_gen_tables(void);

#endif /* AES_GENERIC_ROM_TABLES */

// Tables generation code
#define ROTL8(x)     (((x) << 8) & 0xFFFFFFFF) | ((x) >> 24)
#define XTIME(x)     (((x) << 1) ^ (((x)&0x80) ? 0x1B : 0x00))
#define MUL(x, y)    (((x) && (y)) ? pow[(log[(x)] + log[(y)]) % 255] : 0)

#define AES_FT0(idx) FT0[idx]
#define AES_FT1(idx) FT1[idx]
#define AES_FT2(idx) FT2[idx]
#define AES_FT3(idx) FT3[idx]

#define AES_FROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3)                                                 \
    do {                                                                                           \
        (X0) = *RK++ ^ AES_FT0(((Y0)) & 0xFF) ^ AES_FT1(((Y1) >> 8) & 0xFF) ^                      \
               AES_FT2(((Y2) >> 16) & 0xFF) ^ AES_FT3(((Y3) >> 24) & 0xFF);                        \
                                                                                                   \
        (X1) = *RK++ ^ AES_FT0(((Y1)) & 0xFF) ^ AES_FT1(((Y2) >> 8) & 0xFF) ^                      \
               AES_FT2(((Y3) >> 16) & 0xFF) ^ AES_FT3(((Y0) >> 24) & 0xFF);                        \
                                                                                                   \
        (X2) = *RK++ ^ AES_FT0(((Y2)) & 0xFF) ^ AES_FT1(((Y3) >> 8) & 0xFF) ^                      \
               AES_FT2(((Y0) >> 16) & 0xFF) ^ AES_FT3(((Y1) >> 24) & 0xFF);                        \
                                                                                                   \
        (X3) = *RK++ ^ AES_FT0(((Y3)) & 0xFF) ^ AES_FT1(((Y0) >> 8) & 0xFF) ^                      \
               AES_FT2(((Y1) >> 16) & 0xFF) ^ AES_FT3(((Y2) >> 24) & 0xFF);                        \
    } while (0)

void aes_generic_init(struct aes_generic *ctx)
{
    if (NULL == ctx) {
        return;
    }

    memset(ctx, 0x00, sizeof(*ctx));
}

void aes_generic_free(struct aes_generic *ctx)
{
    if (ctx == NULL) {
        return;
    }

    aes_gcmsiv_zeroize(ctx, sizeof(*ctx));
}

// AES key schedule (encryption)
aes_gcmsiv_status_t aes_generic_set_key(struct aes_generic *ctx, const uint8_t *key, size_t key_sz)
{
    unsigned int i;
    uint32_t *RK;

    if (NULL == ctx || NULL == key) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    switch (key_sz) {
    case 16:
        ctx->nr = 10;
        break;
    case 24:
        ctx->nr = 12;
        break;
    case 32:
        ctx->nr = 14;
        break;
    default:
        return AES_GCMSIV_INVALID_KEY_SIZE;
    }

#ifndef AES_GENERIC_ROM_TABLES
    if (aes_generic_gen_tables_is_init == 0) {
        aes_generic_gen_tables();
        aes_generic_gen_tables_is_init = 1;
    }
#endif /* AES_GENERIC_ROM_TABLES */

    ctx->rk = RK = ctx->buf;

    for (i = 0; i < (key_sz >> 2); i++) {
        GET_UINT32_LE(RK[i], key, i << 2);
    }

    switch (ctx->nr) {
    case 10:
        for (i = 0; i < 10; i++, RK += 4) {
            RK[4] = RK[0] ^ RCON[i] ^ ((uint32_t)FSb[(RK[3] >> 8) & 0xFF]) ^
                    ((uint32_t)FSb[(RK[3] >> 16) & 0xFF] << 8) ^
                    ((uint32_t)FSb[(RK[3] >> 24) & 0xFF] << 16) ^
                    ((uint32_t)FSb[(RK[3]) & 0xFF] << 24);

            RK[5] = RK[1] ^ RK[4];
            RK[6] = RK[2] ^ RK[5];
            RK[7] = RK[3] ^ RK[6];
        }
        break;
    case 12:
        for (i = 0; i < 8; i++, RK += 6) {
            RK[6] = RK[0] ^ RCON[i] ^ ((uint32_t)FSb[(RK[5] >> 8) & 0xFF]) ^
                    ((uint32_t)FSb[(RK[5] >> 16) & 0xFF] << 8) ^
                    ((uint32_t)FSb[(RK[5] >> 24) & 0xFF] << 16) ^
                    ((uint32_t)FSb[(RK[5]) & 0xFF] << 24);

            RK[7] = RK[1] ^ RK[6];
            RK[8] = RK[2] ^ RK[7];
            RK[9] = RK[3] ^ RK[8];
            RK[10] = RK[4] ^ RK[9];
            RK[11] = RK[5] ^ RK[10];
        }
        break;
    case 14:
        for (i = 0; i < 7; i++, RK += 8) {
            RK[8] = RK[0] ^ RCON[i] ^ ((uint32_t)FSb[(RK[7] >> 8) & 0xFF]) ^
                    ((uint32_t)FSb[(RK[7] >> 16) & 0xFF] << 8) ^
                    ((uint32_t)FSb[(RK[7] >> 24) & 0xFF] << 16) ^
                    ((uint32_t)FSb[(RK[7]) & 0xFF] << 24);

            RK[9] = RK[1] ^ RK[8];
            RK[10] = RK[2] ^ RK[9];
            RK[11] = RK[3] ^ RK[10];

            RK[12] = RK[4] ^ ((uint32_t)FSb[(RK[11]) & 0xFF]) ^
                     ((uint32_t)FSb[(RK[11] >> 8) & 0xFF] << 8) ^
                     ((uint32_t)FSb[(RK[11] >> 16) & 0xFF] << 16) ^
                     ((uint32_t)FSb[(RK[11] >> 24) & 0xFF] << 24);

            RK[13] = RK[5] ^ RK[12];
            RK[14] = RK[6] ^ RK[13];
            RK[15] = RK[7] ^ RK[14];
        }
        break;
    }

    return AES_GCMSIV_SUCCESS;
}

aes_gcmsiv_status_t aes_generic_ecb_encrypt(struct aes_generic *ctx,
                                            const uint8_t plain[AES_BLOCK_SIZE],
                                            uint8_t cipher[AES_BLOCK_SIZE])
{
    int i;
    uint32_t *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

    if (NULL == ctx || NULL == plain || NULL == cipher) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    RK = ctx->rk;

    GET_UINT32_LE(X0, plain, 0);
    X0 ^= *RK++;
    GET_UINT32_LE(X1, plain, 4);
    X1 ^= *RK++;
    GET_UINT32_LE(X2, plain, 8);
    X2 ^= *RK++;
    GET_UINT32_LE(X3, plain, 12);
    X3 ^= *RK++;

    for (i = (ctx->nr >> 1) - 1; i > 0; i--) {
        AES_FROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);
        AES_FROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3);
    }

    AES_FROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);

    X0 = *RK++ ^ ((uint32_t)FSb[(Y0)&0xFF]) ^ ((uint32_t)FSb[(Y1 >> 8) & 0xFF] << 8) ^
         ((uint32_t)FSb[(Y2 >> 16) & 0xFF] << 16) ^ ((uint32_t)FSb[(Y3 >> 24) & 0xFF] << 24);

    X1 = *RK++ ^ ((uint32_t)FSb[(Y1)&0xFF]) ^ ((uint32_t)FSb[(Y2 >> 8) & 0xFF] << 8) ^
         ((uint32_t)FSb[(Y3 >> 16) & 0xFF] << 16) ^ ((uint32_t)FSb[(Y0 >> 24) & 0xFF] << 24);

    X2 = *RK++ ^ ((uint32_t)FSb[(Y2)&0xFF]) ^ ((uint32_t)FSb[(Y3 >> 8) & 0xFF] << 8) ^
         ((uint32_t)FSb[(Y0 >> 16) & 0xFF] << 16) ^ ((uint32_t)FSb[(Y1 >> 24) & 0xFF] << 24);

    X3 = *RK++ ^ ((uint32_t)FSb[(Y3)&0xFF]) ^ ((uint32_t)FSb[(Y0 >> 8) & 0xFF] << 8) ^
         ((uint32_t)FSb[(Y1 >> 16) & 0xFF] << 16) ^ ((uint32_t)FSb[(Y2 >> 24) & 0xFF] << 24);

    PUT_UINT32_LE(X0, cipher, 0);
    PUT_UINT32_LE(X1, cipher, 4);
    PUT_UINT32_LE(X2, cipher, 8);
    PUT_UINT32_LE(X3, cipher, 12);

    return AES_GCMSIV_SUCCESS;
}

aes_gcmsiv_status_t aes_generic_ctr(struct aes_generic *ctx,
                                    const uint8_t nonce[AES_BLOCK_SIZE],
                                    const uint8_t *input,
                                    size_t input_sz,
                                    uint8_t *output)
{
    uint8_t counter_block[AES_BLOCK_SIZE];
    uint32_t counter;
    uint8_t key_stream[AES_BLOCK_SIZE];

    if (NULL == ctx || NULL == nonce || (NULL == input && 0 != input_sz) ||
        (NULL == output && 0 != input_sz)) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    memcpy(counter_block, nonce, sizeof(counter_block));
    GET_UINT32_LE(counter, counter_block, 0);

    while (input_sz >= AES_BLOCK_SIZE) {
        aes_generic_ecb_encrypt(ctx, counter_block, key_stream);

        // Increment counter with wrapping
        counter += 1;
        PUT_UINT32_LE(counter, counter_block, 0);

        for (size_t i = 0; i < AES_BLOCK_SIZE; ++i) {
            output[i] = input[i] ^ key_stream[i];
        }

        input += AES_BLOCK_SIZE;
        output += AES_BLOCK_SIZE;
        input_sz -= AES_BLOCK_SIZE;
    }

    if (input_sz > 0) {
        aes_generic_ecb_encrypt(ctx, counter_block, key_stream);

        // Increment counter with wrapping
        counter += 1;
        PUT_UINT32_LE(counter, counter_block, 0);

        for (size_t i = 0; i < input_sz; ++i) {
            output[i] = input[i] ^ key_stream[i];
        }
    }

    return AES_GCMSIV_SUCCESS;
}

#ifndef AES_GENERIC_ROM_TABLES

void aes_generic_gen_tables(void)
{
    int i, x, y, z;
    int pow[256];
    int log[256];

    // Compute pow and log tables over GF(2^8)
    for (i = 0, x = 1; i < 256; i++) {
        pow[i] = x;
        log[x] = i;
        x = (x ^ XTIME(x)) & 0xFF;
    }

    // Calculate the round constants
    for (i = 0, x = 1; i < 10; i++) {
        RCON[i] = (uint32_t)x;
        x = XTIME(x) & 0xFF;
    }

    // Generate the forward and reverse S-boxes
    FSb[0x00] = 0x63;

    for (i = 1; i < 256; i++) {
        x = pow[255 - log[i]];

        y = x;
        y = ((y << 1) | (y >> 7)) & 0xFF;
        x ^= y;
        y = ((y << 1) | (y >> 7)) & 0xFF;
        x ^= y;
        y = ((y << 1) | (y >> 7)) & 0xFF;
        x ^= y;
        y = ((y << 1) | (y >> 7)) & 0xFF;
        x ^= y ^ 0x63;

        FSb[i] = (unsigned char)x;
    }

    // Generate the forward tables
    for (i = 0; i < 256; i++) {
        x = FSb[i];
        y = XTIME(x) & 0xFF;
        z = (y ^ x) & 0xFF;

        FT0[i] = ((uint32_t)y) ^ ((uint32_t)x << 8) ^ ((uint32_t)x << 16) ^ ((uint32_t)z << 24);
        FT1[i] = ROTL8(FT0[i]);
        FT2[i] = ROTL8(FT1[i]);
        FT3[i] = ROTL8(FT2[i]);
    }
}

#endif /* AES_GENERIC_ROM_TABLES */
