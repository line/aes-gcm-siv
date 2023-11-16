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

#include "polyval_generic.h"

#include <string.h>

#include "utils.h"

// 0, P(X), P(X)*X, P(X)*X^2, ...
static const uint64_t PL[16] = {
    UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000003),
    UINT64_C(0x0000000000000002), UINT64_C(0x0000000000000006), UINT64_C(0x0000000000000007),
    UINT64_C(0x0000000000000005), UINT64_C(0x0000000000000004), UINT64_C(0x000000000000000d),
    UINT64_C(0x000000000000000c), UINT64_C(0x000000000000000e), UINT64_C(0x000000000000000f),
    UINT64_C(0x000000000000000b), UINT64_C(0x000000000000000a), UINT64_C(0x0000000000000008),
    UINT64_C(0x0000000000000009)};

static const uint64_t PH[16] = {
    UINT64_C(0x0000000000000000), UINT64_C(0xc200000000000000), UINT64_C(0x4600000000000000),
    UINT64_C(0x8400000000000000), UINT64_C(0x8c00000000000000), UINT64_C(0x4e00000000000000),
    UINT64_C(0xca00000000000000), UINT64_C(0x0800000000000000), UINT64_C(0xda00000000000000),
    UINT64_C(0x1800000000000000), UINT64_C(0x9c00000000000000), UINT64_C(0x5e00000000000000),
    UINT64_C(0x5600000000000000), UINT64_C(0x9400000000000000), UINT64_C(0x1000000000000000),
    UINT64_C(0xd200000000000000)};

// 0, X^-128, X^-127, X^-126, ...
static const uint64_t XL[16] = {
    UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000003),
    UINT64_C(0x0000000000000002), UINT64_C(0x0000000000000007), UINT64_C(0x0000000000000006),
    UINT64_C(0x0000000000000004), UINT64_C(0x0000000000000005), UINT64_C(0x000000000000000e),
    UINT64_C(0x000000000000000f), UINT64_C(0x000000000000000d), UINT64_C(0x000000000000000c),
    UINT64_C(0x0000000000000009), UINT64_C(0x0000000000000008), UINT64_C(0x000000000000000a),
    UINT64_C(0x000000000000000b)};

static const uint64_t XH[16] = {
    UINT64_C(0x0000000000000000), UINT64_C(0x9204000000000000), UINT64_C(0xe608000000000000),
    UINT64_C(0x740c000000000000), UINT64_C(0x0e10000000000000), UINT64_C(0x9c14000000000000),
    UINT64_C(0xe818000000000000), UINT64_C(0x7a1c000000000000), UINT64_C(0x1c20000000000000),
    UINT64_C(0x8e24000000000000), UINT64_C(0xfa28000000000000), UINT64_C(0x682c000000000000),
    UINT64_C(0x1230000000000000), UINT64_C(0x8034000000000000), UINT64_C(0xf438000000000000),
    UINT64_C(0x663c000000000000)};

struct dot_context {
    uint64_t hl;
    uint64_t hh;
    uint64_t lo;
    uint64_t hi;
    uint8_t rem;
};

static inline void dot(struct dot_context *dot,
                       const uint8_t *a,
                       const uint64_t bl[16],
                       const uint64_t bh[16]);

aes_gcmsiv_status_t polyval_generic_start(struct polyval_generic *ctx,
                                          const uint8_t *key,
                                          size_t key_sz)
{
    struct dot_context dot_ctx;

    if (NULL == ctx || (NULL == key && 0 != key_sz)) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    if (POLYVAL_SIZE != key_sz) {
        return AES_GCMSIV_INVALID_KEY_SIZE;
    }

    // Compute H * X^-128
    dot(&dot_ctx, key, XL, XH);

    // Compute table
    ctx->HL[0] = 0;
    ctx->HH[0] = 0;

    ctx->HL[1] = dot_ctx.hl;
    ctx->HH[1] = dot_ctx.hh;

    // Compute HX, HX^2, HX^3
    for (size_t i = 2; i < 16; i *= 2) {
        dot_ctx.rem = (dot_ctx.hh >> 63) & 0x01;
        dot_ctx.hh = (dot_ctx.hh << 1) ^ (dot_ctx.hl >> 63) ^ PH[dot_ctx.rem];
        dot_ctx.hl = (dot_ctx.hl << 1) ^ PL[dot_ctx.rem];

        ctx->HL[i] = dot_ctx.hl;
        ctx->HH[i] = dot_ctx.hh;

        // Compute HX + H, HX^2 + H, HX^2 + HX, ...
        for (size_t j = 1; j < i; ++j) {
            ctx->HL[i + j] = dot_ctx.hl ^ ctx->HL[j];
            ctx->HH[i + j] = dot_ctx.hh ^ ctx->HH[j];
        }
    }

    aes_gcmsiv_zeroize(&dot_ctx, sizeof(dot_ctx));

    return AES_GCMSIV_SUCCESS;
}

aes_gcmsiv_status_t polyval_generic_update(struct polyval_generic *ctx,
                                           const uint8_t *data,
                                           size_t data_sz)
{
    struct dot_context dot_ctx;

    if (NULL == ctx || (NULL == data && 0 != data_sz)) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    while (data_sz >= POLYVAL_SIZE) {
        // Compute S_{j-1} xor X_j
        for (size_t i = 0; i < POLYVAL_SIZE; ++i) {
            ctx->S[i] = ctx->S[i] ^ data[i];
        }

        // Compute S_j = (S_{j-1} xor  X_j) * H * X^-128
        dot(&dot_ctx, ctx->S, ctx->HL, ctx->HH);

        // Update tag
        PUT_UINT64_LE(dot_ctx.hl, ctx->S, 0);
        PUT_UINT64_LE(dot_ctx.hh, ctx->S, 8);

        data += POLYVAL_SIZE;
        data_sz -= POLYVAL_SIZE;
    }

    if (data_sz > 0) {
        // Compute S_{j-1} xor X_j
        for (size_t i = 0; i < data_sz; ++i) {
            ctx->S[i] = ctx->S[i] ^ data[i];
        }

        // Compute S_j = (S_{j-1} xor  X_j) * H * X^-128
        dot(&dot_ctx, ctx->S, ctx->HL, ctx->HH);

        // Update tag
        PUT_UINT64_LE(dot_ctx.hl, ctx->S, 0);
        PUT_UINT64_LE(dot_ctx.hh, ctx->S, 8);
    }

    aes_gcmsiv_zeroize(&dot_ctx, sizeof(dot_ctx));

    return AES_GCMSIV_SUCCESS;
}

aes_gcmsiv_status_t polyval_generic_finish(struct polyval_generic *ctx,
                                           const uint8_t *nonce,
                                           size_t nonce_sz,
                                           uint8_t tag[POLYVAL_SIZE])
{
    if (NULL == ctx || (NULL == nonce && 0 != nonce_sz) || NULL == tag) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    if (POLYVAL_SIZE < nonce_sz) {
        return AES_GCMSIV_INVALID_NONCE_SIZE;
    }

    for (size_t i = 0; i < nonce_sz; ++i) {
        tag[i] = ctx->S[i] ^ nonce[i];
    }

    for (size_t i = nonce_sz; i < POLYVAL_SIZE; ++i) {
        tag[i] = ctx->S[i];
    }

    return AES_GCMSIV_SUCCESS;
}

void dot(struct dot_context *dot, const uint8_t *a, const uint64_t bl[16], const uint64_t bh[16])
{
    dot->hl = 0;
    dot->hh = 0;

    for (size_t i = 0; i < POLYVAL_SIZE; ++i) {
        dot->hi = (a[POLYVAL_SIZE - i - 1] >> 4) & 0x0f;
        dot->lo = (a[POLYVAL_SIZE - i - 1] >> 0) & 0x0f;

        dot->rem = (dot->hh >> 60) & 0x0f;
        dot->hh = ((dot->hh << 4) | (dot->hl >> 60)) ^ PH[dot->rem] ^ bh[dot->hi];
        dot->hl = (dot->hl << 4) ^ PL[dot->rem] ^ bl[dot->hi];

        dot->rem = (dot->hh >> 60) & 0x0f;
        dot->hh = ((dot->hh << 4) | (dot->hl >> 60)) ^ PH[dot->rem] ^ bh[dot->lo];
        dot->hl = (dot->hl << 4) ^ PL[dot->rem] ^ bl[dot->lo];
    }
}
