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

#include "polyval_x86_64.h"

#ifdef TARGET_PLATFORM_X86_64

#include <string.h>

#include "utils.h"

#ifdef __GNUC__
#define PCLMUL __attribute__((target("sse2,pclmul")))
#else
#define PCLMUL
#endif

#define XOR(a, b)      _mm_xor_si128((a), (b))
#define CLMUL(a, b, c) _mm_clmulepi64_si128((a), (b), (c))
#define SWAP(a)        _mm_shuffle_epi32((a), 0x4e)

static inline void mult(__m128i a, __m128i b, __m128i *c0, __m128i *c1, __m128i *c2);
static inline void add_mult(
    const __m128i a, const __m128i b, __m128i *c0, __m128i *c1, __m128i *c2);
static inline __m128i mult_inv_x128(const __m128i p0, const __m128i p1, const __m128i p2);
static inline __m128i mult_inv_x64(const __m128i p);
static inline __m128i dot(const __m128i a, const __m128i b);
static inline __m128i polyval_x86_64_process_tables(const __m128i *h_table,
                                                    __m128i s,
                                                    const uint8_t *data,
                                                    size_t data_sz);

PCLMUL
aes_gcmsiv_status_t polyval_x86_64_start(struct polyval_x86_64 *ctx,
                                         const uint8_t *key,
                                         size_t key_sz)
{
    if (NULL == ctx || (NULL == key && 0 != key_sz)) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    if (POLYVAL_SIZE != key_sz) {
        return AES_GCMSIV_INVALID_KEY_SIZE;
    }

    ctx->s = _mm_setzero_si128();

    // h_tables[0] = H
    ctx->h_table[0] = _mm_loadu_si128((const __m128i_u *)key);

    for (size_t i = 1; i < 8; ++i) {
        // h_tables[i] = dot(H, h_tables[i - 1])
        //             = H * h_tables[i - 1]        * X^-128
        //             = H * (H^i * (X^-128)^(i-1)) * X^-128
        //             = H^(i+1)                    * (X^-128)^i
        ctx->h_table[i] = dot(ctx->h_table[0], ctx->h_table[i - 1]);
    }

    return AES_GCMSIV_SUCCESS;
}

PCLMUL
aes_gcmsiv_status_t polyval_x86_64_update(struct polyval_x86_64 *ctx,
                                          const uint8_t *data,
                                          size_t data_sz)
{
    if (NULL == ctx || (NULL == data && 0 != data_sz)) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    ctx->s = polyval_x86_64_process_tables(ctx->h_table, ctx->s, data, data_sz);

    return AES_GCMSIV_SUCCESS;
}

PCLMUL
aes_gcmsiv_status_t polyval_x86_64_finish(struct polyval_x86_64 *ctx,
                                          const uint8_t *nonce,
                                          size_t nonce_sz,
                                          uint8_t tag[POLYVAL_SIZE])
{
    uint8_t tmp[POLYVAL_SIZE];
    __m128i n;

    if (NULL == ctx || (NULL == nonce && 0 != nonce_sz) || NULL == tag) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    if (POLYVAL_SIZE < nonce_sz) {
        return AES_GCMSIV_INVALID_NONCE_SIZE;
    }

    memcpy(tmp, nonce, nonce_sz);
    memset(tmp + nonce_sz, 0x00, sizeof(tmp) - nonce_sz);

    n = _mm_loadu_si128((const __m128i_u *)tmp);
    _mm_storeu_si128((__m128i_u *)tag, XOR(n, ctx->s));

    return AES_GCMSIV_SUCCESS;
}

PCLMUL
void mult(const __m128i a, const __m128i b, __m128i *c0, __m128i *c1, __m128i *c2)
{
    // a * b = (a0 + a1 * X^64) * (b0 + b1 * X^64)
    //       = a0b0 + a0b1 * X^64 + a1b0 * X^64 + a1b1 * X^128
    //       = a0b0 + (a0b1 + a1b0)      * X^64 + a1b1 * X^128
    //       = c0   + c1                 * X^64 + c2   * X^128
    *c0 = CLMUL(a, b, 0x00);
    *c2 = CLMUL(a, b, 0x11);
    *c1 = XOR(CLMUL(a, b, 0x01), CLMUL(a, b, 0x10));
}

PCLMUL
void add_mult(const __m128i a, const __m128i b, __m128i *c0, __m128i *c1, __m128i *c2)
{
    *c0 = XOR(*c0, CLMUL(a, b, 0x00));
    *c2 = XOR(*c2, CLMUL(a, b, 0x11));
    *c1 = XOR(*c1, XOR(CLMUL(a, b, 0x01), CLMUL(a, b, 0x10)));
}

PCLMUL
__m128i mult_inv_x128(const __m128i p0, const __m128i p1, const __m128i p2)
{
    // p = p0 + p1                 * X^64               + p2  * X^128
    //   = p0 + (p1l + p1h * X^64) * X^64               + p2  * X^128
    //   = p0 + p1l * X^64                + (p1h + p2)        * X^128
    //   = p0 + (p1 << 64)                + ((p1 >> 64) + p2) * X^128
    //   = q                              + r                 * X^128
    __m128i q = XOR(p0, _mm_slli_si128(p1, 8));
    __m128i r = XOR(p2, _mm_srli_si128(p1, 8));

    // s = q * X^-64
    __m128i s = mult_inv_x64(q);
    // t = s * X^-64
    //   = q * X^-64 * X^-64
    //   = q * X^-128
    __m128i t = mult_inv_x64(s);

    // p * X^-128 = (q + r * X^128) * X^128
    //            = q * X^-128 + r * X^128 * X^-128
    //            = r + q * X^-128
    //            = r + t
    return XOR(r, t);
}

PCLMUL
__m128i mult_inv_x64(const __m128i p)
{
    // POLY = 0x00000000 + 0xc2000000           * X^32 + 0x00000001 * X^64 + 0x00000000 + X^96
    //      = 0          + (X^25 + X^30 + X^31) * X^32 + 1          * X^64
    //      = X^57 + X^62 + X^63                       +              X^64
    //     (= POLY0                                    + POLY1      * X^64)
    //      = X^-64
    const __m128i POLY = _mm_setr_epi32(0x00000000, 0xc2000000, 0x00000001, 0x00000000);

    // p = p0 + p1 * X^64
    // q = p1 + p0 * X^64
    __m128i q = SWAP(p);

    // r = p0 * POLY0
    //   = p0 * (X^63 + X^62 + X^57)
    __m128i r = CLMUL(p, POLY, 0x00);

    // q + r = p1 + p0 * X^64 + p0 * (X^63 + X^62 + X^57)
    //       = p1             + p0 * (X^64 + X^63 + X^62 + X^57)
    //       = p1             + p0 * X^-64
    //       = (p0 + p1 * X^64) * X^-64
    //       = p * X^-64
    return XOR(q, r);
}

PCLMUL
__m128i dot(const __m128i a, const __m128i b)
{
    __m128i c0, c1, c2;
    // a * b = c0 + c1 * X^64 + c2 * X^128
    //       = c
    mult(a, b, &c0, &c1, &c2);
    // c * X^-128 = a * b * X^-128
    //            = dot(a, b)
    return mult_inv_x128(c0, c1, c2);
}

PCLMUL
__m128i polyval_x86_64_process_tables(const __m128i *h_table,
                                      __m128i s,
                                      const uint8_t *data,
                                      size_t data_sz)
{
    __m128i s0, s1, s2;
    __m128i d;
    const __m128i_u *blocks = NULL;
    size_t blocks_sz = 0;
    uint8_t tmp[POLYVAL_SIZE];

    if (0 == data_sz) {
        return s;
    }

    // Process 8 blocks of 16 bytes at a time
    blocks_sz = data_sz / (8 * POLYVAL_SIZE);

    if (blocks_sz > 0) {
        blocks = (const __m128i_u *)data;

        for (size_t i = 0; i < blocks_sz; ++i) {
            // d0 = D7 * H0
            d = _mm_loadu_si128(&blocks[7]);
            mult(d, h_table[0], &s0, &s1, &s2);

            // d1 = d0 + D6 * H1
            d = _mm_loadu_si128(&blocks[6]);
            add_mult(d, h_table[1], &s0, &s1, &s2);

            // d2 = d1                + D5 * H2
            //    = d0      + D6 * H1 + D5 * H2
            //    = D7 * H0 + D6 * H1 + D5 * H2
            d = _mm_loadu_si128(&blocks[5]);
            add_mult(d, h_table[2], &s0, &s1, &s2);

            d = _mm_loadu_si128(&blocks[4]);
            add_mult(d, h_table[3], &s0, &s1, &s2);

            d = _mm_loadu_si128(&blocks[3]);
            add_mult(d, h_table[4], &s0, &s1, &s2);

            d = _mm_loadu_si128(&blocks[2]);
            add_mult(d, h_table[5], &s0, &s1, &s2);

            d = _mm_loadu_si128(&blocks[1]);
            add_mult(d, h_table[6], &s0, &s1, &s2);

            // d7 = d6                                + (D0 + Sn-1) * H7
            //    = D7 * H0 + D6 * H1           + ... + (D0 + Sn-1) * H7
            //    = D7 * H  + D6 * H^2 * X^-128 + ... + (D0 + Sn-1) * H^8 * (X^-128)^7
            d = XOR(s, _mm_loadu_si128(&blocks[0]));
            add_mult(d, h_table[7], &s0, &s1, &s2);

            // s = d7                                                                        * X^-128
            //   = (D7 * H       + D6 * H^2 * X^-128 + ... + (D0 + Sn-1) * H^8 * (X^-128)^7) * X^-128
            //   =  D7 * HX^-128 + D6 * (HX^-128)^2  + ... + (D0 + Sn-1) * (HX^-128)^8
            //   = (D7           + D6 * (HX^-128)    + ... + (D0 + Sn-1) * (HX^-128)^7)      * HX^-128
            //   = dot(D7        + D6 * (HX^-128)    + ... + (D0 + Sn-1) * (HX^-128)^7, H)
            //   = dot(D7        + (D6 + ...               + (D0 + Sn-1) * (HX^-128)^6) * HX^-128, H)
            //   = dot(D7        + dot(D6 + ...,                   H)                            , H)
            //   = dot(D7        + dot(D6 + ... dot(D0 + Sn-1, H), H)                            , H)
            //   = Polyval(H, D0 + Sn-1, D1, ..., D7)
            s = mult_inv_x128(s0, s1, s2);

            blocks += 8;
        }

        data += blocks_sz * 8 * POLYVAL_SIZE;
        data_sz -= blocks_sz * 8 * POLYVAL_SIZE;
    }

    // Process remaining blocks of 16 bytes
    blocks_sz = data_sz / POLYVAL_SIZE;

    if (blocks_sz > 0) {
        blocks = (const __m128i_u *)data;

        // Compute Polyval(H, D0 + Sn-1, ..., Dn)
        if (blocks_sz > 1) {
            d = _mm_loadu_si128(&blocks[blocks_sz - 1]);
            mult(d, h_table[0], &s0, &s1, &s2);

            for (size_t i = 1; i < blocks_sz - 1; ++i) {
                d = _mm_loadu_si128(&blocks[blocks_sz - 1 - i]);
                add_mult(d, h_table[i], &s0, &s1, &s2);
            }

            // dn = (Sn-1 + D0) * H^n * (X^-128)^(n-1)
            d = XOR(s, _mm_loadu_si128(&blocks[0]));
            add_mult(d, h_table[blocks_sz - 1], &s0, &s1, &s2);
        } else {
            // d = (Sn-1 + D0) * H
            d = XOR(s, _mm_loadu_si128(&blocks[0]));
            mult(d, h_table[0], &s0, &s1, &s2);
        }

        // If more than 2 blocks
        // s = dn * X^-128
        //   = dot(Dn + ... dot(D0 + Sn-1m H), H)
        //   = Polyval(H, D0 + Sn-1, ..., Dn)
        // If 1 block only
        // s = d               * X^-128
        //   = (Sn-1 + D0) * H * X^-128
        //   = dot(Sn-1 + D0, H)
        //   = Polyval(H, D0 + Sn-1)
        // So,
        // s = Polyval(H, D0 + Sn-1, ..., Dn)
        s = mult_inv_x128(s0, s1, s2);

        data += blocks_sz * POLYVAL_SIZE;
        data_sz -= blocks_sz * POLYVAL_SIZE;
    }

    // Process trailing bytes
    if (data_sz > 0) {
        memset(tmp, 0x00, sizeof(tmp));
        memcpy(tmp, data, data_sz);

        d = XOR(s, _mm_loadu_si128((const __m128i *)tmp));
        s = dot(d, h_table[0]);
    }

    return s;
}

#endif /* TARGET_PLATFORM_X86_64 */
