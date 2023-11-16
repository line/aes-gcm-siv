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

#include "polyval_arm64.h"

#ifdef TARGET_PLATFORM_ARM64

#include <string.h>

#include "utils.h"

#if __GNUC__ && !__clang__
#define CRYPTO __attribute__((target("+crypto")))
#else
#define CRYPTO
#endif

#define AS_P64(a)       vreinterpretq_p64_u8((a))
#define GET_LANE(a, i)  vgetq_lane_p64(AS_P64((a)), (i))
#define HIGH(a)         vextq_u8((a), vdupq_n_u8(0x00), 8)
#define LOW(a)          vextq_u8(vdupq_n_u8(0x00), (a), 8)
#define MULT(a, b)      vreinterpretq_u8_p128(vmull_p64((a), (b)))
#define MULT_HIGH(a, b) vreinterpretq_u8_p128(vmull_high_p64(AS_P64((a)), AS_P64((b))))
#define MULT_LOW(a, b)  MULT(GET_LANE((a), 0), GET_LANE((b), 0))
#define POLY(a)         vget_lane_p64(vcreate_p64((a)), 0)
#define SWAP(a)         vextq_u8((a), (a), 8)
#define XOR(a, b)       veorq_u8((a), (b))

static inline void mult(uint8x16_t a, uint8x16_t b, uint8x16_t *c0, uint8x16_t *c1, uint8x16_t *c2);
static inline void add_mult(
    const uint8x16_t a, const uint8x16_t b, uint8x16_t *c0, uint8x16_t *c1, uint8x16_t *c2);
static inline uint8x16_t mult_inv_x128(const uint8x16_t p0,
                                       const uint8x16_t p1,
                                       const uint8x16_t p2);
static inline uint8x16_t mult_inv_x64(const uint8x16_t p);
static inline uint8x16_t dot(const uint8x16_t a, const uint8x16_t b);
static inline uint8x16_t polyval_arm64_process_tables(const uint8x16_t *h_table,
                                                      uint8x16_t s,
                                                      const uint8_t *data,
                                                      size_t data_sz);

CRYPTO
aes_gcmsiv_status_t polyval_arm64_start(struct polyval_arm64 *ctx,
                                        const uint8_t *key,
                                        size_t key_sz)
{
    if (NULL == ctx || (NULL == key && 0 != key_sz)) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    if (POLYVAL_SIZE != key_sz) {
        return AES_GCMSIV_INVALID_KEY_SIZE;
    }

    ctx->s = vdupq_n_u8(0x00);
    ctx->h_table[0] = vld1q_u8(key);

    for (size_t i = 1; i < 8; ++i) {
        ctx->h_table[i] = dot(ctx->h_table[0], ctx->h_table[i - 1]);
    }

    return AES_GCMSIV_SUCCESS;
}

CRYPTO
aes_gcmsiv_status_t polyval_arm64_update(struct polyval_arm64 *ctx,
                                         const uint8_t *data,
                                         size_t data_sz)
{
    if (NULL == ctx || (NULL == data && 0 != data_sz)) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    ctx->s = polyval_arm64_process_tables(ctx->h_table, ctx->s, data, data_sz);

    return AES_GCMSIV_SUCCESS;
}

CRYPTO
aes_gcmsiv_status_t polyval_arm64_finish(struct polyval_arm64 *ctx,
                                         const uint8_t *nonce,
                                         size_t nonce_sz,
                                         uint8_t tag[POLYVAL_SIZE])
{
    uint8_t tmp[POLYVAL_SIZE];
    uint8x16_t n;

    if (NULL == ctx || (NULL == nonce && 0 != nonce_sz) || NULL == tag) {
        return AES_GCMSIV_INVALID_PARAMETERS;
    }

    if (POLYVAL_SIZE < nonce_sz) {
        return AES_GCMSIV_INVALID_NONCE_SIZE;
    }

    memset(tmp, 0x00, sizeof(tmp));
    memcpy(tmp, nonce, nonce_sz);

    n = vld1q_u8(tmp);
    vst1q_u8(tag, XOR(n, ctx->s));

    return AES_GCMSIV_SUCCESS;
}

CRYPTO
void mult(uint8x16_t a, uint8x16_t b, uint8x16_t *c0, uint8x16_t *c1, uint8x16_t *c2)
{
    // a * b = (a0 + a1 * X^64) * (b0 + b1 * X^64)
    //       = a0b0 + a0b1 * X^64 + a1b0 * X^64 + a1b1 * X^128
    //       = a0b0 + (a0b1 + a1b0)      * X^64 + a1b1 * X^128
    //       = c0   + c1                 * X^64 + c2   * X^128
    *c0 = MULT_LOW(a, b);
    *c2 = MULT_HIGH(a, b);
    *c1 = XOR(MULT_LOW(a, SWAP(b)), MULT_HIGH(a, SWAP(b)));
}

CRYPTO
void add_mult(
    const uint8x16_t a, const uint8x16_t b, uint8x16_t *c0, uint8x16_t *c1, uint8x16_t *c2)
{
    *c0 = XOR(*c0, MULT_LOW(a, b));
    *c2 = XOR(*c2, MULT_HIGH(a, b));
    *c1 = XOR(*c1, XOR(MULT_LOW(a, SWAP(b)), MULT_HIGH(a, SWAP(b))));
}

CRYPTO
uint8x16_t mult_inv_x128(const uint8x16_t p0, const uint8x16_t p1, const uint8x16_t p2)
{
    // p = p0 + p1                 * X^64               + p2  * X^128
    //   = p0 + (p1l + p1h * X^64) * X^64               + p2  * X^128
    //   = p0 + p1l * X^64                + (p1h + p2)        * X^128
    //   = p0 + (p1 << 64)                + ((p1 >> 64) + p2) * X^128
    //   = q                              + r                 * X^128
    uint8x16_t q = XOR(p0, LOW(p1));
    uint8x16_t r = XOR(p2, HIGH(p1));

    // s = q * X^-64
    uint8x16_t s = mult_inv_x64(q);
    // t = s * X^-64
    //   = q * X^-64 * X^-64
    //   = q * X^-128
    uint8x16_t t = mult_inv_x64(s);

    // p * X^-128 = (q + r * X^128) * X^128
    //            = q * X^-128 + r * X^128 * X^-128
    //            = r + q * X^-128
    //            = r + t
    return XOR(r, t);
}

CRYPTO
uint8x16_t mult_inv_x64(const uint8x16_t p)
{
    // POLY = X^57 + X^62 + X^63
    //      = X^57 + X^62 + X^63 + X^64 + X^64
    //      = X^-64                    + X^64
    poly64_t POLY = vget_lane_p64(vcreate_p64(0xc200000000000000), 0);

    // p = p0 + p1 * X^64
    // q = p1 + p0 * X^64
    uint8x16_t q = SWAP(p);

    // r = p0 * POLY0
    //   = p0 * (X^63 + X^62 + X^57)
    uint8x16_t r = MULT(GET_LANE(p, 0), POLY);

    // q + r = p1 + p0 * X^64 + p0 * (X^63 + X^62 + X^57)
    //       = p1             + p0 * (X^64 + X^63 + X^62 + X^57)
    //       = p1             + p0 * X^-64
    //       = (p0 + p1 * X^64) * X^-64
    //       = p * X^-64
    return XOR(q, r);
}

CRYPTO
uint8x16_t dot(const uint8x16_t a, const uint8x16_t b)
{
    uint8x16_t c0, c1, c2;
    // a * b = c0 + c1 * X^64 + c2 * X^128
    //       = c
    mult(a, b, &c0, &c1, &c2);
    // c * X^-128 = a * b * X^-128
    //            = dot(a, b)
    return mult_inv_x128(c0, c1, c2);
}

CRYPTO
uint8x16_t polyval_arm64_process_tables(const uint8x16_t *h_table,
                                        uint8x16_t s,
                                        const uint8_t *data,
                                        size_t data_sz)
{
    uint8x16_t s0, s1, s2;
    uint8x16_t d;
    size_t blocks_sz = 0;
    uint8_t tmp[POLYVAL_SIZE];

    if (0 == data_sz) {
        return s;
    }

    // Process 8 blocks of 16 bytes at a time
    blocks_sz = data_sz / (8 * POLYVAL_SIZE);

    if (blocks_sz > 0) {
        for (size_t i = 0; i < blocks_sz; ++i) {
            // d0 = D7 * H0
            d = vld1q_u8(data + (7 * POLYVAL_SIZE));
            mult(d, h_table[0], &s0, &s1, &s2);

            // d1 = d0 + D6 * H1
            d = vld1q_u8(data + (6 * POLYVAL_SIZE));
            add_mult(d, h_table[1], &s0, &s1, &s2);

            // d2 = d1                + D5 * H2
            //    = d0      + D6 * H1 + D5 * H2
            //    = D7 * H0 + D6 * H1 + D5 * H2
            d = vld1q_u8(data + (5 * POLYVAL_SIZE));
            add_mult(d, h_table[2], &s0, &s1, &s2);

            d = vld1q_u8(data + (4 * POLYVAL_SIZE));
            add_mult(d, h_table[3], &s0, &s1, &s2);

            d = vld1q_u8(data + (3 * POLYVAL_SIZE));
            add_mult(d, h_table[4], &s0, &s1, &s2);

            d = vld1q_u8(data + (2 * POLYVAL_SIZE));
            add_mult(d, h_table[5], &s0, &s1, &s2);

            d = vld1q_u8(data + (1 * POLYVAL_SIZE));
            add_mult(d, h_table[6], &s0, &s1, &s2);

            // d7 = d6                                + (D0 + Sn-1) * H7
            //    = D7 * H0 + D6 * H1           + ... + (D0 + Sn-1) * H7
            //    = D7 * H  + D6 * H^2 * X^-128 + ... + (D0 + Sn-1) * H^8 * (X^-128)^7
            d = XOR(s, vld1q_u8(data + (0 * POLYVAL_SIZE)));
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

            data += 8 * POLYVAL_SIZE;
        }

        data_sz -= blocks_sz * 8 * POLYVAL_SIZE;
    }

    // Process remaining blocks of 16 bytes
    blocks_sz = data_sz / POLYVAL_SIZE;

    if (blocks_sz > 0) {
        // Compute Polyval(H, D0 + Sn-1, ..., Dn)
        if (blocks_sz > 1) {
            d = vld1q_u8(data + ((blocks_sz - 1) * POLYVAL_SIZE));
            mult(d, h_table[0], &s0, &s1, &s2);

            for (size_t i = 1; i < blocks_sz - 1; ++i) {
                d = vld1q_u8(data + ((blocks_sz - 1 - i) * POLYVAL_SIZE));
                add_mult(d, h_table[i], &s0, &s1, &s2);
            }

            // dn = (Sn-1 + D0) * H^n * (X^-128)^(n-1)
            d = XOR(s, vld1q_u8(data + (0 * POLYVAL_SIZE)));
            add_mult(d, h_table[blocks_sz - 1], &s0, &s1, &s2);
        } else {
            // d = (Sn-1 + D0) * H
            d = XOR(s, vld1q_u8(data + 0 * POLYVAL_SIZE));
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

        d = XOR(s, vld1q_u8(tmp));
        s = dot(d, h_table[0]);
    }

    return s;
}

#endif /* TARGET_PLATFORM_ARM64 */
