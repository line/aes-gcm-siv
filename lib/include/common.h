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

#ifndef AES_GCMSIV_COMMON_H
#define AES_GCMSIV_COMMON_H

#include <stddef.h>
#include <stdint.h>

#include "aes_gcmsiv.h"

// Architecture specific defines
#ifdef USE_INTRINSICS

// Intel x86
#if __i386__ || _M_IX86
#define TARGET_PLATFORM_X86
#endif

// Intel x86_64
#if __x86_64__ || _M_X64
#define TARGET_PLATFORM_X86_64
#endif

// ARM
#if __arm__ || _M_ARM
#define TARGET_PLATFORM_ARM
#endif

// ARM AArch64
#if __aarch64__ || _M_ARM64
#define TARGET_PLATFORM_ARM64
#endif

#endif /* USE_INTRINSICS */

// Use only one lookup table
#ifdef USE_FEWER_TABLES
#define AES_GENERIC_FEWER_TABLES
#endif /* USE_FEWER_TABLES */

// Use const lookup tables
#ifdef USE_ROM_TABLES
#define AES_GENERIC_ROM_TABLES
#endif /* USE_ROM_TABLES */

// AES and Polyval constants
#define AES_BLOCK_SIZE 16
#define POLYVAL_SIZE   16

// Memory load / store words
#define GET_UINT32_LE(n, b, i)                                                                     \
    do {                                                                                           \
        (n) = (((uint32_t)(b)[(i) + 0]) << 0) | (((uint32_t)(b)[(i) + 1]) << 8) |                  \
              (((uint32_t)(b)[(i) + 2]) << 16) | (((uint32_t)(b)[(i) + 3]) << 24);                 \
    } while (0)

#define PUT_UINT32_LE(n, b, i)                                                                     \
    do {                                                                                           \
        (b)[(i) + 0] = (uint8_t)((n) >> 0);                                                        \
        (b)[(i) + 1] = (uint8_t)((n) >> 8);                                                        \
        (b)[(i) + 2] = (uint8_t)((n) >> 16);                                                       \
        (b)[(i) + 3] = (uint8_t)((n) >> 24);                                                       \
    } while (0)

#define GET_UINT64_LE(n, b, i)                                                                     \
    do {                                                                                           \
        (n) = (((uint64_t)(b)[(i) + 0]) << 0) | (((uint64_t)(b)[(i) + 1]) << 8) |                  \
              (((uint64_t)(b)[(i) + 2]) << 16) | (((uint64_t)(b)[(i) + 3]) << 24) |                \
              (((uint64_t)(b)[(i) + 4]) << 32) | (((uint64_t)(b)[(i) + 5]) << 40) |                \
              (((uint64_t)(b)[(i) + 6]) << 48) | (((uint64_t)(b)[(i) + 7]) << 56);                 \
    } while (0)

#define PUT_UINT64_LE(n, b, i)                                                                     \
    do {                                                                                           \
        (b)[(i) + 0] = (uint8_t)((n) >> 0);                                                        \
        (b)[(i) + 1] = (uint8_t)((n) >> 8);                                                        \
        (b)[(i) + 2] = (uint8_t)((n) >> 16);                                                       \
        (b)[(i) + 3] = (uint8_t)((n) >> 24);                                                       \
        (b)[(i) + 4] = (uint8_t)((n) >> 32);                                                       \
        (b)[(i) + 5] = (uint8_t)((n) >> 40);                                                       \
        (b)[(i) + 6] = (uint8_t)((n) >> 48);                                                       \
        (b)[(i) + 7] = (uint8_t)((n) >> 56);                                                       \
    } while (0)

#endif /* AES_GCMSIV_COMMON_H */
