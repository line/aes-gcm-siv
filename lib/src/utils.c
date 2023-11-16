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

#include "utils.h"

#ifdef TARGET_PLATFORM_ARM64

#ifdef __APPLE__
#include "TargetConditionals.h"

#ifdef TARGET_OS_OSX
#include <sys/sysctl.h>
#endif /* TARGET_OS_OSX */

#endif /* __APPLE__ */

#ifdef __linux__
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif /* __linux__ */

static inline void has_feature_arm64(int *has_aes, int *has_polyval);

#endif /* TARGET_PLATFORM_ARM64 */

#ifdef TARGET_PLATFORM_X86_64
static inline void has_feature_x86_64(int *has_aes, int *has_polyval);
#endif /* TARGET_PLATFORM_X86_64 */

int aes_gcmsiv_has_feature(enum hw_feature what)
{
    static int is_done = 0;
    static int has_aes = 0;
    static int has_polyval = 0;

    if (is_done) {
        goto done;
    }

#ifdef TARGET_PLATFORM_ARM64
    has_feature_arm64(&has_aes, &has_polyval);
#endif /* TARGET_PLATFORM_ARM64 */

#ifdef TARGET_PLATFORM_X86_64
    has_feature_x86_64(&has_aes, &has_polyval);
#endif /* TARGET_PLATFORM_X86_64 */

    is_done = 1;
done:
    switch (what) {
    case HW_FEATURE_AES:
        return has_aes;
    case HW_FEATURE_POLYVAL:
        return has_polyval;
    default:
        return 0;
    }
}

void aes_gcmsiv_zeroize(void *ptr, size_t ptr_sz)
{
    volatile uint8_t *bytes = ptr;

    for (size_t i = 0; i < ptr_sz; ++i) {
        bytes[i] = 0x00;
    }
}

#ifdef TARGET_PLATFORM_ARM64

#ifdef __APPLE__

#if TARGET_OS_OSX
void has_feature_arm64(int *has_aes, int *has_polyval)
{
    int res;
    int info;
    size_t info_sz;

    info = 0;
    info_sz = sizeof(info);
    res = sysctlbyname("hw.optional.arm.FEAT_AES", &info, &info_sz, NULL, 0);
    *has_aes = (0 == res) && (0 != info);

    info = 0;
    info_sz = sizeof(info);
    res = sysctlbyname("hw.optional.arm.FEAT_PMULL", &info, &info_sz, NULL, 0);
    *has_polyval = (0 == res) && (0 != info);
}
#endif /* TARGET_OS_OSX */

#if TARGET_OS_IPHONE
void has_feature_arm64(int *has_aes, int *has_polyval)
{
    // iOS cannot do runtime detection of HW features so to be safe, everything is disabled.
    *has_aes = 0;
    *has_polyval = 0;
}
#endif /* TARGET_OS_IPHONE */

#endif /* __APPLE__ */

#ifdef __linux__
void has_feature_arm64(int *has_aes, int *has_polyval)
{
    unsigned long auxval;

    auxval = getauxval(AT_HWCAP);

    *has_aes = (auxval & HWCAP_AES) != 0;
    *has_polyval = (auxval & HWCAP_PMULL) != 0;
}
#endif /*__linux__ */

#endif /* TARGET_PLATFORM_ARM64  */

#ifdef TARGET_PLATFORM_X86_64

void has_feature_x86_64(int *has_aes, int *has_polyval)
{
    uint32_t eax, ebx, ecx, edx;
    int has_sse;

    asm("cpuid\n\t" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));

    has_sse = (edx & (1 << 25)) != 0;

    *has_aes = has_sse && (((ecx) & (1 << 25)) != 0);
    *has_polyval = has_sse && (((edx) & (1 << 1)) != 0);
}

#endif /* TARGET_PLATFORM_X86_64 */
