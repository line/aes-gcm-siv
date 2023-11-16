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

#ifndef AES_GCMSIV_UTIL_H
#define AES_GCMSIV_UTIL_H

#include "common.h"

enum hw_feature {
    HW_FEATURE_AES,
    HW_FEATURE_POLYVAL,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int aes_gcmsiv_has_feature(enum hw_feature what);
void aes_gcmsiv_zeroize(void *ptr, size_t ptr_sz);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* end AES_GCMSIV_UTIL_H */
