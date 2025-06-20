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

#ifndef UTILS_H
#define UTILS_H

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

std::string to_hex(const std::vector<uint8_t> &input, bool uppercase = false);
std::vector<uint8_t> from_hex(const std::string input);

int memeq(const uint8_t *lhs, size_t lhs_sz, const uint8_t *rhs, size_t rhs_sz);

#endif /* end UTILS_H */
