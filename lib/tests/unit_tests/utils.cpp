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

#include <cstdlib>

std::string to_hex(const std::vector<uint8_t> &input, bool uppercase)
{
    std::string result;
    uint8_t u[2];

    for (std::size_t i = 0; i < input.size(); ++i) {
        u[0] = (input[i] & 0xF0) >> 4;
        u[1] = input[i] & 0x0F;

        if (u[0] < 10) {
            result += u[0] + '0';
        } else {
            result += u[0] + (uppercase ? 'A' : 'a') - 10;
        }

        if (u[1] < 10) {
            result += u[1] + '0';
        } else {
            result += u[1] + (uppercase ? 'A' : 'a') - 10;
        }
    }

    return result;
}

std::vector<uint8_t> from_hex(const std::string input)
{
    std::vector<uint8_t> result;
    char c[2];

    if (input.length() % 2 != 0) {
        throw std::invalid_argument("Incorrect length");
    }

    for (std::size_t i = 0; i < input.length(); i += 2) {
        c[0] = input[i];
        c[1] = input[i + 1];

        uint8_t out = 0;

        if (c[0] >= '0' && c[0] <= '9') {
            out |= 0xF0 & ((c[0] - '0') << 4);
        } else if (c[0] >= 'a' && c[0] <= 'f') {
            out |= 0xF0 & ((c[0] - 'a' + 10) << 4);
        } else if (c[0] >= 'A' && c[0] <= 'F') {
            out |= 0xF0 & ((c[0] - 'A' + 10) << 4);
        } else {
            throw std::invalid_argument("Invalid character");
        }

        if (c[1] >= '0' && c[1] <= '9') {
            out |= 0x0F & (c[1] - '0');
        } else if (c[1] >= 'a' && c[1] <= 'f') {
            out |= 0x0F & (c[1] - 'a' + 10);
        } else if (c[1] >= 'A' && c[1] <= 'F') {
            out |= 0x0F & (c[1] - 'A' + 10);
        } else {
            throw std::invalid_argument("Invalid character");
        }

        result.push_back(out);
    }

    return result;
}

int memeq(const uint8_t *lhs, size_t lhs_sz, const uint8_t *rhs, size_t rhs_sz)
{
    if (lhs_sz != rhs_sz) {
        return 0;
    }

    for (size_t i = 0; i < lhs_sz; ++i) {
        if (lhs[i] != rhs[i]) {
            return 0;
        }
    }

    return 1;
}
