/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2013, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#include <s2e.h>

void test_range1()
{
    uintptr_t value = 123, low, high;
    s2e_make_concolic(&value, sizeof(value), "value");
    if (value > 10222) {
        s2e_get_range(value, &low, &high);
        s2e_print_expression("low", low);
        s2e_print_expression("high", high);
        s2e_assert(low == 10223);
        s2e_assert(high == (uint32_t) -1);
    } else {
        s2e_get_range(value, &low, &high);
        s2e_print_expression("low", low);
        s2e_print_expression("high", high);
        s2e_assert(low == 0);
        s2e_assert(high == 10222);
    }
    s2e_assert(s2e_get_constraint_count(value) == 1);
    s2e_kill_state(0, "done");
}

void test_constraints1()
{
    uint32_t value = 123;
    s2e_make_concolic(&value, sizeof(value), "value");
    s2e_assert(s2e_get_constraint_count(value) == 0);

    if (value > 10) {
        s2e_assert(s2e_get_constraint_count(value) == 1);
        if (value == 309) {
            s2e_print_expression("value", value);
        }
        s2e_assert(s2e_get_constraint_count(value) == 2);
    } else {
        s2e_assert(s2e_get_constraint_count(value) == 1);
        if (value == 3) {
            s2e_print_expression("value", value);
        }
        s2e_assert(s2e_get_constraint_count(value) == 2);
    }

    s2e_kill_state(0, "done");
}
