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

#include <inttypes.h>
#include <s2e.h>
#include <rawmonitor.h>
#include "main.h"
#include "config-host.h"

#if defined(S2E_PLUGIN_DIR)
void test_external(void);
#endif

static S2E_RAWMONITOR_STACK s_stack = {
    .StackSize = 0x1000,
    .StackBase = 0x80000 - 0x1000
};

void main(void)
{
    /* Init basic plugin environment */
    s2e_rawmonitor_register_stack(&s_stack);

    //test_range1();
    //test_constraints1();
#if defined(S2E_PLUGIN_DIR)
    test_external();
#endif
    //test_symbhw_pci_bars();
    //test_symbhw_pci_immutable_fields();
    //test_symbhw_pci_extraspace();
    //test_symbhw_symbolic_port_writes();
    //test_symbhw_query_resource_size();
    //test_symbhw_unaligned_reads();
    //test_symbhw_unaligned_cmd_port();
    //test_symbhw_hotplug();
    //test_symbhw_multiple_mappings();
    //test_symbhw_multiple_mappings_io();
    //test_symbhw_select_config_single_path();
    //test_symbhw_select_config_multi_path();
    //test_symbhw_switch_config_symbbus();

    test_selfmod1();

    s2e_kill_state(0, "done");
}

