///
/// Copyright (C) 2010-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///

/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
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
 * Currently maintained by:
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#ifndef _S2E_DEVICE_STATE_H_

#define _S2E_DEVICE_STATE_H_

#include <vector>
#include <map>
#include <set>
#include <stdint.h>
#include <llvm/ADT/SmallVector.h>

#include <klee/AddressSpace.h>

#include "s2e_block.h"

extern "C" {
    struct QEMUFile;
}

namespace s2e {

class S2EExecutionState;

class S2EDeviceState {
private:
    static const unsigned SECTOR_SIZE;

    /* Give 64GB of KLEE address space for each block device */
    static const uint64_t BLOCK_DEV_AS;

    static std::vector<void *> s_devices;
    static std::set<std::string> s_customDevices;
    static bool s_devicesInited;

    static QEMUFile *s_memFile;

    uint8_t *m_stateBuffer;
    unsigned m_stateBufferSize;

    static llvm::SmallVector<struct BlockDriverState*, 5> s_blockDevices;
    klee::AddressSpace m_deviceState;

    void allocateBuffer(unsigned int Sz);

    static unsigned getBlockDeviceId(struct BlockDriverState* dev);
    static uint64_t getBlockDeviceStart(struct BlockDriverState* dev);

public:
    S2EDeviceState(klee::ExecutionState *state);
    S2EDeviceState(const S2EDeviceState &state);
    ~S2EDeviceState();

    void setExecutionState(klee::ExecutionState *state) {
        m_deviceState.state = state;
    }

    void initDeviceState();

    //From QEMU to KLEE
    void saveDeviceState();
    
    //From KLEE to QEMU
    void restoreDeviceState();

    int putBuffer(const uint8_t *buf, int64_t pos, int size);
    int getBuffer(uint8_t *buf, int64_t pos, int size);

    int writeSector(struct BlockDriverState *bs, int64_t sector, const uint8_t *buf, int nb_sectors);
    int readSector(struct BlockDriverState *bs, int64_t sector, uint8_t *buf, int nb_sectors);
};

}

#endif
