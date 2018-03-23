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

#include <stdio.h>
#include <fstream>
#include <sstream>

#include <llvm/Support/raw_ostream.h>

#include "cfg.pb.h"

#include "BinaryCFGReader.h"

namespace llvm {

static bool IsTerminatorInstruction(const std::string &bytes) {
    if (bytes.empty()) {
        return false;
    }

    const uint8_t TERMINATOR_OPCODES[9] = {
        0xF4,   // HLT
        0xFF,   // CALL
        0xE8,   // CALL
        0x9A,   // CALL
        0xCC,   // INT
        0xCD,   // INT
        0xCE,   // INT
        0xF2,   // REPNE
        0xF3    // REPE
    };

    for (auto const &opcode : TERMINATOR_OPCODES) {
        if ((uint8_t) bytes[0] == opcode) {
            return true;
        }
    }

    return false;
}

bool ParseMcSemaCfgFile(const std::string &file,
                        BinaryBasicBlocks &bbs,
                        BinaryFunctions &functions) {
    std::ifstream input(file);
    mcsema::Module module;

    if (!module.ParseFromIstream(&input)) {
        llvm::errs() << "Parsing McSema module failed\n";

        return false;
    }

    for (const mcsema::Function &f : module.internal_funcs()) {
        std::stringstream ss;

        if (!f.name().empty()) {
            ss << f.name();
        } else {
            ss << "sub_" << hexval(f.entry_address());
        }

        BinaryFunction *bf = new BinaryFunction(ss.str());
        functions.insert(bf);

        for (const mcsema::Block &b : f.blocks()) {
            if (b.insts_size() == 0) {
                continue;
            }

            auto iit_begin = b.insts().begin();
            auto iit_end = b.insts().end();
            auto iit = iit_begin;

            do {
                // Set default base address in case block turns out to be empty
                int64_t base_addr = b.base_address();
                int64_t last_addr;
                int64_t size = 0;

                if (iit != iit_end) {
                    base_addr = (*iit).inst_addr();
                }

                while (iit != iit_end) {
                    const mcsema::Instruction &i = *iit;
                    last_addr = i.inst_addr();
                    size += i.inst_len();
                    ++iit;

                    // The blocks returned by mcsema might not be properly
                    // terminated on instructions that change control flow
                    // such as calls, interrupts, etc. Split the blocks here.
                    if (IsTerminatorInstruction(i.inst_bytes())) {
                        break;
                    }
                }

                assert(base_addr <= last_addr);
                BinaryBasicBlock *binaryBb = new BinaryBasicBlock(base_addr,
                                                                  last_addr,
                                                                  size);
                bbs.insert(binaryBb);

                if (binaryBb->getStartPc() == (uint64_t) f.entry_address()) {
                    bf->setEntryBlock(binaryBb);
                }

                bf->add(binaryBb);
            } while (iit != iit_end);
        }

        // Go again through the list to update the successors
        for (const mcsema::Block &b : f.blocks()) {
            if (b.insts_size() == 0) {
                continue;
            }

            BinaryBasicBlock *binaryBb = bbs.find(b.base_address());
            assert(binaryBb);

            for (uint64_t follow : b.block_follows()) {
                BinaryBasicBlock *bb = bbs.find(follow);
                if (!bb) {
                    llvm::errs() << "Block " << hexval(b.base_address())
                                 << " has incorrect follower "
                                 << hexval(follow) << "\n";
                    continue;
                }

                binaryBb->addSucc(bb);
                bb->addPred(binaryBb);
            }
        }
    }
    return true;
}

bool ParseBBInfoFile(const std::string &file, BinaryBasicBlocks &bbs)
{
    const unsigned MAX_LINE = 512;
    char line[MAX_LINE];

    FILE *fp = fopen(file.c_str(), "r");
    if (!fp) {
        llvm::errs() << "Could not open " << file << "\n";
        return false;
    }

    while (fgets(line, MAX_LINE, fp)) {
        std::istringstream ss(line);
        std::string start, end, size, type_str, target_str;
        ss >> start >> end >> size >> type_str >> target_str;

        if (type_str == "c") {
            // Insert a call block
            bbs.insert(new BinaryBasicBlock(strtol(start.c_str(), NULL, 0),
                                            strtol(end.c_str(), NULL, 0),
                                            strtol(size.c_str(), NULL, 0),
                                            strtol(target_str.c_str(), NULL, 0)));
        } else {
            // Insert a normal block
            bbs.insert(new BinaryBasicBlock(strtol(start.c_str(), NULL, 0),
                                            strtol(end.c_str(), NULL, 0),
                                            strtol(size.c_str(), NULL, 0)));
        }
    }

    fclose(fp);
    return true;
}

bool ParseCfgFile(const std::string &file, BinaryBasicBlocks &bbs,
                  BinaryFunctions &functions)
{
    const unsigned MAX_LINE = 512;
    char line[MAX_LINE];

    FILE *fp = fopen(file.c_str(), "r");
    if (!fp) {
        llvm::errs() << "Could not open " << file << "\n";
        return false;
    }

    BinaryFunction *currentFunction = NULL;

    while (fgets(line, MAX_LINE, fp)) {
        std::istringstream ss(line);

        if (strstr(line, "function")) {
            std::string dummy, address_str, function_name;
                uint64_t address;
            ss >> dummy >> address_str >> function_name;

            if (function_name.size() == 0) {
                function_name = "<unknown>";
            }

            address = strtol(address_str.c_str(), NULL, 0);

            BinaryBasicBlock *bb = bbs.find(address);
            assert(bb && "Could not find entry point basic block");

            currentFunction = new BinaryFunction(function_name, bb);
            functions.insert(currentFunction);
        } else {
            std::string bb_str;
            uint64_t bb_addr;

            ss >> bb_str;
            bb_addr = strtol(bb_str.c_str(), NULL, 0);
            if (!bb_addr) {
                continue;
            }

            BinaryBasicBlock *bb = bbs.find(bb_addr);
            if (!bb) {
                llvm::errs() << "Warning: bb " << hexval(bb_addr) << " is undefined\n";
                continue;
            }

            BinaryBasicBlock::Children succs;
            while (!ss.eof()) {
                std::string edge_str;
                uint64_t edge_addr = 0;
                ss >> edge_str;
                edge_addr = strtol(edge_str.c_str(), NULL, 0);
                if (!edge_addr) {
                    continue;
                }

                BinaryBasicBlock *edge = bbs.find(edge_addr);
                if (edge) {
                    succs.push_back(edge);
                }
            }

            currentFunction->add(bb, succs);
        }
    }

    fclose(fp);
    return true;
}

} // namespace llvm
