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

#ifndef S2E_TOOLS_BINARY_CFG_READER_H
#define S2E_TOOLS_BINARY_CFG_READER_H

#include "CFG/BinaryCFG.h"

namespace llvm {

///
/// \brief Parse a CFG file produced by Trail of Bits' McSema tool.
///
/// \param file Path to the McSema CFG file to read
/// \param basicBlocks An ordered set of basic blocks read from the input file
/// \param functions An unordered set of functions read from the input file
/// \return \c true on success, \c false on failure
///
bool ParseMcSemaCfgFile(const std::string &file,
                        BinaryBasicBlocks &basicBlocks,
                        BinaryFunctions &functions);

///
/// \brief Parse a basic block information file produced by the S2E analysis
/// tool.
///
/// \param file Path to the basic block information file to read
/// \param basicBlocks An ordered set of basic blocks read from the input file
/// \t return \c true on success, \c false on failure
///
bool ParseBBInfoFile(const std::string &file,
                     BinaryBasicBlocks &basicBlocks);

///
/// \brief Parse a CFG file produced by the S2E analysis tool.
///
/// \param file path to the CFG file to read
/// \param basicBlocks An ordered set of basic blocks read from the input file
/// \param functions An unordered set of functions read from the input file
/// \return \c true on success, \c false on failure
bool ParseCfgFile(const std::string &file,
                  BinaryBasicBlocks &basicBlocks,
                  BinaryFunctions &functions);

} // namespace llvm

#endif
