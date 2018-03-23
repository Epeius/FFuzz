///
/// Copyright (C) 2015-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <s2e/cpu.h>

#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <llvm/Support/CommandLine.h>
#include <klee/util/ExprTemplates.h>

#include <s2e/Plugins/FunctionMonitor.h>
#include <algorithm>

#include "StaticLibraryFunctionModels.h"

using namespace klee;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(StaticLibraryFunctionModels, "Plugin that implements models for statically-linked libraries", //
        "", "ModuleExecutionDetector", "Vmi");

/**
 * Sample s2e-config.lua to use this plugin:
 *
 * pluginsConfig.StaticLibraryFunctionModels = {
 *   modules = {}
 * }
 *
 * g_function_models = {}
 *
 * g_function_models["TNETS_00002_patched"] = {}
 * g_function_models["TNETS_00002_patched"][0x8049b20] = {
 *   type="strlen",
 *   accepts_null_input = true,
 * }
 *
 * pluginsConfig.StaticLibraryFunctionModels.modules = g_function_models
 */

// TODO: replace this with a stack frame bound, check for mapped memory page, ...
#define MAX_STRLEN  4096

StaticLibraryFunctionModels::~StaticLibraryFunctionModels()
{
    foreach2(it, m_binaries.begin(), m_binaries.end())
    {
        delete it->second.fp;
        delete it->second.ef;
    }
    m_binaries.clear();
}

void StaticLibraryFunctionModels::initialize()
{
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();
    m_vmi = s2e()->getPlugin<Vmi>();

    m_detector->onModuleTranslateBlockEnd.connect( //
            sigc::mem_fun(*this, &StaticLibraryFunctionModels::onModuleTranslateBlockEnd));

    m_handlers["strlen"] = &StaticLibraryFunctionModels::handleStrlenExplicit;
    m_handlers["strcmp"] = &StaticLibraryFunctionModels::handleStrcmpExplicit;
    m_handlers["strncmp"] = &StaticLibraryFunctionModels::handleStrncmpExplicit;
    m_handlers["memcmp"] = &StaticLibraryFunctionModels::handleMemcmpExplicit;

    m_handlers["nop"] = &StaticLibraryFunctionModels::handleNop;

    m_handlers["strtol"] = &StaticLibraryFunctionModels::handleStrtolExplicit;

    getInfoStream() << "Model count: " << getFunctionModelCount() << "\n";

#if 0
    m_handlers["strncmp"] = &StaticLibraryFunctionModels::handleStrncmp;
    m_handlers["strsep"] = &StaticLibraryFunctionModels::handleStrsep;
    m_handlers["strcpy"] = &StaticLibraryFunctionModels::handleStrcpy;
    m_handlers["strtok"] = &StaticLibraryFunctionModels::handleStrtok;
    m_handlers["strtol"] = &StaticLibraryFunctionModels::handleStrtol;
    m_handlers["strchr"] = &StaticLibraryFunctionModels::handleStrchr;
    m_handlers["strstr"] = &StaticLibraryFunctionModels::handleStrstr;
    m_handlers["memcmp"] = &StaticLibraryFunctionModels::handleMemcmp;

    m_handlers["printf"] = &StaticLibraryFunctionModels::handlePrintf;
    m_handlers["_printf"] = &StaticLibraryFunctionModels::handlePrintf;
    m_handlers["fdprintf"] = &StaticLibraryFunctionModels::handleFdprintf;
    m_handlers["vprintf"] = &StaticLibraryFunctionModels::handleVprintf;
    m_handlers["fprintf"] = &StaticLibraryFunctionModels::handleFprintf;
    m_handlers["vsnprintf"] = &StaticLibraryFunctionModels::handleVsnprintf;
#endif
}

///
/// \brief Returns how many function models are available.
///
unsigned StaticLibraryFunctionModels::getFunctionModelCount() const
{
    ConfigFile *cfg = s2e()->getConfig();
    return cfg->getInt(getConfigKey() + ".count");
}

bool StaticLibraryFunctionModels::getBool(S2EExecutionState *state, const std::string &property)
{
    std::stringstream ss;
    const ModuleDescriptor *module = m_detector->getModule(state, state->getPc());
    assert(module);

    ss << getConfigKey()
       << ".modules[\""
       << module->Name
       << "\"]"
       << "["
       << hexval(state->getPc())
       << "]"
       << "."
       << property;

    return s2e()->getConfig()->getBool(ss.str());
}

void StaticLibraryFunctionModels::onModuleTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
        const ModuleDescriptor &module, TranslationBlock *tb, uint64_t endPc,
        bool staticTarget, uint64_t targetPc)
{
    /* Only instrument direct calls */
    if (!staticTarget || tb->se_tb_type != TB_CALL) {
        return;
    }

    /* Check if we call a known string function */
    uint64_t pc = module.ToNativeBase(targetPc);

    std::stringstream ss;
    ss << getConfigKey() << ".modules[\"" << module.Name << "\"]" << "[" << hexval(pc) << "]";

    ConfigFile *cfg = s2e()->getConfig();
    bool oldSilent = cfg->isSilent();
    cfg->setSilent(true);

    bool ok;
    std::string type = cfg->getString(ss.str() + ".type", "", &ok);
    if (!ok) {
        return;
    }

    getDebugStream(state) << "Found function type " << type << "\n";

    HandlerMap::const_iterator it = m_handlers.find(type);
    if (it == m_handlers.end()) {
        return;
    }

    getDebugStream(state) << "Found handler for function type " << type << "\n";

    signal->connect(sigc::bind(sigc::mem_fun(*this, &StaticLibraryFunctionModels::onCall), (*it).second));

    cfg->setSilent(oldSilent);
}

void StaticLibraryFunctionModels::onCall(S2EExecutionState *state, uint64_t pc,
        StaticLibraryFunctionModels::OpHandler handler)
{
    state->undoCallAndJumpToSymbolic();

    bool handled = ((*this).*handler)(state, pc);
    if (handled) {
        state->bypassFunction(0);
    } else {
        getDebugStream(state) << "Handling function at PC " << hexval(pc) << " failed, falling back to original code\n";
    }
}

ref<Expr> StaticLibraryFunctionModels::readMemory8(S2EExecutionState *state, uint64_t addr)
{
    ref<Expr> expr = state->readMemory8(addr);
    if (!expr.isNull()) {
        return expr;
    }

    /* Try to read data from executable image */

    const ModuleDescriptor *module = m_detector->getCurrentDescriptor(state);
    if (!module) {
        getDebugStream(state) << "No current module\n";
        return ref<Expr>(NULL);
    }

    vmi::ExecutableFile *file;
    std::map<std::string, Vmi::BinData>::const_iterator it = m_binaries.find(module->Name);
    if (it == m_binaries.end()) {
        Vmi::BinData bindata = m_vmi->getFromDisk(*module, false);
        if (!bindata.ef) {
            getDebugStream(state) << "No executable file for " << module->Name << "\n";
            return ref<Expr>(NULL);
        }
        m_binaries[module->Name] = bindata;
        file = bindata.ef;
    } else {
        file = it->second.ef;
    }

    bool addrInSection = false;
    const vmi::Sections &sections = file->getSections();
    foreach2(it, sections.begin(), sections.end())
    {
        if (it->start <= addr && addr + sizeof(char) <= it->start + it->size) {
            addrInSection = true;
            break;
        }
    }
    if (!addrInSection) {
        getDebugStream(state) << "Address " << hexval(addr) << " is not in any section of " << module->Name << "\n";
        return ref<Expr>(NULL);
    }

    uint8_t byte;
    ssize_t size = file->read(&byte, sizeof(byte), addr);
    if (size != sizeof(byte)) {
        getDebugStream(state) << "Failed to read byte at " << hexval(addr) << " in " << module->Name << "\n";
        return ref<Expr>(NULL);
    }

    expr = E_CONST(byte, Expr::Int8);

    return expr;
}

bool StaticLibraryFunctionModels::readArgument(S2EExecutionState *state, unsigned param, uint64_t &arg)
{
    target_ulong ret;

    uint64_t addr = state->getSp() + (param + 1) * state->getPointerSize();

    // First check if argument is symbolic
    ref<Expr> readArg = state->mem()->readMemory(addr, state->getPointerWidth());
    if(!isa<ConstantExpr>(readArg)) {
        getDebugStream(state) << "[readArgument] Argument " << param << " at " << hexval(addr) << " is symbolic\n";
        return false;
    }

    // If not, read concrete value
    bool ok = state->readPointer(addr, ret);

    if (!ok) {
        getDebugStream(state) << "Failed to read argument " << param << " at " << hexval(addr) << "\n";
        return false;
    }

    arg = ret;
    return true;
}

bool StaticLibraryFunctionModels::findNullChar(S2EExecutionState *state, uint64_t stringAddr, size_t &len)
{
    /* Find char that must be NULL */

    assert(stringAddr);

    getDebugStream(state) << "Searching for NULL at " << hexval(stringAddr) << "\n";

    Solver *solver = s2e()->getExecutor()->getSolver(*state);
    const ref<Expr> nullByteExpr = E_CONST('\0', Expr::Int8);

    for (len = 0; len < MAX_STRLEN; len++) {
        assert(stringAddr <= UINT64_MAX - len);
        ref<Expr> charExpr = readMemory8(state, stringAddr + len);
        if (charExpr.isNull()) {
            getDebugStream(state) << "Failed to read char " << len << " of string " << hexval(stringAddr) << "\n";
            return false;
        }

        ref<Expr> isNullByteExpr = E_EQ(charExpr, nullByteExpr);
        Query query(state->constraints, isNullByteExpr);

        bool truth;
        bool res = solver->mustBeTrue(query, truth);
        if (res && truth) {
            break;
        }
    }

    if (len == MAX_STRLEN) {
        getDebugStream(state) << "Could not find NULL char\n";
        return false;
    }

    getDebugStream(state) << "Max length " << len << "\n";

    return true;
}

bool StaticLibraryFunctionModels::handleStrlenExplicit(S2EExecutionState *state, uint64_t pc)
{
    getDebugStream(state) << __FUNCTION__ << "\n";

    /* Read function arguments */

    uint64_t stringAddr;
    if (!readArgument(state, 0, stringAddr)) {
        getDebugStream(state) << "Failed to read stringAddr argument\n";
        return false;
    }

    getDebugStream(state) << "Handling strlen(" << hexval(stringAddr) << ")\n";

    if (!stringAddr) {
        getDebugStream(state) << "Got NULL input\n";
        return false;
    }

    /* Get string properties */

    // length left after the given char
    size_t currLen;
    if (!findNullChar(state, stringAddr, currLen)) {
        getDebugStream(state) << "Failed to find NULL char in string " << hexval(stringAddr) << "\n";
        return false;
    }

    /*
     * This is how we assemble the expression.
     *
     * nr = 0       ITE( ( s[0] == '\0' ), 0,
     * nr = 1       ITE( ( s[1] == '\0' ), 1,
     * nr = 2       ITE( ( s[2] == '\0' ), 2, 3 ) ) )
     */

    const Expr::Width width = state->getPointerSize() * CHAR_BIT;
    const ref<Expr> nullByteExpr = E_CONST('\0', Expr::Int8);

    ref<Expr> retExpr = E_CONST(currLen, width);

    for (int nr = (int) currLen - 1; nr >= 0; nr--) {
        ref<Expr> charExpr = readMemory8(state, stringAddr + nr);
        if (charExpr.isNull()) {
            getDebugStream(state) << "Failed to read char " << nr << " of string " << hexval(stringAddr) << "\n";
            return false;
        }

        retExpr = E_ITE(E_EQ(charExpr, nullByteExpr), E_CONST(nr, width), retExpr);
    }

    state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), retExpr);

    return true;
}

bool StaticLibraryFunctionModels::stringCompareExplicit(S2EExecutionState *state, bool hasMaxSize)
{
    /* Read function arguments */

    uint64_t stringAddr[2];
    uint64_t maxSize;

    for (int i = 0; i < 2; i++) {
        if (!readArgument(state, i, stringAddr[i])) {
            getDebugStream(state) << "Failed to read stringAddr argument\n";
            return false;
        }
    }

    if (hasMaxSize) {
        if (!readArgument(state, 2, maxSize)) {
            getDebugStream(state) << "Failed to read maxSize argument\n";
            return false;
        }
    }

    if (!hasMaxSize) {
        getDebugStream(state) << "Handling strcmp(" << hexval(stringAddr[0]) << ", " << hexval(stringAddr[1]) << ")\n";
    } else {
        getDebugStream(state) << "Handling strncmp("
                              << hexval(stringAddr[0])
                              << ", "
                              << hexval(stringAddr[1])
                              << ", "
                              << maxSize
                              << ")\n";
    }

    if (!stringAddr[0] || !stringAddr[1]) {
        getDebugStream(state) << "Got NULL input\n";
        return false;
    }

    if (hasMaxSize && maxSize == 0) {
        getDebugStream(state) << "Max size is zero\n";
        state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), 0);
        return true;
    }

    /* Get string properties */

    size_t currLen[2]; // length left after the given char

    for (int i = 0; i < 2; i++) {
        if (!findNullChar(state, stringAddr[i], currLen[i])) {
            getDebugStream(state) << "Failed to find NULL char in string " << hexval(stringAddr[i]) << "\n";
            return false;
        }
    }

    size_t memSize = std::min(currLen[0], currLen[1]) + 1;
    if (hasMaxSize) {
        memSize = std::min(memSize, maxSize);
    }

    getDebugStream(state) << "Comparing " << memSize << " chars\n";

    /*
     * This is how we assemble the expression.
     *
     * nr = 0       ITE( s1[0] < s2[0],                  -1,
     *              ITE( s1[0] > s2[0],                  +1,
     *              ITE( s1[0] == '\0' && s2[0] == '\0',  0,
     * nr = 1       ITE( s1[1] < s2[1],                  -1,
     *              ITE( s1[1] > s2[1],                  +1,
     *              ITE( s1[1] == '\0' && s2[1] == '\0',  0,
     * nr = 2       ITE( s1[2] < s2[2],                  -1,
     *              ITE( s1[2] > s2[2],                  +1, 0 ) ) ) ) ) ) ) )
     */

    const Expr::Width width = state->getPointerSize() * CHAR_BIT;

    const ref<Expr> nullByteExpr = E_CONST('\0', Expr::Int8);

    assert(width == Expr::Int32 && "-1 representation becomes wrong");
    const ref<Expr> retNegExpr = E_CONST(UINT32_MAX, width);
    const ref<Expr> retZeroExpr = E_CONST(0, width);
    const ref<Expr> retPosExpr = E_CONST(1, width);

    ref<Expr> retExpr;

    for (int nr = memSize - 1; nr >= 0; nr--) { // also compare null char
        ref<Expr> charExpr[2];
        for (int i = 0; i < 2; i++) {
            charExpr[i] = readMemory8(state, stringAddr[i] + nr);
            if (charExpr[i].isNull()) {
                getDebugStream(state) << "Failed to read char " << nr << " of string " << hexval(stringAddr[i]) << "\n";
                return false;
            }
        }

        if ((unsigned) nr == memSize - 1) {
            retExpr = E_ITE(E_GT(charExpr[0], charExpr[1]), retPosExpr, retZeroExpr);
            retExpr = E_ITE(E_LT(charExpr[0], charExpr[1]), retNegExpr, retExpr);
        } else {
            retExpr = E_ITE(E_AND(E_EQ(charExpr[0], nullByteExpr), E_EQ(charExpr[1], nullByteExpr)), retZeroExpr, retExpr);
            retExpr = E_ITE(E_GT(charExpr[0], charExpr[1]), retPosExpr, retExpr);
            retExpr = E_ITE(E_LT(charExpr[0], charExpr[1]), retNegExpr, retExpr);
        }
    }

    bool inverted = getBool(state, "inverted");
    if (inverted) {
        getDebugStream(state) << "strcmp returns inverted result\n";
        retExpr = E_SUB(E_CONST(0, width), retExpr);
    }

    state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), retExpr);

    return true;
}

bool StaticLibraryFunctionModels::handleStrcmpExplicit(S2EExecutionState *state, uint64_t pc)
{
    getDebugStream(state) << __FUNCTION__ << "\n";

    return stringCompareExplicit(state, false);
}

bool StaticLibraryFunctionModels::handleStrncmpExplicit(S2EExecutionState *state, uint64_t pc)
{
    getDebugStream(state) << __FUNCTION__ << "\n";

    return stringCompareExplicit(state, true);
}

bool StaticLibraryFunctionModels::handleMemcmpExplicit(S2EExecutionState *state, uint64_t pc)
{
    getDebugStream(state) << __FUNCTION__ << "\n";

    /* Read function arguments */

    uint64_t memAddr[2];
    uint64_t memSize;

    for (int i = 0; i < 2; i++) {
        if (!readArgument(state, i, memAddr[i])) {
            getDebugStream(state) << "Failed to read memAddr argument\n";
            return false;
        }
    }
    if (!readArgument(state, 2, memSize)) {
        getDebugStream(state) << "Failed to read memSize argument\n";
        return false;
    }

    getDebugStream(state) << "Handling memcmp("
                          << hexval(memAddr[0])
                          << ", "
                          << hexval(memAddr[1])
                          << ", "
                          << memSize
                          << ")\n";

    if (!memAddr[0] || !memAddr[1] || !memSize) {
        getDebugStream(state) << "Got NULL input\n";
        return false;
    }
    if (memSize > MAX_STRLEN) {
        getDebugStream(state) << "Got too big input\n";
        return false;
    }

    /*
     * This is how we assemble the expression.
     *
     * nr = 0       ITE( s1[0] != s2[0], s1[0] - s2[0],
     * nr = 1       ITE( s1[1] != s2[1], s1[1] - s2[1],
     * nr = 2       ITE( s1[2] != s2[2], s1[2] - s2[2], 0 ) ) )
     *
     */

    const Expr::Width width = state->getPointerSize() * CHAR_BIT;

    ref<Expr> retExpr = E_CONST(0, width);

    for (int nr = memSize - 1; nr >= 0; nr--) {
        ref<Expr> charExpr[2];
        for (int i = 0; i < 2; i++) {
            charExpr[i] = readMemory8(state, memAddr[i] + nr);
            if (charExpr[i].isNull()) {
                getDebugStream(state) << "Failed to read byte " << nr << " of memory " << hexval(memAddr[i]) << "\n";
                return false;
            }
        }

        retExpr = E_ITE(E_NEQ(charExpr[0], charExpr[1]), E_SUBZE(charExpr[0], charExpr[1], width), retExpr);
    }

    bool inverted = getBool(state, "inverted");
    if (inverted) {
        getDebugStream(state) << "memcmp returns inverted result\n";
        retExpr = E_SUB(E_CONST(0, width), retExpr);
    }

    state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), retExpr);

    return true;
}

bool StaticLibraryFunctionModels::handleStrtolExplicit(S2EExecutionState *state, uint64_t pc)
{
    getDebugStream(state) << __FUNCTION__ << "\n";

    /* Read function arguments */

    uint64_t stringAddr;
    uint64_t endAddr;
    uint64_t base;

    if (!readArgument(state, 0, stringAddr)) {
        getDebugStream(state) << "Failed to read stringAddr argument\n";
        return false;
    }

    if (!readArgument(state, 1, endAddr)) {
        getDebugStream(state) << "Failed to read endAddr argument\n";
        return false;
    }

    if (!readArgument(state, 2, base)) {
        getDebugStream(state) << "Failed to read base argument\n";
        return false;
    }

    getDebugStream(state) << "Handling strtol("
                          << hexval(stringAddr)
                          << ", "
                          << hexval(endAddr)
                          << ", "
                          << base
                          << ")\n";

    if (!stringAddr) {
        getDebugStream(state) << "Got NULL input\n";
        return false;
    }

    if (endAddr != 0) {
        getDebugStream(state) << "Unsupported option\n";
        return false;
    }

    if (base != 10) {
        getDebugStream(state) << "Unsupported base\n";
        return false;
    }

    /* Get string properties */

    size_t strLen; // length left after the given char

    if (!findNullChar(state, stringAddr, strLen)) {
        getDebugStream(state) << "Failed to find NULL char in string " << hexval(stringAddr) << "\n";
        return false;
    }

    /* Assemble the expression */

    if (strLen == 0) {
        getDebugStream(state) << "Zero length string\n";
        state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), 0);
        return true;
    } else {
        ref<Expr> charExpr = readMemory8(state, stringAddr);
        if (charExpr.isNull()) {
            getDebugStream(state) << "Failed to read char 0 of string " << hexval(stringAddr) << "\n";
            return false;
        }

        const ref<Expr> nullByteExpr = E_CONST('\0', Expr::Int8);
        const Expr::Width width = state->getPointerSize() * CHAR_BIT;

        ref<Expr> retExpr = E_CONST(0, width);
        for (int i = 1; i <= 9; i++) {
            retExpr = E_ITE(E_EQ(charExpr, E_CONST('0' + i, Expr::Int8)), E_CONST(i, width), retExpr);
        }

        if (strLen > 1) {
            ref<Expr> termCharExpr = readMemory8(state, stringAddr + 1);
            if (termCharExpr.isNull()) {
                getDebugStream(state) << "Failed to read char 1 of string " << hexval(stringAddr) << "\n";
                return false;
            }

            assert(width == Expr::Int32 && "-1 representation becomes wrong");
            retExpr = E_ITE(E_EQ(termCharExpr, nullByteExpr), retExpr, E_CONST(UINT32_MAX, width));
        }

        state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), retExpr);
        return true;
    }
}

bool StaticLibraryFunctionModels::handleNop(S2EExecutionState *state, uint64_t pc)
{
    getDebugStream(state) << __FUNCTION__ << "\n";
    return true;
}

bool StaticLibraryFunctionModels::handleStrsep(S2EExecutionState *state, uint64_t pc)
{
    getDebugStream(state) << __FUNCTION__ << "\n";
    return false;
}

bool StaticLibraryFunctionModels::handleStrcpy(S2EExecutionState *state, uint64_t pc)
{
    getDebugStream(state) << __FUNCTION__ << "\n";
    return false;
}

bool StaticLibraryFunctionModels::handleStrtok(S2EExecutionState *state, uint64_t pc)
{
    getDebugStream(state) << __FUNCTION__ << "\n";
    return false;
}

bool StaticLibraryFunctionModels::handleStrchr(S2EExecutionState *state, uint64_t pc)
{
    getDebugStream(state) << __FUNCTION__ << "\n";
    return false;
}

bool StaticLibraryFunctionModels::handleStrstr(S2EExecutionState *state, uint64_t pc)
{
    getDebugStream(state) << __FUNCTION__ << "\n";
    return false;
}

bool StaticLibraryFunctionModels::handleMemcmp(S2EExecutionState *state, uint64_t pc)
{
    getDebugStream(state) << __FUNCTION__ << "\n";
    return false;
}

void StaticLibraryFunctionModels::readSymbolicString(S2EExecutionState *state, uint64_t concretePtr,
        std::vector<ref<Expr> > &ret)
{
    /* Check if there are any symbolic bytes in this ptr */
    unsigned i = 0;
    do {
        klee::ref<klee::Expr> byte = state->mem()->readMemory(concretePtr + i, klee::Expr::Int8);
        if (byte.isNull()) {
            getDebugStream(state) << "Could not read byte at " << hexval(concretePtr + i) << "\n";
            break;
        }

        ret.push_back(byte);

        if (isa<ConstantExpr>(byte)) {
            /* Check for null character */
            ref<ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(byte);
            if (!ce->getZExtValue()) {
                break;
            }
        }
        ++i;
    } while (true);
}

void StaticLibraryFunctionModels::printString(S2EExecutionState *state, std::vector<ref<Expr> > &str,
        llvm::raw_ostream &ofs)
{
    foreach2(it, str.begin(), str.end())
    {
        ref<Expr> e = *it;
        if (e.isNull()) {
            break;
        } else if (isa<ConstantExpr>(*it)) {
            ref<ConstantExpr> ce = dyn_cast<ConstantExpr>(*it);
            ofs << (char) ce->getZExtValue();
        } else {
            ofs << *it << " ";
        }
    }
    ofs << "\n";
}

void StaticLibraryFunctionModels::checkFormatString(S2EExecutionState *state, uint64_t paramIndex)
{
    klee::ref<klee::Expr> ptr = FunctionMonitor::readParameter(state, paramIndex);
    if (ptr.isNull()) {
        getDebugStream(state) << "Could not read format string parameter\n";
        return;
    }

    if (!isa<klee::ConstantExpr>(ptr)) {
        getDebugStream(state) << "Format string pointer is symbolic " << ptr << "\n";
        //TODO: try to stretch the pointer to create a crash
        return;
    }

    ref<ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(ptr);
    uint64_t concretePtr = ce->getZExtValue();

    /* Check if there are any symbolic bytes in this ptr */
    unsigned i = 0;
    do {
        klee::ref<klee::Expr> byte = state->mem()->readMemory(concretePtr + i, klee::Expr::Int8);
        if (byte.isNull()) {
            getDebugStream(state) << "Could not read byte at " << hexval(concretePtr + i) << "\n";
        } else if (!isa<klee::ConstantExpr>(byte)) {
            getDebugStream(state) << "Byte " << i << " of format string is symbolic: " << byte << "\n";
        } else {
            /* Check for null character */
            ref<ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(byte);
            if (!ce->getZExtValue()) {
                break;
            }
        }
        ++i;
    } while (true);
}

bool StaticLibraryFunctionModels::handlePrintf(S2EExecutionState *state, uint64_t pc)
{
    getDebugStream(state) << __FUNCTION__ << "\n";
    checkFormatString(state, 0);
    return true;
}

bool StaticLibraryFunctionModels::handleFdprintf(S2EExecutionState *state, uint64_t pc)
{
    getDebugStream(state) << __FUNCTION__ << "\n";
    checkFormatString(state, 1);
    return true;
}

bool StaticLibraryFunctionModels::handleVprintf(S2EExecutionState *state, uint64_t pc)
{
    getDebugStream(state) << __FUNCTION__ << "\n";
    return false;
}

bool StaticLibraryFunctionModels::handleFprintf(S2EExecutionState *state, uint64_t pc)
{
    getDebugStream(state) << __FUNCTION__ << "\n";
    return false;
}

bool StaticLibraryFunctionModels::handleVsnprintf(S2EExecutionState *state, uint64_t pc)
{
    getDebugStream(state) << __FUNCTION__ << "\n";
    return false;
}

} // namespace plugins
} // namespace s2e
