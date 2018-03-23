///
/// Copyright (C) 2014-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <s2e/cpu.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/FastReg.h>
#include <s2e/Plugins/Vmi.h>
#include <s2e/Plugins/Screenshot.h>

#include <vmi/PEFile.h>

#include <sstream>
#include <llvm/Support/Path.h>
#include <llvm/Support/TimeValue.h>

#include <boost/algorithm/string.hpp>

#include "SimpleCFIChecker.h"

namespace s2e {
namespace plugins {

//#define SCFI_DUMP_TABLES

#define MOVING_AVERAGE_ALPHA 0.4
#define MIN_TIMER_TICKS 200
#define TIMER_TICK_GRANULARITY 5
#define IDLE_JIT_CODE_CALL_COUNT_AVERAGE 10

typedef enum S2E_CFI_COMMAND {
    DONE,
    FYI,
    TAKE_SCREENSHOT,
    WINDOW_TEXT
} S2E_CFI_COMMAND;

typedef struct S2E_CFI {
    S2E_CFI_COMMAND command;
    uint64_t ptr_info;
} S2E_CFI;


S2E_DEFINE_PLUGIN(SimpleCFIChecker, "Simple CFI checker", "",
                  "WindowsMonitor2", "ModuleMap", "Vmi", "MemoryMap");

//#define USE_SHADOW_STACK

#ifdef USE_SHADOW_STACK
typedef llvm::DenseMap<std::pair<uint64_t, uint64_t>, uint64_t> ShadowStack;
#else
#if 0
static uint64_t getTid(S2EExecutionState *state, unsigned pointerSize) {
    int reg = pointerSize == 4 ? R_FS : R_GS;
    return state->regs()->read<uint64_t>(CPU_OFFSET(segs[reg].base));
}
#endif
#endif

extern "C" {
    void *g_invokeCallRetInstrumentation;
}

static SimpleCFIChecker *s_checker;

struct ThreadCfiState
{
    /* true to delay the violation report */
    bool confirmViolation;
    uint8_t stage;

    /**
     * In case of a first violation, check that the
     * (callee, pid, tid) is executed. If there is
     * a crash in the meantime, ignore the violation.
     */
    bool isCall;
    uint64_t pc, pid, tid;

    uint64_t second_stage_pc;
};

class SimpleCFICheckerState: public PluginState {
public:
    TrackedPids m_trackedPids;

    llvm::DenseMap<uint64_t, FunctionsSet> m_functions;
    std::set<ModuleDescriptor, ModuleDescriptor::ModuleByName> m_ignoredModules;

    std::set<AddressRange> m_addressRanges;
#ifdef USE_SHADOW_STACK
    ShadowStack m_shadowStack;
#else
    StacksMap m_returnStacks;
    AddressMap *m_currentReturnStack;
#endif

    uint64_t m_callCount;
    uint64_t m_retCount;
    uint64_t m_callViolationCount;
    uint64_t m_retViolationCount;
    uint64_t m_segFaultCount;
    uint64_t m_werFaultCount;

    uint64_t m_JITCallCount;
    uint64_t m_JITCallCountPrev;
    uint64_t m_JITCallCountAverage;

    uint64_t m_screenshotID;

    typedef std::pair<uint64_t, uint64_t> PidTidPair;
    typedef llvm::DenseMap<PidTidPair, bool> IgnoreNextReturn;
    typedef llvm::DenseMap<PidTidPair, ThreadCfiState> PerThreadCfiState;

    /* Address of the function whose returns should not be checked */
    /* XXX: support only one for now */
    llvm::DenseSet<uint64_t> m_functionsWithIgnoredReturn;
    IgnoreNextReturn m_ignoreNextReturns;
    PerThreadCfiState m_perThreadCfiState;

    virtual SimpleCFICheckerState* clone() const {
        assert(0); // XXX
        ///XXX: must copy the interval map
        return NULL;
        //SimpleCFICheckerState *ret = new SimpleCFICheckerState(m_jitRegionsAlloc);
        //return ret;
    }

    SimpleCFICheckerState() {
        m_callCount = 0;
        m_retCount = 0;
        m_callViolationCount = 0;
        m_retViolationCount = 0;
        m_segFaultCount = 0;
        m_werFaultCount = 0;

        m_JITCallCount = 0;
        m_JITCallCountPrev = 0;
        m_JITCallCountAverage = 0;

        m_screenshotID = 0;
        m_currentReturnStack = 0;
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new SimpleCFICheckerState();
    }

    virtual ~SimpleCFICheckerState() {

    }

    bool inAnyAddressRange(uint64_t address) {
        for (auto ar : m_addressRanges) {
            if (address >= ar.first && address < ar.second) {
                return true;
            }
        }
        return false;
    }

    QDict *getStatistics() const {
        QDict *ret = qdict_new();
        qdict_put_obj(ret, "call_count", QOBJECT(qint_from_int(m_callCount)));
        qdict_put_obj(ret, "ret_count", QOBJECT(qint_from_int(m_retCount)));
        qdict_put_obj(ret, "call_violation_count", QOBJECT(qint_from_int(m_callViolationCount)));
        qdict_put_obj(ret, "ret_violation_count", QOBJECT(qint_from_int(m_retViolationCount)));
        qdict_put_obj(ret, "seg_fault_count", QOBJECT(qint_from_int(m_segFaultCount)));
        qdict_put_obj(ret, "wer_fault_count", QOBJECT(qint_from_int(m_werFaultCount)));
        return ret;
    }
};

void SimpleCFIChecker::initialize()
{
    m_map = s2e()->getPlugin<ModuleMap>();
    m_vmi = s2e()->getPlugin<Vmi>();
    m_memory = s2e()->getPlugin<MemoryMap>();
    m_monitor = dynamic_cast<WindowsMonitor2*>(s2e()->getPlugin("Interceptor"));

    if (!m_monitor) {
        getWarningsStream() << "requires WindowsMonitor2\n";
        exit(-1);
    }

    ConfigFile *cfg = s2e()->getConfig();

    bool ok = false;

    m_verbose = cfg->getBool(getConfigKey() + ".verbose");

    /**
     * If an indirect call or a return go to an invalid address,
     * do not report the violations.
     */
    m_ignoreViolationOnCrash = cfg->getBool(getConfigKey() + ".ignoreViolationOnCrash");

    m_clockSlowDownFactor = cfg->getInt(getConfigKey() + ".clockSlowDownFactor", 10);

    m_dumpRegions = true;

    //Fetch the list of modules where to report the calls
    ConfigFile::string_list moduleList =
            cfg->getStringList(getConfigKey() + ".moduleNames", ConfigFile::string_list(), &ok);

    if (moduleList.empty()) {
        getWarningsStream() << "no modules configured\n";
        exit(-1);
    }

    foreach2(it, moduleList.begin(), moduleList.end()) {
        m_trackedModules.insert(*it);
    }


    moduleList =
            cfg->getStringList(getConfigKey() + ".whiteListedModulePaths", ConfigFile::string_list(), &ok);

    foreach2(it, moduleList.begin(), moduleList.end()) {
        std::string l = *it;
        boost::to_lower(l);
        m_whiteListedModulePaths.insert(l);
    }

    ConfigFile::string_list whitelistedRetList;
    whitelistedRetList = cfg->getListKeys(getConfigKey() + ".whiteListedReturns");

    foreach2(it, whitelistedRetList.begin(), whitelistedRetList.end()) {
        std::string key = *it;
        std::stringstream s;
        s << getConfigKey() << ".whiteListedReturns." << key << ".";
        WhitelistedReturn wret;

        wret.src_checksum = cfg->getInt(s.str() + "srcChecksum");
        wret.src_addr = cfg->getInt(s.str() + "srcAddr");
        wret.dst_checksum = cfg->getInt(s.str() + "dstChecksum");
        wret.dst_addr = cfg->getInt(s.str() + "dstAddr");

        m_whitelistedReturns.insert(wret);
    }

    ConfigFile::string_list flushICacheList;
    flushICacheList = cfg->getListKeys(getConfigKey() + ".flushICacheList");

    foreach2(it, flushICacheList.begin(), flushICacheList.end()) {
        std::string key = *it;
        std::stringstream s;
        s << getConfigKey() << ".flushICacheList." << key << ".";

        uint32_t checksum = cfg->getInt(s.str() + "checksum");
        ConfigFile::integer_list addresses =
                cfg->getIntegerList(s.str() + "addresses", ConfigFile::integer_list(), &ok);

        if (ok) {
            foreach2(it, addresses.begin(), addresses.end()) {
                uint64_t addr = *it;
                m_flushInstructionCacheCalls[checksum].insert(addr);

                getDebugStream() << "Will instrument FlushInstructionCache call at " << hexval(addr)
                                 << " module checksum " << hexval(checksum) << "\n";
            }
        }
    }

    m_tracer = NULL;

    bool trace = s2e()->getConfig()->getBool(getConfigKey() + ".traceExecution", false);
    if (trace) {
        m_tracer = s2e()->getPlugin<UserSpaceTracer>();
        if (!m_tracer) {
            getWarningsStream() << "traceExecution requires UserSpaceTracer\n";
            exit(-1);
        }
    }

    m_firstTrackedModuleTime = 0;

    m_reportAccessFaults = s2e()->getConfig()->getBool(getConfigKey() + ".reportAccessFaults", false);


    m_monitor->onMonitorLoad.connect(
            sigc::mem_fun(*this,
                    &SimpleCFIChecker::onMonitorLoad)
            );

    m_monitor->onModuleLoad.connect(
            sigc::mem_fun(*this,
                    &SimpleCFIChecker::onModuleLoad)
            );

    m_monitor->onModuleUnload.connect(
            sigc::mem_fun(*this,
                    &SimpleCFIChecker::onModuleUnload)
            );

    m_monitor->onProcessLoad.connect(
            sigc::mem_fun(*this,
                    &SimpleCFIChecker::onProcessLoad)
            );

    m_monitor->onProcessUnload.connect(
            sigc::mem_fun(*this,
                    &SimpleCFIChecker::onProcessUnload)
            );

    m_monitor->onThreadExit.connect(
            sigc::mem_fun(*this,
                    &SimpleCFIChecker::onThreadExit)
            );

    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
            sigc::mem_fun(*this, &SimpleCFIChecker::onTranslateBlockStart));

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
                    sigc::mem_fun(*this, &SimpleCFIChecker::onTbEndInstrument));

    s2e()->getCorePlugin()->onCallReturnTranslate.connect(
            sigc::mem_fun(*this, &SimpleCFIChecker::onCfiCallReturnTranslate));

    s2e()->getCorePlugin()->onTranslateLeaRipRelative.connect(
            sigc::mem_fun(*this, &SimpleCFIChecker::onTranslateLeaRipRelative));

    s2e()->getCorePlugin()->onTranslateSpecialInstructionEnd.connect(
            sigc::mem_fun(*this, &SimpleCFIChecker::onTranslateSpecialInstructionEnd));

    m_monitor->onProcessOrThreadSwitch.connect(
            sigc::mem_fun(*this,
                    &SimpleCFIChecker::onProcessOrThreadSwitch)
            );

    //stop helpers
    m_terminateOnJITIdle = cfg->getBool(getConfigKey() + ".terminateOnJITIdle");
    m_timerCount = 0;
    m_timerTicks = 0;
    m_stopRequested = false;
    s2e()->getCorePlugin()->onTimer.connect(
            sigc::mem_fun(*this, &SimpleCFIChecker::onTimer));


    s_checker = this;
}

bool SimpleCFIChecker::isWhitelistedReturn(const ModuleDescriptor *src, uint64_t srcAddr, const ModuleDescriptor *dst, uint64_t dstAddr)
{
    WhitelistedReturn wret;
    uint64_t native_src;

    if (!src)
        return false;

    native_src = src->ToNativeBase(srcAddr);

    if (!dst) {
        /* Match on source module and address, wildcard on destination */
        for (auto w : m_whitelistedReturns) {
            if (w.src_addr == native_src && w.src_checksum == src->Checksum &&
                w.dst_addr == (uint64_t)-1 && w.dst_checksum == (uint32_t)-1) {
                return true;
            }
        }
        /* Match on source only */
        for (auto w : m_whitelistedReturns) {
            if (w.src_checksum == src->Checksum && w.src_addr == (uint64_t)-1 &&
                w.dst_addr == (uint64_t)-1 && w.dst_checksum == (uint32_t)-1) {
                return true;
            }
        }
        /* Can't continue, no 'dst' module */
        return false;
    }

    wret.src_addr = native_src;
    wret.src_checksum = src->Checksum;
    wret.dst_addr = dst->ToNativeBase(dstAddr);
    wret.dst_checksum = dst->Checksum;

    if (m_whitelistedReturns.find(wret) == m_whitelistedReturns.end())
            return false;

    return true;
}

bool SimpleCFIChecker::isGeneratedTrampoline(S2EExecutionState *state, uint64_t caller)
{
    const ModuleDescriptor *modCaller = m_map->getModule(state, caller);
    if (!modCaller) {
        return false;
    }
    auto addrList = m_flushInstructionCacheCalls.find(modCaller->Checksum);
    if (addrList != m_flushInstructionCacheCalls.end()) {
        return addrList->second.count(modCaller->ToNativeBase(caller));
    }
    return false;
}

void SimpleCFIChecker::onProcessOrThreadSwitch(S2EExecutionState *state)
{
    DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);

    uint64_t pid = m_monitor->getCurrentProcessId(state);
    uint64_t tid = m_monitor->getCurrentThreadId(state);

    if (plgState->m_trackedPids.find(pid) == plgState->m_trackedPids.end()) {
        plgState->m_currentReturnStack = NULL;
        g_invokeCallRetInstrumentation = NULL;
        g_s2e->getExecutor()->setClockSlowDown(1);
        return;
    }

    std::pair<uint64_t, uint64_t> pt = std::make_pair(pid, tid);
    plgState->m_currentReturnStack = &plgState->m_returnStacks[pt];
    g_invokeCallRetInstrumentation = plgState->m_currentReturnStack;

    g_s2e->getExecutor()->setClockSlowDown(m_clockSlowDownFactor);
}

/**
 * Normally, in case of a page fault that causes an application to crash, Windows
 * will call our custom JIT debugger, which will then notify the BugCollector plugin
 * of the crash. However, crashes sometimes don't result in the JIT debugger to
 * be called. Therefore, we hook the onAccessFault event directly. We could
 * implement it in BugCollector, but it's easier to put it here (we need filtering
 * by tracked process).
 * Also, the JIT debugger seems to mask some CFI violations for an unknown reason.
 * So, we catch these faults in the kernel.
 */
void SimpleCFIChecker::onAccessFault(S2EExecutionState *state, const S2E_WINMON2_ACCESS_FAULT &AccessFault)
{
    DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);

    if (!AccessFault.AccessMode) {
        return;
    }

    if ((uint32_t) AccessFault.StatusCode != 0xc0000005) {
        //Only report page faults
        return;
    }

    //XXX: getCurrentProcessId might fail in kernel mode, but it's ok here.
    uint64_t pid = m_monitor->getCurrentProcessId(state);

    if (plgState->m_trackedPids.find(pid) == plgState->m_trackedPids.end()) {
        return;
    }

    getDebugStream(pid, 0) << "Fatal page fault detected pid: " << hexval(pid)
                           << " address: " << hexval(AccessFault.Address)
                           << " um: " << (int) AccessFault.AccessMode
                           << "\n";

    ++plgState->m_segFaultCount;

    onCFIAccessFault.emit(state, AccessFault);
}


void SimpleCFIChecker::takeScreenShot(S2EExecutionState *state)
{
    Screenshot* ss = dynamic_cast<Screenshot*>(s2e()->getPlugin("Screenshot"));
    if (ss) {
        Plugin::getWarningsStream(state) << "SimpleCFI: taking screenshot\n";
        DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);
        std::stringstream stringStream;
        stringStream << "screenshot-" << state->getID() << "-" << (plgState->m_screenshotID++) << ".png";
        std::string outputFileName = s2e()->getOutputFilename(stringStream.str());
        ss->takeScreenShot(outputFileName);
    }
}


void SimpleCFIChecker::onWindowInfo(S2EExecutionState *state, std::string info)
{
    getDebugStream() << "Received window text info: " << info << "\n";
    onWindowTextSignal.emit(state, info);
}

void SimpleCFIChecker::onFYINotification(S2EExecutionState *state, std::string info)
{
    getDebugStream() << "Received FYI notification: " << info << "\n";
    onFYISignal.emit(state, info);
}

void SimpleCFIChecker::onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, const std::string &ImageFileName)
{
    if (m_trackedModules.find(ImageFileName) != m_trackedModules.end()) {
        DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);

        getDebugStream() << "starting to track: "
                         << ImageFileName << " (pid: " << hexval(pid)
                         << " as: " << hexval(pageDir) << ")\n";

        plgState->m_trackedPids.insert(pid);
        m_memory->trackPid(state, pid, true);

        if (!m_firstTrackedModuleTime) {
            m_firstTrackedModuleTime = llvm::sys::TimeValue::now().seconds();
            m_firstTrackedModuleTime -= s2e()->getStartTime();
        }
    }

    if (ImageFileName == "WerFault.exe" || ImageFileName == "dumprep.exe"
            || ImageFileName == "DW20.EXE" || ImageFileName == "DWWIN.EXE") {
        DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);
        ++plgState->m_werFaultCount;
    }
}

void SimpleCFIChecker::onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid)
{
    DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);

    getDebugStream(pid) << "Unloading process\n";

    std::vector<std::pair<uint64_t,uint64_t> > toDelete;

    foreach2 (it, plgState->m_returnStacks.begin(), plgState->m_returnStacks.end()) {
        std::pair<uint64_t,uint64_t> p = (*it).first;
        if (p.first == pid) {
            toDelete.push_back(p);
        }
    }

    foreach2(it, toDelete.begin(), toDelete.end()) {
        getDebugStream(pid, (*it).second) << "Erasing stack\n";
        plgState->m_returnStacks.erase(*it);
    }

    if (plgState->m_trackedPids.find(pid) != plgState->m_trackedPids.end()) {
        ExecutionTracer *tracer = s2e()->getPlugin<ExecutionTracer>();
        if (tracer) {
            tracer->flushCircularBufferToFile();
        }
    }

    /**********************/
    toDelete.clear();
    foreach2(it, plgState->m_ignoreNextReturns.begin(), plgState->m_ignoreNextReturns.end()) {
        std::pair<uint64_t,uint64_t> p = (*it).first;
        if (p.first == pid) {
            toDelete.push_back(p);
        }
    }
    foreach2(it, toDelete.begin(), toDelete.end()) {
        plgState->m_ignoreNextReturns.erase(*it);
    }

    /**********************/
    toDelete.clear();
    foreach2(it, plgState->m_perThreadCfiState.begin(), plgState->m_perThreadCfiState.end()) {
        std::pair<uint64_t,uint64_t> p = (*it).first;
        if (p.first == pid) {
            toDelete.push_back(p);
        }
    }
    foreach2(it, toDelete.begin(), toDelete.end()) {
        plgState->m_perThreadCfiState.erase(*it);
    }



    unsigned hadTrackedPids = plgState->m_trackedPids.size();
    plgState->m_trackedPids.erase(pid);
    m_memory->trackPid(state, pid, false);

    /**
     * Notify plugins when there is nothing left to track.
     * This may happen if all the processes close unexpectedly
     * without crashing or if the crash wasn't caught properly.
     */
    if ((hadTrackedPids > 0) && (plgState->m_trackedPids.size() == 0)) {
        onAllProcessesTerminated.emit(state);
    }

    getDebugStream() << "Was tracking " << hadTrackedPids << " now tracking "
                             << plgState->m_trackedPids.size() << "\n";
}

void SimpleCFIChecker::onThreadExit(S2EExecutionState *state, const ThreadDescriptor &desc)
{
    DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);
    std::pair<uint64_t, uint64_t> p = std::make_pair(desc.Pid, desc.Tid);
    plgState->m_ignoreNextReturns.erase(p);
    plgState->m_perThreadCfiState.erase(p);
    plgState->m_returnStacks.erase(p);
}

void SimpleCFIChecker::readModInfo(const ModuleDescriptor &mod, S2EExecutionState *state,
                                   vmi::PEFile *pefile, uint64_t diff, uint64_t exportsDiff,
                                   FunctionsSet &functions) {
    getDebugStream() << "reading PE file, diff = " << hexval(diff) << "\n";
    DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);

    functions.insert(pefile->getEntryPoint() + diff);
#ifdef SCFI_DUMP_TABLES
    getDebugStream() << "EntryPoint: "
                            << hexval((pefile->getEntryPoint() + diff)) << "\n";
#endif

    const vmi::ExceptionHandlers &exceptions = pefile->getExceptions();
    if (exceptions.empty()) {
        getWarningsStream() << "exceptions table is empty!\n";
    }

    foreach2 (it, exceptions.begin(), exceptions.end()) {
        functions.insert(*it + diff);
    }

    const vmi::Sections &sections = pefile->getSections();

    const vmi::Relocations &relocations = pefile->getRelocations();
    if (relocations.empty()) {
        getWarningsStream() << "relocation table is empty!\n";
        plgState->m_ignoredModules.insert(mod);
    }
    foreach2 (it, relocations.begin(), relocations.end()) {
        uint64_t dst = it->second;

        bool isInTextSection = false;
        foreach2 (it2, sections.begin(), sections.end()) {
            const vmi::SectionDescriptor &s = *it2;
            if (dst >= s.start && dst < s.start + s.size) {
                isInTextSection = s.isExecutable();
                break;
            }
        }

        if (isInTextSection) {
#ifdef SCFI_DUMP_TABLES
            getDebugStream() << "reloc: " << hexval(it->first + diff)
                             << " dst: " << hexval(dst + diff) << "\n";
#endif
            functions.insert(dst + diff);
        }
#ifdef SCFI_DUMP_TABLES
        else {
            getDebugStream() << "SKIPPING reloc: " << hexval(it->first) << " dst: " << hexval(dst) << "\n";
        }
#endif
    }


    const vmi::Exports &exports = pefile->getExports();
    if (exports.empty()) {
        getWarningsStream() << "exports table is empty!\n";
    }

    foreach2 (it, exports.begin(), exports.end()) {
#ifdef SCFI_DUMP_TABLES
        getDebugStream() << mod.Name << " export: '" << (*it).first << "' " << hexval(it->second + exportsDiff) << "\n";
#endif
        functions.insert(it->second + exportsDiff);
    }

    const vmi::FunctionAddresses &addresses = pefile->getAdditionalFunctionAddresses();
    for (auto it : addresses) {
        functions.insert(it + diff);
    }

    const S2E_WINMON2_KERNEL_STRUCTS &ks = m_monitor->getKernelStruct();
    if (ks.KernelMajorVersion > 5) {
        if (mod.Name == "kernel32.dll") {
            vmi::Exports::const_iterator it = exports.find("SwitchToFiber");
            if (it != exports.end()) {
                getDebugStream() << "Hooking export " << (*it).first << "\n";
                uint64_t address = it->second + exportsDiff;
                plgState->m_functionsWithIgnoredReturn.insert(address);
            }
        }
    }

    /* Case insentive for Windows */
    std::string lowerp = mod.Path;
    boost::to_lower(lowerp);
    if (m_whiteListedModulePaths.count(lowerp)) {
        Plugin::getDebugStream(state) << "Whitelisting " << mod << "\n";
        plgState->m_ignoredModules.insert(mod);
    }
}



void SimpleCFIChecker::scanModule(S2EExecutionState *state, const ModuleDescriptor &module)
{
    DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);
    uint64_t pid = module.Pid;
    getDebugStream() << "scanning new module: " << module.Name
                            << " as: " << hexval(module.AddressSpace) << " pid: " << hexval(pid)
                            << " native base:" << hexval(module.NativeBase)
                            << " path:" << module.Path << "\n";

    /* TODO: read from memory too if fails ? */
    Vmi::PeData pd = m_vmi->getPeFromDisk(module, true);
    if (!pd.pe) {
        getWarningsStream(pid) << "cannot get PE file for " << module.Name << "\n";
        return;
    }

    unsigned pointerSize = pd.pe->getPointerSize();
    getDebugStream(pid) << "ptrsize: " << hexval(pointerSize)
                            << " checksum: " << hexval(pd.pe->getCheckSum())
                            << " NativeBase: " << hexval(pd.pe->getImageBase())
                            << " LoadBase: " << hexval(module.LoadBase)
                            << " EntryPoint: " << hexval(module.EntryPoint) << "\n";

    plgState->m_functions.insert(std::make_pair(pid, FunctionsSet()));
    getDebugStream(pid) << "Number of PIDs: " << plgState->m_trackedPids.size() << "\n";
    getDebugStream(pid) << "Current pid has " << plgState->m_functions[pid].size() << " functions\n";

    FunctionsSet &functions = plgState->m_functions[pid];

    uint64_t diff = module.LoadBase - pd.pe->getImageBase();

    readModInfo(module, state, pd.pe, diff, module.LoadBase, functions);

    //Get all the extra addresses, which may not be found in reloc/export tables.
    const Vmi::Modules &vmod = m_vmi->getModules();
    Vmi::Modules::const_iterator mit = vmod.find(pd.pe->getCheckSum());
    if (mit != vmod.end()) {
        const Vmi::Module &mod = (*mit).second;
        if (mod.Checksum == pd.pe->getCheckSum()) {
            //XXX: for now, symbols assume functions.
            foreach2(sit, mod.Symbols.begin(), mod.Symbols.end()) {
                //XXX: we can't use module.NativeBase because it may be incorrect.
                //Rely instead on the info in the lua file.
                uint64_t address = (*sit).second - mod.NativeBase;
                functions.insert(module.LoadBase + address);
            }

            pd.pe->parseExceptionStructures(mod.CHandler, mod.CXXHandlers);
            const vmi::ExceptionHandlers &exceptions = pd.pe->getExceptionFilters();
            if (exceptions.empty()) {
                getWarningsStream() << "no exception filters!\n";
            }

            foreach2 (it, exceptions.begin(), exceptions.end()) {
                functions.insert(*it + diff);
            }

            if (mod.IgnoredAddressRanges.size() > 0) {
                AddressRange range = mod.IgnoredAddressRanges[0];
                plgState->m_addressRanges.insert(std::make_pair(
                                                     range.first - mod.NativeBase + module.LoadBase,
                                                     range.second - mod.NativeBase + module.LoadBase));
                getDebugStream(pid) << "Added whitelist address range: "
                                    << hexval(range.first) << ","
                                    << hexval(range.second) << "\n";
            }
        }
    }

    /**
     * Add any additional information about addresses that we might have
     * collected during execution. E.g., a module might be used by two processes,
     * the first process initializes some callbacks in an OS API that will then
     * invoke functions in the second process. Without this collection, process B
     * might cause FPs, because the callbacks might not be in the reloc info of
     * the module.AddressSpace and process B does not go through init code that
     * could have allowed us to discover these functions.
     */
    const Vmi::ModuleAddresses &ma = m_vmi->getModuleAddresses();
    auto mait = ma.find(pd.pe->getCheckSum());
    if (mait != ma.end()) {
        foreach2(sit, mait->second.begin(), mait->second.end()) {
            uint64_t address = (*sit) - pd.pe->getImageBase();
            functions.insert(module.LoadBase + address);
        }
        getDebugStream(pid) << "added " << mait->second.size() << " dynamically inferred functions\n";
    }


    //Few hard-coded addresses for some versions of Acrobat without reloc info
    //TODO: use IDA to get the list of functions
    if (pd.pe->getCheckSum() == 0x55392) { //AcroRd32.exe 8.1
        functions.insert(0x403320 - pd.pe->getImageBase() + module.LoadBase);
        functions.insert(0x4030f6 - pd.pe->getImageBase() + module.LoadBase);
    }


    delete pd.pe;
    delete pd.fp;
}

void SimpleCFIChecker::onMonitorLoad(S2EExecutionState *state)
{
    //uint64_t major = m_monitor->getKernelStruct().KernelMajorVersion;
    //uint64_t minor = m_monitor->getKernelStruct().KernelMinorVersion;

    /**
     * Looks like segfault detection does not really work (especially on MsOffice).
     * It has too many FPs.
     * It's not a problem because we also track calls to wer and dw.
     * In the worst case, the app will just close and we'll get
     * "app terminated unexpectedly" warning and the analysis will
     * be quarantined.
     */
    bool supported = false;

    //bool supported = major == 5 || (major == 6 && minor == 1);
    if (supported) {
        if (m_reportAccessFaults) {
            getDebugStream() << "Tracking access faults\n";
            /* Fatal page fault tracking is defective on Windows 10 */
            /* TODO: should probably track when the process unexpectedly terminates instead */
            m_monitor->onAccessFault.connect(
                    sigc::mem_fun(*this,
                            &SimpleCFIChecker::onAccessFault)
                    );
        }
    } else {
        if (m_reportAccessFaults) {
            getDebugStream() << "Unsupported OS detected, won't track access faults\n";
        }
    }
}

void SimpleCFIChecker::onModuleLoad(
        S2EExecutionState* state,
        const ModuleDescriptor &module
        )
{
    DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);

    uint64_t pid = module.Pid;

    getDebugStream(pid) << "onModuleLoad: "
                     << module.Name << " (pid: " << hexval(pid)
                     << " as: " << hexval(module.AddressSpace) << ")\n";

    if (plgState->m_trackedPids.find(pid) == plgState->m_trackedPids.end()) {
        getDebugStream(pid) << "Pid not tracked, ignoring module load\n";
        /* Ignore modules from untracked pids */
        return;
    }


    scanModule(state, module);

    if (m_tracer) {
        m_tracer->startTracing(state);
    }

    se_tb_safe_flush();
}

void SimpleCFIChecker::onModuleUnload(
        S2EExecutionState* state,
        const ModuleDescriptor &module
        )
{
    getDebugStream() << "onModuleUnload: "
                     << module.Name << " pid: " << hexval(module.Pid)
                     << " as: " << hexval(module.AddressSpace) << ")\n";
    return;
}

void SimpleCFIChecker::addFunctionFromInstruction(S2EExecutionState *state,
                                                  uint64_t pc,
                                                  uint64_t addr, bool checkRange)
{
    DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);

    foreach2 (it, plgState->m_trackedPids.begin(),
                  plgState->m_trackedPids.end()) {
        uint64_t pid = *it;
        const ModuleDescriptor *mod = m_map->getModule(state, pid, pc);
        if (!mod) {
            continue;
        }

        if (checkRange && !mod->Contains(addr)) {
            continue;
        }

        m_vmi->addFuctionAddress(mod->Checksum, mod->ToNativeBase(addr));

        FunctionsSet &functions = plgState->m_functions[pid];
        functions.insert(addr);
    }
}

void SimpleCFIChecker::onTranslateSpecialInstructionEnd(ExecutionSignal *signal,
                                                       S2EExecutionState *state,
                                                       TranslationBlock *tb,
                                                       uint64_t pc,
                                                       enum special_instruction_t  type)
{
    if (type != PUSHIM) {
        return;
    }

    if (m_monitor->isKernelAddress(pc)) { // XXX make it configurable
        return;
    }

    // Ignore 16-bit mode
    if ((tb->flags >> VM_SHIFT) & 1) {
        return;
    }

    /* Get the push opcode: 0x68 + imm32 */
#ifdef CONFIG_LIBS2E
    // XXX: Fix this hack!
    #define ldub_code(x) g_sqi.libcpu.ldub_code(x)
    #define ldl_code(x) g_sqi.libcpu.ldl_code(x)
#endif

    uint8_t op = ldub_code(pc);
    if (op != 0x68) {
        return;
    }

    uint32_t addr = ldl_code(pc + 1);

    addFunctionFromInstruction(state, addr, addr, true);
}

void SimpleCFIChecker::onTranslateLeaRipRelative(ExecutionSignal *signal,
                                                 S2EExecutionState *state,
                                                 TranslationBlock* tb,
                                                 uint64_t pc, uint64_t addr)
{
    if (m_monitor->isKernelAddress(pc)) { // XXX make it configurable
        return;
    }

    // Ignore 16-bit mode
    if ((tb->flags >> VM_SHIFT) & 1) {
        return;
    }

    addFunctionFromInstruction(state, pc, addr, false);
}

void SimpleCFIChecker::onTranslateBlockStart(ExecutionSignal *signal,
                                      S2EExecutionState *state,
                                      TranslationBlock *tb,
                                      uint64_t pc)
{
    if ((tb->flags >> VM_SHIFT) & 1) {
        return;
    }

    if (m_monitor->isKernelAddress(pc)) { // XXX make it configurable
        return;
    }

    DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);

    if (plgState->m_trackedPids.empty()) {
        return;
    }

    if (plgState->m_functionsWithIgnoredReturn.find(pc) != plgState->m_functionsWithIgnoredReturn.end()) {
        getDebugStream() << "Found SwitchToFiber TB\n";
        signal->connect(sigc::mem_fun(*this, &SimpleCFIChecker::onFunctionExec));
    }
}

void SimpleCFIChecker::onCfiCallReturnTranslate(S2EExecutionState *state,
                                                uint64_t pc, bool isCall, bool *instrument)
{
    if (m_monitor->isKernelAddress(pc)) { // XXX make it configurable
        return;
    }

    *instrument = true;
}

/**
 * Wait for the last instruction of the target TB to be executed before
 * confirming a CFI violation. This filters out cases where buggy code
 * crashes immediately upon call or return. The call and return might also
 * succeed, but the first instruction would crash immediately.
 *
 * There might be some FNs, but it's unlikely that an exploit would crash that soon.
 */
void SimpleCFIChecker::onTranslateBlockEnd(ExecutionSignal *signal,
                                      S2EExecutionState *state,
                                      TranslationBlock *tb,
                                      uint64_t pc, bool isStatic, uint64_t staticTarget)
{
    DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);

    /* Check if need to confirm the first CFI violation */
    uint64_t pid = m_monitor->getCurrentProcessId(state);
    uint64_t tid = m_monitor->getCurrentThreadId(state);

    bool useTbComplete = false;

    foreach2(it, plgState->m_perThreadCfiState.begin(), plgState->m_perThreadCfiState.end()) {
        const ThreadCfiState &cfi = (*it).second;

        /* The same code can be executed in parallel in the original buggy
         * and non-buggy threads, so just filter by process and pc (not by thread) */
        if (pid != cfi.pid) {
            continue;
        }

        if (cfi.stage == 0) {
            if (tb->pc == cfi.pc) {
                getDebugStream(pid, tid) << " attaching signals to confirm violation"
                                          << " tb_pc=" << hexval(tb->pc)
                                          << " instr_pc=" << hexval(pc)
                                          << "\n";
                useTbComplete = true;
                signal->connect(sigc::mem_fun(*this, &SimpleCFIChecker::onCFIViolationConfirm));
            }
        } else {
            /* second stage is used if the first stage was a bb with only one instruction */
            if (tb->pc == cfi.second_stage_pc) {
                getDebugStream(pid, tid) << " attaching signals to confirm 2nd stage violation"
                                          << " tb_pc=" << hexval(tb->pc)
                                          << " instr_pc=" << hexval(pc)
                                          << " is_static=" << hexval(isStatic)
                                          << " static_target=" << hexval(staticTarget)
                                          << "\n";
                useTbComplete = true;
                enum ETranslationBlockType tb_type = tb->se_tb_type;
                if (tb_type == TB_CALL || tb_type == TB_CALL_IND || tb_type == TB_RET) {
                    getDebugStream(pid, tid) << " don't instrument because it's a call/ret\n";
                    continue;
                }

                signal->connect(sigc::mem_fun(*this, &SimpleCFIChecker::onCFIViolationConfirm));
            }
        }
    }

    /**
     * Disassembly works only after the entire block is translated.
     */
    if (useTbComplete && !m_onTbComplete.connected()) {
        m_onTbComplete = s2e()->getCorePlugin()->onTranslateBlockComplete.connect(
                    sigc::mem_fun(*this, &SimpleCFIChecker::onTbComplete));
    }
}

void SimpleCFIChecker::onTbComplete(S2EExecutionState *state, TranslationBlock *tb, uint64_t endpc)
{
    uint64_t pid = m_monitor->getCurrentProcessId(state);
    uint64_t tid = m_monitor->getCurrentThreadId(state);

    llvm::raw_ostream &os = getDebugStream(pid, tid);
    os << "Disassembly at " << hexval(tb->pc) << "\n";
    state->disassemble(os, tb->pc, tb->size);
    os << "\n";
    m_onTbComplete.disconnect();
}


void SimpleCFIChecker::onCFIViolationConfirm(S2EExecutionState *state, uint64_t pc)
{
    /* We got executed, confirm CFI violation */
    DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);

    uint64_t pid = m_monitor->getCurrentProcessId(state);
    uint64_t tid = m_monitor->getCurrentThreadId(state);

    getDebugStream(pid, tid) << "onCFIViolationConfirm called pc=" << hexval(pc) << "\n";

    SimpleCFICheckerState::PidTidPair p(pid, tid);
    SimpleCFICheckerState::PerThreadCfiState::iterator it = plgState->m_perThreadCfiState.find(p);
    if (it == plgState->m_perThreadCfiState.end()) {
        /* Same code can be executed by buggy and non-buggy threads */
        return;
    }

    ThreadCfiState &cfi = (*it).second;

    /**
     * If we have only one instruction in this TB, check for crash in the next TB.
     */
    bool oneMoreTime = false;
    TranslationBlock *tb = state->getTb();
    if (tb->icount == 1 && cfi.stage == 0) {
        oneMoreTime = true;
    }

    llvm::raw_ostream &os = getDebugStream(pid, tid);
    os << "Disassembly at " << hexval(tb->pc) << "\n";
    state->disassemble(os, tb->pc, tb->size);
    os << "\n";

    if (oneMoreTime) {
        getDebugStream(pid, tid) << "Only one instruction in this TB, will try to confirm at end of next tb.\n";

        cfi.second_stage_pc = state->getPc();
        cfi.stage = 1;

        /* Ensure next stage gets instrumented */
        se_tb_safe_flush();
    } else {
        getDebugStream(pid, tid) << "Confirmed CFI violation at pc " << hexval(pc) << "\n";

        onCFIViolationDetected.emit(state, !cfi.isCall);

        /**
         * Disconnect only after the violation has been confirmed, because we
         * might have tb flushes before, threads that execute the same code, etc.
         */
        cfi.confirmViolation = false;
        cfi.pid = 0;
        cfi.tid = 0;
        cfi.pc = 0;
        m_onTbEnd.disconnect();

        if (cfi.isCall) {
            ++plgState->m_callViolationCount;
        } else {
            ++plgState->m_retViolationCount;
        }

        /* Remove this instrumentation */
        se_tb_safe_flush();
    }
}

bool SimpleCFIChecker::setupViolationConfirmation(S2EExecutionState *state, uint64_t monitorPc, bool isCall)
{
    DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);

    if (!m_ignoreViolationOnCrash) {
        return false;
    }

    /**
     * We need to setup a confirmation for every thread, because multiple threads
     * can end up executing the same buggy code. It's not enough to rely on the
     * global violation count.
     */

    uint64_t pid = m_monitor->getCurrentProcessId(state);
    uint64_t tid = m_monitor->getCurrentThreadId(state);

    SimpleCFICheckerState::PidTidPair p = std::make_pair(pid, tid);
    SimpleCFICheckerState::PerThreadCfiState::iterator it = plgState->m_perThreadCfiState.find(p);

    if (it != plgState->m_perThreadCfiState.end()) {
        if ((*it).second.confirmViolation == false) {
            getDebugStream(pid, tid) << "Already have a confirmed violation in this thread\n";
            /* We had a violation once already, return */
            return false;
        }
    } else {
        plgState->m_perThreadCfiState[p].confirmViolation = true;
    }

    ThreadCfiState &cfi = plgState->m_perThreadCfiState[p];

    if (cfi.stage > 0) {
        getDebugStream(pid, tid) << "A previous violation has not been confirmed yet.\n";
        cfi.confirmViolation = false;
        m_onTbEnd.disconnect();
        return false;
    }

    cfi.isCall = isCall;
    cfi.pc = monitorPc;
    cfi.pid = pid;
    cfi.tid = tid;
    cfi.stage = 0;
    cfi.second_stage_pc = 0;

    /* Make sure the target tb gets re-instrumented */
    se_tb_safe_flush();

    if (!m_onTbEnd.connected()) {
        /* Might have multiple threads trying to violate at the same time */
        m_onTbEnd = s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
                sigc::mem_fun(*this, &SimpleCFIChecker::onTranslateBlockEnd));
    }

    return true;
}

/**
 * Tracks functions that needs their ret intruction to be ignored.
 */
void SimpleCFIChecker::onFunctionExec(S2EExecutionState* state, uint64_t pc)
{
    DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);
    if (plgState->m_trackedPids.empty()) {
        return;
    }

    uint64_t pid = m_monitor->getCurrentProcessId(state);

    TrackedPids::iterator pIt = plgState->m_trackedPids.find(pid);
    if (pIt == plgState->m_trackedPids.end()) {
        return;
    }

    uint64_t tid = m_monitor->getCurrentThreadId(state);

    getDebugStream(pid, tid) << "Detected call to SwitchToFiber\n";

    plgState->m_ignoreNextReturns[std::make_pair(pid, tid)] = true;
}

void SimpleCFIChecker::onTbEndInstrument(ExecutionSignal *signal,
                                      S2EExecutionState *state,
                                      TranslationBlock *tb,
                                      uint64_t pc, bool isStatic, uint64_t staticTarget)
{
    DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);
    if (plgState->m_trackedPids.empty()) {
        return;
    }
    if (isGeneratedTrampoline(state, pc)) {
        getDebugStream() << "Instrumenting call to FlushInstructionCache at " << hexval(pc) << "\n";
        signal->connect(sigc::mem_fun(*this, &SimpleCFIChecker::onGenerateTrampoline));
    }
}

// Instrument calls to FlushInstructionCache, extract address and whitelist it
void SimpleCFIChecker::onGenerateTrampoline(S2EExecutionState *state, uint64_t pc)
{
    DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);
    if (plgState->m_trackedPids.empty()) {
        return;
    }

    uint64_t pid = m_monitor->getCurrentProcessId(state);
    TrackedPids::iterator pIt = plgState->m_trackedPids.find(pid);
    if (pIt == plgState->m_trackedPids.end()) {
        return;
    }
    const ModuleDescriptor *modCaller = m_map->getModule(state, pc);
    uint64_t param = 0;

    if (state->getPointerSize() == 4) {
        uint64_t esp = s2e_read_register_concrete_fast<target_ulong>(CPU_OFFSET(regs[R_ESP]));
        state->readMemoryConcrete(esp + 8, &param, state->getPointerSize());
    } else {
        param = s2e_read_register_concrete_fast<target_ulong>(CPU_OFFSET(regs[R_EDX]));
    }

    plgState->m_functions[pid].insert(param);
    getInfoStream() << "FlushInstructionCache(" << hexval(param) << ") at "
                    << hexval(modCaller ? modCaller->ToNativeBase(pc) : pc) << "\n";
}

extern "C" {
void helper_se_call(target_ulong pc)
{
    s_checker->onCall(g_s2e_state, pc);
}

void helper_se_ret(target_ulong pc)
{
    s_checker->onRet(g_s2e_state, pc);
}
}

bool SimpleCFIChecker::isJitTarget(S2EExecutionState *state, uint64_t pid, uint64_t callee)
{
    MemoryMapRegionType type = m_memory->getType(state, pid, callee);
    if (type & MM_EXEC) {
        return true;
    } else {
        m_monitor->initCurrentProcessThreadId(state);
        if (m_monitor->getCurrentProcessId(state) != pid) {
            getWarningsStream() << "DETECTED PID INCONSISTENCY\n";
            return false;
        }

        /* Last resort check (very slow): parse the VAD tree */
        uint64_t start, end, protection;
        if (m_monitor->getVirtualMemoryInfo(state, m_monitor->getCurrentProcess(state), callee, &start, &end, &protection)) {
            if (protection & 1) {
                return true;
            }
        }
    }

    return false;
}

/**
 * Check if the target is within an executable portion
 * of the data section. The process usually enables execute
 * flag with NtProtectVirtualMemory. This can e.g, happen
 * in wmvdecod.dll.
 */
bool SimpleCFIChecker::isDataSectionJit(S2EExecutionState *state, uint64_t pid,
                                        const ModuleDescriptor *mod,
                                        uint64_t pc)
{
    if (!mod) {
        return false;
    }

    const SectionDescriptor *sec = mod->getSection(pc);
    if (!sec) {
        return false;
    }

    getDebugStream(pid, 0) << hexval(pc)
                             << " is inside binary section "
                             << sec->name << "\n";
    if (!sec->isExecutable()) {
        if (isJitTarget(state, pid, pc)) {
            return true;
        }
    }

    return false;
}

void SimpleCFIChecker::onCall(S2EExecutionState* state, uint64_t pc)
{
    DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);
    /**
     * Count how many calls and returns we instrument.
     * We only want those that are in the processes of interest.
     */
    ++plgState->m_callCount;

    // Get and save return address
    uint64_t addr = env->return_address;


    {
#ifdef USE_SHADOW_STACK
        plgState->m_shadowStack[std::make_pair(pid, sp)] = addr;
#else
        unsigned &cnt = (*plgState->m_currentReturnStack)[addr];
        cnt++;
#endif
    }

    enum ETranslationBlockType se_tb_type = state->getTb()->se_tb_type;
    assert(se_tb_type == TB_CALL || se_tb_type == TB_CALL_IND);

    // Check the destination if the call is indirect
    if (se_tb_type != TB_CALL_IND) {
        return;
    }


    uint64_t pid = m_monitor->getCurrentProcessId(state);
    assert(pid && "This must never be null");

    uint64_t tid = m_monitor->getCurrentThreadId(state);
    assert(tid && "This must never be null");

    uint64_t caller = state->getTb()->pcOfLastInstr;
    uint64_t callee = s2e_read_register_concrete_fast<target_ulong>(CPU_OFFSET(eip));


    if (plgState->m_functions[pid].count(callee) == 0) {
        const ModuleDescriptor *modCallee = m_map->getModule(state, callee);

        if (modCallee) {
            if (plgState->m_ignoredModules.count(*modCallee)) {
                return;
            }

            // Check for whitelisted address range
            if (plgState->inAnyAddressRange(callee)) {
                return;
            }

            if (isDataSectionJit(state, pid, modCallee, callee)) {
                getDebugStream(pid, tid) << hexval(callee)
                                         << " is in executable region of data section\n";

                plgState->m_ignoredModules.insert(*modCallee);
                return;
            }
        } else {
            bool r = isJitTarget(state, pid, callee);
            if (r) {
                ++plgState->m_JITCallCount;
                return;
            }

            getDebugStream(pid, tid) << hexval(callee) << " --- jit region, on call, failed lookup\n";
        }

        const ModuleDescriptor *modCaller = m_map->getModule(state, caller);

        getWarningsStream(pid, tid) << "CFI violation detected: call from "
            << (modCaller ? modCaller->Name : "") << "(" << hexval(modCaller ? modCaller->ToNativeBase(caller) : caller) << ") to "
            << (modCallee ? modCallee->Name : "") << "(" << hexval(modCallee ? modCallee->ToNativeBase(callee) : callee) << ")\n";


        if (m_verbose && m_dumpRegions) {
            m_memory->dump(state);
            m_map->dump(state);
            m_dumpRegions = false;
            m_monitor->dumpVad(state);
            cpu_dump_state(env, stderr, fprintf, 0);
        }


        if (!setupViolationConfirmation(state, callee, true)) {
            ++plgState->m_callViolationCount;
            onCFIViolationDetected.emit(state, false);
        }
    }
}

void SimpleCFIChecker::onRet(S2EExecutionState *state, uint64_t pc)
{
    DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);
    ++plgState->m_retCount;


#ifdef USE_SHADOW_STACK
    llvm::DenseMap<uint64_t, uint64_t>::iterator it =
            plgState->m_shadowStack.find(std::make_pair(pid, sp));
    if (it == plgState->m_shadowStack.end() ||
            it->second != addr) {
        const ModuleDescriptor *modCallee = m_map->getModule(state, pc);
        if (modCallee == 0) { // && plgState->m_jitRegions.lookup(pc, false)) {
            return;
        }

        const ModuleDescriptor *modCallerReal = m_map->getModule(state, addr);

        getWarningsStream(pid) << "CFI violation detected: return from "
            << (modCallee ? modCallee->Name : "") << "(" << hexval(pc) << ") to "
            << (modCallerReal ? modCallerReal->Name : "") << "(" << hexval(addr) << ")\n";

    }

#else


    AddressMap &returnStack = *plgState->m_currentReturnStack;

    /* We instrument ret when it is done executing, so current pc is the return address */
    uint64_t addr = s2e_read_register_concrete_fast<target_ulong>(CPU_OFFSET(eip));

    AddressMap::iterator amit = returnStack.find(addr);

    if (likely(amit != returnStack.end())) {
        /**
         * Can't just resize the stack.
         * We can have a mix of different stacks in this structure (APC and normal stack),
         * things like longjumps, etc. Resizing the stack may have random effects.
         * So just erase the current return address and hope we don't
         * get FNs.
         */

        assert((*amit).second > 0);
        if ((--(*amit).second) == 0) {
            returnStack.erase(amit);
        }
        return;
    }

    const ModuleDescriptor *modCallee = m_map->getModule(state, pc);

    uint64_t pid = m_monitor->getCurrentProcessId(state);
    uint64_t tid = m_monitor->getCurrentThreadId(state);
    assert(pid && tid && "This must never be null");

    if (modCallee) {
        if (plgState->m_ignoredModules.count(*modCallee)) {
            return;
        }
    } else {
        bool r = isJitTarget(state, pid, pc);
        if (r) {
            ++plgState->m_JITCallCount;
            return;
        }

        getDebugStream() << hexval(pc) << " --- jit region, on ret, failed lookup\n";
    }

    /* Check for ignored return instruction */
    SimpleCFICheckerState::IgnoreNextReturn::iterator rit =
            plgState->m_ignoreNextReturns.find(std::make_pair(pid, tid));
    if (rit != plgState->m_ignoreNextReturns.end()) {
        if ((*rit).second) {
            (*rit).second = false;
            getDebugStream(pid, tid) << "Ignored violating return\n";
            return;
        }
    }

    const ModuleDescriptor *modCallerReal = m_map->getModule(state, addr);

    if (isWhitelistedReturn(modCallee, pc, modCallerReal, addr)) {
        return;
    }

    if (isDataSectionJit(state, pid, modCallerReal, addr)) {
        getDebugStream(pid, tid) << hexval(pc)
                                 << " is in executable region of data section\n";
        plgState->m_ignoredModules.insert(*modCallerReal);
        return;
    }

    getWarningsStream(pid, tid) << "CFI violation detected: return from "
        << (modCallee ? modCallee->Name : "") << "(" << hexval(modCallee ? modCallee->ToNativeBase(pc) : pc) << ") to "
        << (modCallerReal ? modCallerReal->Name : "") << "(" << hexval(modCallerReal ? modCallerReal->ToNativeBase(addr) : addr) << ")\n";

    if (m_verbose) {
        foreach2 (it, plgState->m_returnStacks.begin(), plgState->m_returnStacks.end()) {
            getWarningsStream() << "\nThread " << hexval(it->first.first) << ":" << hexval(it->first.second) << "\n";
            foreach2 (it2, it->second.begin(), it->second.end()) {
                std::string ModuleName = "<unknown>";
                uint64_t pc = (*it2).first;
                const ModuleDescriptor *module = m_map->getModule(state, it->first.first, pc);
                if (module) {
                    ModuleName = module->Name;
                    pc = module->ToNativeBase(pc);
                }
                getWarningsStream(it->first.first, it->first.second) //<< "    "
                                    //<< "sp:" << hexval((*it2).first) << " "
                                    << hexval(pc) << ": " << ModuleName << "\n";
            }
        }

        if (m_dumpRegions) {
            m_memory->dump(state);
            m_map->dump(state);
            m_dumpRegions = false;
            m_monitor->dumpVad(state);
            cpu_dump_state(env, stderr, fprintf, 0);
        }
    }

    if (!setupViolationConfirmation(state, addr, false)) {
        ++plgState->m_retViolationCount;
        onCFIViolationDetected.emit(state, true);
    }



#endif
}


void SimpleCFIChecker::stopAnalysis(S2EExecutionState *state) {
    Screenshot* ss = dynamic_cast<Screenshot*>(s2e()->getPlugin("Screenshot"));
    if (ss) {
        Plugin::getWarningsStream(state) << "SimpleCFI: taking screenshot before killing state\n";
        ss->takeScreenShot(state);
    }

    Plugin::getWarningsStream(state) << "SimpleCFI: finishing analysis\n";
    //XXX: fix this, cannot kill states if called from onTimer()
    exit(0);
    //s2e_kill_state("killed by tickler invokation");
}


void SimpleCFIChecker::stopIfJITCodeNotRunning(S2EExecutionState *state) {

    DECLARE_PLUGINSTATE(SimpleCFICheckerState, state);

    uint64_t delta = plgState->m_JITCallCount - plgState->m_JITCallCountPrev;
    plgState->m_JITCallCountPrev = plgState->m_JITCallCount;

    plgState->m_JITCallCountAverage =
            (uint64_t)
            ((1 - MOVING_AVERAGE_ALPHA) * plgState->m_JITCallCountAverage +
             MOVING_AVERAGE_ALPHA * delta);


    if (!m_stopRequested) {
        return;
    }

    Plugin::getDebugStream(state) << "Evaluating JIT activity:"
                                 << " total #calls: " << plgState->m_callCount
                                 << " JIT #calls: " << plgState->m_JITCallCount
                                 << " JIT calls delta: " << delta
                                 << " JIT #calls average: " << plgState->m_JITCallCountAverage
                                 << "\n";

    if (!m_terminateOnJITIdle) {
        return;
    }

    //wait a few timer ticks before deciding wether to stop
    if ((m_timerTicks++) < MIN_TIMER_TICKS) {
        return;
    }

    if (plgState->m_JITCallCountAverage < IDLE_JIT_CODE_CALL_COUNT_AVERAGE) {

        if (delta > plgState->m_JITCallCountAverage || delta > IDLE_JIT_CODE_CALL_COUNT_AVERAGE) {
            //recent spike in JIT activity, backoff
            m_timerTicks = 0;
            return;
        }

        //almost no JIT-ed code is running, stop the analysis now
        stopAnalysis(state);
    }
}

void SimpleCFIChecker::onTimer(void)
{
    if (m_timerCount < TIMER_TICK_GRANULARITY) {
        ++m_timerCount;
        return;
    }

    m_timerCount = 0;

    if (!g_s2e_state) {
        return;
    }

    //stopIfJITCodeNotRunning(g_s2e_state);
    if (m_stopRequested) {
        stopAnalysis(g_s2e_state);
    }
}

/************************************************/
void SimpleCFIChecker::handleOpcodeInvocation(S2EExecutionState *state,
                                              uint64_t guestDataPtr,
                                              uint64_t guestDataSize) {
    S2E_CFI command;

    if (guestDataSize != sizeof(command)) {
        Plugin::getWarningsStream(state) <<
                "SimpleCFI: mismatched S2E_CFI size\n";
        exit(-1);
    }

    if (!state->mem()->readMemoryConcrete(guestDataPtr, &command, guestDataSize)) {
        Plugin::getWarningsStream(state) <<
                "SimpleCFI: could not read transmitted data\n";
        exit(-1);
    }

    if (command.command == DONE) {
        m_stopRequested = true;
        Plugin::getWarningsStream(state) << "SimpleCFI: received DONE command\n";
        return;
    } else if (command.command == FYI) {
        Plugin::getDebugStream(state) << "SimpleCFI: received FYI command\n";
        std::string info;
        if (state->mem()->readString(command.ptr_info, info, 2048)) {
            onFYINotification(state, info);
        } else {
            Plugin::getWarningsStream(state) << "SimpleCFI: could not read FYI info string\n";
        }
    } else if (command.command == WINDOW_TEXT) {
        Plugin::getDebugStream(state) << "SimpleCFI: received WINDOW_TEXT command\n";
        std::string info;
        if (state->mem()->readString(command.ptr_info, info, 4096)) {
            onWindowInfo(state, info);
        } else {
            Plugin::getWarningsStream(state) << "SimpleCFI: could not read window text string\n";
        }
    } else if (command.command == TAKE_SCREENSHOT) {
        Plugin::getDebugStream(state) << "SimpleCFI: received TAKE_SCREENSHOT command\n";
        takeScreenShot(state);
    } else {
        assert(false && "unexpected invokation command");
    }

}

QDict *SimpleCFIChecker::getStatistics(S2EExecutionState *state) const
{
    DECLARE_PLUGINSTATE_CONST(SimpleCFICheckerState, state);
    QDict *dict = plgState->getStatistics();
    qdict_put_obj(dict, "first_process_load_time", QOBJECT(qint_from_int(m_firstTrackedModuleTime)));
    qdict_put_obj(dict, "peak_commit_charge", QOBJECT(qint_from_int(m_memory->getPeakCommitCharge(state))));
    return dict;
}

uint64_t SimpleCFIChecker::getStatistic(S2EExecutionState *state, const std::string &name) const
{
    uint64_t ret = 0;
    QDict *stats = getStatistics(state);

    QObject *obj = qdict_get(stats, name.c_str());
    if (obj) {
        QInt *i = qobject_to_qint(obj);
        if (i) {
            ret = qint_get_int(i);
        }
    }

    QDECREF(stats);
    return ret;
}

TrackedPids SimpleCFIChecker::getTrackedPids(S2EExecutionState *state) const
{
    DECLARE_PLUGINSTATE_CONST(SimpleCFICheckerState, state);
    return plgState->m_trackedPids;
}

const AddressMap &SimpleCFIChecker::getAddressMap(S2EExecutionState *state) const
{
    DECLARE_PLUGINSTATE_CONST(SimpleCFICheckerState, state);
    return *plgState->m_currentReturnStack;
}

} // namespace plugins
} // namespace s2e

