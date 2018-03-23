///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_MEMORYCHECKER_H
#define S2E_PLUGINS_MEMORYCHECKER_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/ExecutionTracers/MemoryTracer.h>

#include <string>

namespace s2e {

struct ModuleDescriptor;

namespace plugins {

class OSMonitor;
class ModuleExecutionDetector;

// MemoryCheker tracks memory that the module is allowed to acces
// and checks each access for validiry
class MemoryChecker : public Plugin
{
    S2E_PLUGIN

    OSMonitor *m_osMonitor;
    ModuleExecutionDetector *m_moduleDetector;
    MemoryTracer *m_memoryTracer;
    ExecutionTracer *m_executionTracer;

    bool m_checkMemoryLeaks;
    bool m_checkMemoryErrors;
    bool m_checkResourceLeaks;

    bool m_terminateOnLeaks;
    bool m_terminateOnErrors;

    bool m_traceMemoryAccesses;

    sigc::connection m_dataMemoryAccessConnection;

    void onException(S2EExecutionState *state, unsigned intNb, uint64_t pc);

    void onModuleTransition(S2EExecutionState *state,
                            const ModuleDescriptor *prevModule,
                            const ModuleDescriptor *nextModule);

    void onAfterSymbolicDataMemoryAccess(S2EExecutionState *state,
                 klee::ref<klee::Expr> virtualAddress,
                 klee::ref<klee::Expr> hostAddress,
                 klee::ref<klee::Expr> value,
                 unsigned flags);

    void onStateSwitch(S2EExecutionState *currentState,
                                      S2EExecutionState *nextState);

    // Simple pattern matching for region types. Only one
    // operator is allowed: '*' at the end of pattern means any
    // number of any characters.
    bool matchRegionType(const std::string &pattern, const std::string &type);


public:
    bool terminateOnErrors() const {
        return m_terminateOnErrors;
    }

    std::string getPrettyCodeLocation(S2EExecutionState *state);

public:
    /**
     * Fired right before the actual checking.
     * This gives a chance for other plugins to perform
     * more fine-grained checks.
     * When all callbacks return, the memory checker proceeds normally.
     */
    sigc::signal<void,
            S2EExecutionState *,
            uint64_t /* virtual address */,
            unsigned /* size */,
            bool /* isWrite */>
            onPreCheck;

    /**
     * Fired if the actual checking failed.
     * This gives a chance for other plugins to perform
     * more fine-grained checks that were missed by MemoryChecker.
     */
    sigc::signal<void,
            S2EExecutionState *,
            uint64_t /* virtual address */,
            unsigned /* size */,
            bool /* isWrite */,
            bool * /* success */>
            onPostCheck;

public:
    enum Permissions {
        NONE=0, READ=1, WRITE=2, READWRITE=3, ANY=-1
    };

    MemoryChecker(S2E* s2e): Plugin(s2e) {}

    void initialize();

    void grantMemoryForModuleSections(
                S2EExecutionState *state,
                const ModuleDescriptor &desc
            );

    void revokeMemoryForModuleSections(
                S2EExecutionState *state,
                const ModuleDescriptor &desc
            );

    void revokeMemoryForModuleSection(
                S2EExecutionState *state,
                const ModuleDescriptor &module,
                const std::string &section);


    void revokeMemoryForModuleSections(
                S2EExecutionState *state
            );

    void grantMemoryForModule(S2EExecutionState *state,
                     uint64_t start, uint64_t size,
                     Permissions perms,
                     const std::string &regionType);

    void grantMemoryForModule(S2EExecutionState *state,
                     const ModuleDescriptor *module,
                     uint64_t start, uint64_t size,
                     Permissions perms,
                     const std::string &regionType,
                     bool permanent = false);

    bool revokeMemoryForModule(S2EExecutionState *state,
                     const std::string &regionTypePattern);


    void grantResourceForModule(S2EExecutionState *state,
                                uint64_t handle,
                                const std::string &resourceType);

    bool revokeMemoryForModule(
            S2EExecutionState *state,
            const ModuleDescriptor *module,
            const std::string &regionTypePattern);

    void grantResource(S2EExecutionState *state,
                       uint64_t handle, const std::string &resourceType);

    void revokeResource(S2EExecutionState *state,
                       uint64_t handle);

    void grantMemory(S2EExecutionState *state,
                     uint64_t start, uint64_t size, Permissions perms,
                     const std::string &regionType, uint64_t regionID = 0,
                     bool permanent = false);

    // Revoke memory by address
    // NOTE: end, perms and regionID can be -1, regionTypePattern can be NULL
    bool revokeMemory(S2EExecutionState *state,
                      uint64_t start, uint64_t size,
                      Permissions perms = ANY,
                      const std::string &regionTypePattern = "",
                      uint64_t regionID = uint64_t(-1));

    // Revoke memory by pattern
    // NOTE: regionID can be -1
    bool revokeMemory(S2EExecutionState *state,
                      const std::string &regionTypePattern,
                      uint64_t regionID = uint64_t(-1));

    bool revokeMemoryByPointer(S2EExecutionState *state, uint64_t pointer,
                               const std::string &regionTypePattern);

    bool revokeMemoryByPointerForModule(S2EExecutionState *state, uint64_t pointer,
                               const std::string &regionTypePattern);


    bool revokeMemoryByPointerForModule(
            S2EExecutionState *state,
            const ModuleDescriptor *module,
            uint64_t pointer,
            const std::string &regionTypePattern);


    // Check accessibility of memory region
    bool checkMemoryAccess(S2EExecutionState *state,
                           uint64_t start, uint64_t size, uint8_t perms,
                           llvm::raw_ostream &message);

    // Check that all resources were freed
    bool checkResourceLeaks(S2EExecutionState *state);

    // Check that all memory objects were freed
    bool checkMemoryLeaks(S2EExecutionState *state);

    bool findMemoryRegion(S2EExecutionState *state,
                          uint64_t address,
                          uint64_t *start, uint64_t *size) const;

    std::string getRegionTypePrefix(S2EExecutionState *state,
                                    const std::string &regionType);

};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
