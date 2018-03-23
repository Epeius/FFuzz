///
/// Copyright (C) 2015-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_POVGEN_H
#define S2E_PLUGINS_POVGEN_H

#include <s2e/Plugin.h>
#include <string>
#include <sstream>
#include <inttypes.h>
#include "CGCMonitor.h"
#include <s2e/Plugins/ProcessExecutionDetector.h>
#include <s2e/Plugins/ModuleExecutionDetector.h>
#include <s2e/Plugins/Searchers/SeedSearcher.h>

namespace s2e{
namespace plugins{

class POVGeneratorState;

/** Handler required for KLEE interpreter */
class POVGenerator : public Plugin
{
    S2E_PLUGIN

public:
    typedef std::vector<klee::ref<klee::Expr> > ExprList;
    typedef std::map<std::string /* from */, std::string /* to */> VariableRemapping;

    enum PovType {
        POV_GENERAL,
        POV_TYPE1,
        POV_TYPE2
    };

    struct PovOptions {
        PovType m_type;
        uint64_t m_faultAddress;
        uint64_t m_ipMask;
        uint64_t m_regMask;
        uint64_t m_regNum;
        size_t m_bytesBeforeSecret;
        ExprList m_extraConstraints;
        VariableRemapping m_remapping;
        PovOptions() {
            m_type = POV_GENERAL;
            m_faultAddress = 0;
            m_ipMask = 0;
            m_regMask = 0;
            m_regNum = 0;
            m_bytesBeforeSecret = 0;
        }
    };

private:
    typedef std::pair<std::string, std::vector<unsigned char> > VarValuePair;
    typedef std::vector<VarValuePair> ConcreteInputs;

    typedef std::set<u_int64_t> AddressSet;
    AddressSet m_povAddresses; // addresses at which POVs were generated
    unsigned m_numPOVs; // number of POVs generated so far
    bool m_compress;

    static const std::string XML_HEADER, XML_FOOTER;
    static const std::string C_HEADER, C_FOOTER;
    CGCMonitor *m_monitor;
    ProcessExecutionDetector *m_detector;
    ModuleExecutionDetector *m_modules;
    seeds::SeedSearcher *m_seedSearcher;

    std::string generatePoV(bool xmlFormat, uint64_t seedIndex, const POVGeneratorState *plgState,
                            const PovOptions &opt, const VariableRemapping &remapping,
                            const klee::Assignment &solution, const klee::ConstraintManager &constraints);

public:
    POVGenerator(S2E* s2e);

    void initialize();

    void generatePoV(S2EExecutionState *state, const PovOptions &opt, std::string &xmlPov, std::string &cPov);

    /** TODO: move this to some common plugin */
    static void compress(void *in_data, size_t in_data_size, std::vector<uint8_t> &out_data);
    static std::vector<uint8_t> compress(const std::string &s);

    static bool isReceive(const klee::Array *array);
    static bool isRandom(const klee::Array *array);
    static bool isRandomRead(const klee::ref<klee::Expr> &e);
    static bool isReceiveRead(const klee::ref<klee::Expr> &e);

    std::string writeToFile(S2EExecutionState *state, const PovOptions &opt,
                            const std::string &filePrefix, const std::string &fileExtWithoutDot,
                            const std::string &pov);

    sigc::signal<void,
                S2EExecutionState*,
                const ModuleDescriptor*>
            onRandomInputFork;

private:
    void unmergeSelects(klee::ConstraintManager &mgr, const klee::Assignment &assignment);

    void onStateFork(S2EExecutionState *state,
                     const std::vector<S2EExecutionState*> &newStates,
                     const std::vector<klee::ref<klee::Expr> > &newConditions);

    void onRandom(S2EExecutionState *state,
                  uint64_t pid, const std::vector<klee::ref<klee::Expr>> &data);

    void onWrite(S2EExecutionState *state,
                 uint64_t pid, uint64_t fd,
                 const std::vector<klee::ref<klee::Expr> > &data,
                 klee::ref<klee::Expr> sizeExpr);

    void onSymbolicRead(S2EExecutionState* state, uint64_t pid,  uint64_t fd, uint64_t size,
            const std::vector<std::pair<std::vector<klee::ref<klee::Expr> >, std::string> > &data,
            klee::ref<klee::Expr> sizeExpr);

    void onConcreteRead(S2EExecutionState *state, uint64_t pid, uint64_t fd, const std::vector<uint8_t> &data);

    void generateNegotiate(std::stringstream &ss, bool xmlFormat, const PovOptions &opt);
    void generateReadSecret(std::stringstream &ss, bool xmlFormat, const PovOptions &opt);

    bool solveConstraints(S2EExecutionState *state, const PovOptions &opt, klee::Assignment &assignment);
};

}
}

#endif
