///
/// Copyright (C) 2015-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///

#include "CGCInterface.h"

#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>

#include <s2e/Plugins/ModuleExecutionDetector.h>
#include <s2e/Plugins/CGC/CGCMonitor.h>
#include <s2e/Plugins/CGC/POVGenerator.h>

#include <s2e/Plugins/QEMUEvents.h>

#include <ctime>
#include <sstream>
#include <algorithm>

#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/FileSystem.h>

extern "C" {
#include <qdict.h>
#include <qbool.h>
}

// number of retries per normal / critical DB request
#define RETRY_NORMAL    15
#define RETRY_CRITICAL  15

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(CGCInterface, "CGC interface plugin", "",
                  "ModuleExecutionDetector", "CGCMonitor", "ProcessExecutionDetector",
                  "ExploitGenerator", "POVGenerator", "BasicBlockCoverage", "ControlFlowGraph",
                  "SeedSearcher", "CallSiteMonitor", "TranslationBlockCoverage");

void CGCInterface::initialize()
{
    m_monitor = s2e()->getPlugin<CGCMonitor>();
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();
    m_procDetector = s2e()->getPlugin<ProcessExecutionDetector>();
    m_povGenerator = s2e()->getPlugin<POVGenerator>();
    m_exploitGenerator = s2e()->getPlugin<ExploitGenerator>();
    m_coverage = s2e()->getPlugin<coverage::BasicBlockCoverage>();
    m_tbcoverage = s2e()->getPlugin<coverage::TranslationBlockCoverage>();
    m_cfg = s2e()->getPlugin<ControlFlowGraph>();
    m_csTracker = s2e()->getPlugin<CallSiteMonitor>();
    m_seedSearcher = s2e()->getPlugin<seeds::SeedSearcher>();
    m_recipe = s2e()->getPlugin<recipe::Recipe>();
    m_models = s2e()->getPlugin<StaticLibraryFunctionModels>();

    ConfigFile *cfg = s2e()->getConfig();

    m_maxPovCount = cfg->getInt(getConfigKey() + ".maxPovCount", 5);
    m_disableSendingExtraDataToDB = cfg->getBool(getConfigKey() + ".disableSendingExtraDataToDB", false);

    ///XXX: need to make all config params consistent (camelcase or underscore)
    m_recordConstraints = cfg->getBool(getConfigKey() + ".recordConstraints", false);
    m_recordAllPaths = cfg->getBool(getConfigKey() + ".record_all_paths", false);

    // Seeds with priority equal to or lower than the threshold are considered low priority
    // For CFE, high priorities range from 10 to 7 (various types of POVs and crashes),
    // while normal test cases are from 6 and below.
    bool ok = false;
    m_lowPrioritySeedThreshold = cfg->getInt(getConfigKey() + ".lowPrioritySeedThreshold", 6, &ok);
    if (!ok) {
        getWarningsStream() << "lowPrioritySeedThreshold must be set\n";
        exit(-1);
    }

    s2e()->getCorePlugin()->onStateKill.connect(sigc::mem_fun(*this, &CGCInterface::onStateKill));
    s2e()->getCorePlugin()->onTimer.connect_front(sigc::mem_fun(*this, &CGCInterface::onTimer));
    s2e()->getCorePlugin()->onProcessForkComplete.connect_front(sigc::mem_fun(*this, &CGCInterface::onProcessForkComplete));

    m_povGenerator->onRandomInputFork.connect_front(sigc::mem_fun(*this, &CGCInterface::onRandomInputFork));

    m_monitor->onRandom.connect(sigc::mem_fun(*this, &CGCInterface::onRandom));

    m_seedSearcher->onSeed.connect(sigc::mem_fun(*this, &CGCInterface::onSeed));
    m_exploitGenerator->onPovReady.connect(sigc::mem_fun(*this, &CGCInterface::onPovReady));

    // We must use translation block coverage, because BBs may not be available
    m_tbcoverage->onNewBlockCovered.connect(sigc::mem_fun(*this, &CGCInterface::onNewBlockCovered));

    m_monitor->onSegFault.connect(sigc::mem_fun(*this, &CGCInterface::onSegFault));


    m_cbStatsUpdateInterval = cfg->getInt(getConfigKey() + ".stats_update_interval", 10);
    m_cbStatsLastSent = 0;
    m_cbStatsChanged = false;
    m_completedPaths = 0;
    m_completedSeeds = 0;
    m_maxCompletedPathDepth = 0;
    m_maxPathDepth = 0;
    m_lastReportedStateCount = 0;

    uint64_t now = llvm::sys::TimeValue::now().seconds();
    m_timeOfLastCoveredBlock = now;
    m_timeOfLastCrash = now;
    m_timeOfLastHighPrioritySeed = now;
    m_timeOfLastFetchedSeed = now;
    m_explorationState = WARM_UP;

    /**
     * How long do we wait before using new seeds.
     *
     * Using seeds is currently expensive. For simple CBs, seeds
     * slow down vulnerability finding by a lot. Use them only when
     * S2E is stuck.
     */
    m_stateMachineTimeout = cfg->getInt(getConfigKey() + ".stateMachineTimeout", 60);

    // How often to go through all states to report those that
    // cover new blocks. Normally coverage would get reported
    // when a path completes, but that might miss states that didn't
    // finish but have nevertheless new covered blocks.
    m_coverageTimeout = cfg->getInt(getConfigKey() + ".coverageTimeout", 60);
    m_timeOfLastCoverageReport = now;
}

void CGCInterface::onSeed(const seeds::Seed &seed, seeds::SeedEvent event)
{
    if (event == seeds::TERMINATED) {
        getDebugStream() << "Guest terminated seed " << seed.filename << "\n";
        ++m_completedSeeds;
        return;
    } else if (event == seeds::SCHEDULING_FAILED) {
        assert(m_explorationState == WAIT_SEED_SCHEDULING);
        m_explorationState = WAIT_FOR_NEW_SEEDS;
        return;
    }

    if (event != seeds::FETCHED) {
        return;
    }

    getDebugStream() << "Guest fetched seed " << seed.filename << "\n";
    getDebugStream() << "Constraints size: " << g_s2e_state->constraints.size() << "\n";

    assert(m_explorationState == WAIT_SEED_SCHEDULING);

    m_explorationState = WAIT_SEED_EXECUTION;
    m_seedSearcher->enableSeeds(false);

    uint64_t now = llvm::sys::TimeValue::now().seconds();

    m_timeOfLastFetchedSeed = now;

    if (seed.priority > 0) {
        m_timeOfLastHighPrioritySeed = now;
    }
}

void CGCInterface::onSegFault(S2EExecutionState *state, uint64_t pid, uint64_t address)
{
    m_timeOfLastCrash = llvm::sys::TimeValue::now().seconds();
}

void CGCInterface::onNewBlockCovered(S2EExecutionState *state)
{
    m_timeOfLastCoveredBlock = llvm::sys::TimeValue::now().seconds();
}

void CGCInterface::onProcessForkComplete(bool isChild)
{
    if (isChild) {
        // These variables have to be reset in the child process
        // because they reflect the stats of the parent process.
        m_lastReportedStateCount = 0;
        m_completedPaths = 0;
        m_completedSeeds = 0;
        m_recipe->resetStats();
    }
}

void CGCInterface::onRandom(S2EExecutionState *state,
                            uint64_t pid, const std::vector<klee::ref<klee::Expr>> &data)
{

    std::string name;
    if (!m_monitor->getProcessName(state, pid, name)) {
        return;
    }

    bool prev = m_cbStats[name].calledRandom;
    m_cbStats[name].calledRandom = true;
    if (!prev) {
        m_cbStatsChanged = true;
    }
}

void CGCInterface::onRandomInputFork(S2EExecutionState *state,
                               const ModuleDescriptor *module)
{
    uint64_t pc = module->ToNativeBase(state->getPc());
    auto &d = m_cbStats[module->Name].randomBranchesPc;
    m_cbStatsChanged |= d.find(pc) == d.end();
    d.insert(pc);
}

void CGCInterface::processSeedStateMachine(uint64_t currentTime)
{
    /* Only works for instances that have state 0 */
    if (!m_seedSearcher->isAvailable()) {
        return;
    }

    /* Compute time delta since last major events */
    unsigned foundBlocksD = currentTime - m_timeOfLastCoveredBlock;
    unsigned foundCrashesD = currentTime - m_timeOfLastCrash;
    unsigned recentHighPrioritySeedD = currentTime - m_timeOfLastHighPrioritySeed;
    unsigned timeOfLastFetchedSeedD = currentTime - m_timeOfLastFetchedSeed;

    bool foundBlocks = foundBlocksD < m_stateMachineTimeout;
    bool foundCrashes = foundCrashesD < m_stateMachineTimeout;
    bool recentHighPrioritySeed = recentHighPrioritySeedD < m_stateMachineTimeout;
    bool recentSeedFetch = timeOfLastFetchedSeedD < m_stateMachineTimeout;

    getDebugStream() << "explorationState: " << m_explorationState << " "
                     << "timeOfLastFetchedSeed: " << timeOfLastFetchedSeedD << " "
                     << "foundBlocks: " << foundBlocksD << "s "
                     << "foundCrashes: " << foundCrashesD << "s "
                     << "hpSeed: " << recentHighPrioritySeedD << "s\n";

    if (m_explorationState == WARM_UP) {
        /* The warm up phase allows S2E to quickly find crashes and POVS
         * in easy CBs, without incurring overhead of fetching
         * and running the seeds. How long the plugin stays in this phase
         * depends on S2E's success in finding new basic blocks and crashes.*/
        if (!foundBlocks && !foundCrashes) {
            m_explorationState = WAIT_FOR_NEW_SEEDS;
        } else {
            m_seedSearcher->enableSeeds(false);
        }

    } else if (m_explorationState == WAIT_FOR_NEW_SEEDS) {
        seeds::Seed seed;
        bool hasSeeds = m_seedSearcher->getTopPrioritySeed(seed);
        if (hasSeeds && seed.priority > m_lowPrioritySeedThreshold && !recentHighPrioritySeed) {
            /* Prioritize crash seeds first */
            m_seedSearcher->enableSeeds(true);
            m_explorationState = WAIT_SEED_SCHEDULING;

        } else if (!foundBlocks && !foundCrashes && m_seedSearcher->getSeedCount()) {
            /* Prioritize normal seeds if S2E couldn't find coverage on its own */
            m_seedSearcher->enableSeeds(true);
            m_explorationState = WAIT_SEED_SCHEDULING;

        } else {
            /* Otherwise, disable seed scheduling to avoid overloading */
            m_seedSearcher->enableSeeds(false);
        }

    } else if (m_explorationState == WAIT_SEED_EXECUTION) {
        /* Give newly fetched seed some time to execute */
        if (!recentSeedFetch) {
            m_explorationState = WAIT_FOR_NEW_SEEDS;
        }
    }
}

/// Send execution stats periodically
void CGCInterface::onTimer()
{
    static unsigned timerIndex = 0;

    // Need to use real time, because onTimer may not be called
    // exactly once per second, and could be delayed for a long
    // time by blocking operations (e.g., constraint solver)

    // TODO: this should really be a parameter of the onTimer signal
    uint64_t curTime = llvm::sys::TimeValue::now().seconds();

    // Update the state machine ~ every second
    processSeedStateMachine(curTime);

    processIntermediateCoverage(curTime);

    if (!g_s2e_state || !monitor_ready()) {
        return;
    }

    if (curTime - m_cbStatsLastSent < m_cbStatsUpdateInterval) {
        return;
    }

    m_cbStatsLastSent = curTime;

    getDebugStream() << "Sending statistics\n";

    QEMUEvents::PluginData data;
    data.push_back(std::make_pair("type", QOBJECT(qstring_from_str("stats"))));

    if (m_cbStatsChanged && !m_cbStats.empty()) {
        /* per-module stats */
        QDict *modules = qdict_new();
        for (auto module : m_cbStats) {
            QDict *mdata = qdict_new();
            qdict_put_obj(mdata, "called_random", QOBJECT(qbool_from_int(module.second.calledRandom)));

            QList *pcs = qlist_new();
            for (auto pc : module.second.randomBranchesPc) {
                qlist_append_obj(pcs, QOBJECT(qint_from_int(pc)));
            }

            qdict_put_obj(mdata, "random_branches_pc", QOBJECT(pcs));
            qdict_put_obj(modules, module.first.c_str(), QOBJECT(mdata));
        }

        data.push_back(std::make_pair("stats", QOBJECT(modules)));
        m_cbStatsChanged = false;
    }

    /* global stats */
    QDict *globalStats = qdict_new();

    /* Need to know increase and decrease to aggregate it across all nodes */
    int sdelta = g_s2e->getExecutor()->getStatesCount() - m_lastReportedStateCount;
    qdict_put_obj(globalStats, "states_delta", QOBJECT(qint_from_int(sdelta)));
    m_lastReportedStateCount += sdelta;


    qdict_put_obj(globalStats, "completed_paths", QOBJECT(qint_from_int(m_completedPaths)));
    m_completedPaths = 0;

    qdict_put_obj(globalStats, "completed_seeds", QOBJECT(qint_from_int(m_completedSeeds)));
    m_completedSeeds = 0;

    // Fetch the global seed count, the service will display
    // the max count received from all nodes. All nodes should
    // normally have the same value, since it comes from a shared structure.
    qdict_put_obj(globalStats, "used_seeds", QOBJECT(qint_from_int(m_seedSearcher->getUsedSeedsCount(true))));

    qdict_put_obj(globalStats, "max_completed_path_depth", QOBJECT(qint_from_int(m_maxCompletedPathDepth)));

    if (g_s2e_state) {
        unsigned tmp = std::max(m_maxCompletedPathDepth, (unsigned) g_s2e_state->constraints.size());
        m_maxPathDepth = std::max(m_maxPathDepth, tmp);
    }

    qdict_put_obj(globalStats, "max_path_depth", QOBJECT(qint_from_int(m_maxPathDepth)));

    const recipe::RecipeStats &recipeStats = m_recipe->getStats();
    qdict_put_obj(globalStats, "invalid_recipe_count", QOBJECT(qint_from_int(recipeStats.invalidRecipeCount)));
    qdict_put_obj(globalStats, "failed_recipe_tries", QOBJECT(qint_from_int(recipeStats.failedRecipeTries)));
    qdict_put_obj(globalStats, "successful_recipe_tries", QOBJECT(qint_from_int(recipeStats.successfulRecipeTries)));
    qdict_put_obj(globalStats, "recipe_count", QOBJECT(qint_from_int(m_recipe->getRecipeCount())));

    // The service will sum all stats, so need to reset here
    m_recipe->resetStats();

    // This information allows us to know whether the cfg lua file was loaded properly
    unsigned bbcnt = m_cfg ? m_cfg->getBasicBlockCount() : 0;
    qdict_put_obj(globalStats, "cfg_bb_count", QOBJECT(qint_from_int(bbcnt)));

    unsigned mcnt = m_models ? m_models->getFunctionModelCount() : 0;
    qdict_put_obj(globalStats, "model_count", QOBJECT(qint_from_int(mcnt)));

    data.push_back(std::make_pair("global_stats", QOBJECT(globalStats)));

    // Call site information
    std::stringstream callSiteFileName;
    callSiteFileName << "calls-" << timerIndex << ".json";
    std::string callSitePath = s2e()->getOutputFilename(callSiteFileName.str());
    m_csTracker->generateJsonFile(callSitePath);
    data.push_back(std::make_pair("callsites_filename", QOBJECT(qstring_from_str(callSitePath.c_str()))));

    ++timerIndex;

    QEMUEvents::emitQMPEvent(this , data);
}


void CGCInterface::constraintsToJson(S2EExecutionState* state, std::stringstream &output)
{
    output << "[";

    foreach2(con, state->constraints.begin(), state->constraints.end()) {
        output << "\"" << *con << "\"";
        auto tmp = con;
        ++tmp;
        if (tmp != state->constraints.end()) {
            output << ",";
        }
    }

    output << "]";
}

std::string CGCInterface::constraintsToJsonFile(S2EExecutionState* state)
{
    // Ensure unique file names
    static unsigned index = 0;
    std::stringstream fileName;
    fileName << "constraints-" << state->getID() << "-" << index << ".json";
    index++;

    std::string path = s2e()->getOutputFilename(fileName.str());

    std::stringstream output;
    constraintsToJson(state, output);

    std::error_code error;
    llvm::raw_fd_ostream o(path.c_str(), error, llvm::sys::fs::F_None);

    if (error) {
        getWarningsStream() << "Unable to open " << path << " - " << error.message();
    } else {
        o << output.str() << "\n";
        o.close();
    }

    return path;
}

/**
 * The server will decide what to do with the test case (verify, send to db, etc.)
 */
void CGCInterface::sendTestcase(S2EExecutionState *state, const std::string &xmlPovPath,
                                const std::string &cPovPath, TestCaseType tcType,
                                const PovOptions &opt, const std::string &recipeName)
{
    // This ensures that we generate unique file names for coverage, constraints, etc.
    // This is important, because sendTestcase may be called several times for the same
    // state and files could be overwritten before the service had a chance to read them.
    static unsigned testCaseIndex = 0;

    QEMUEvents::PluginData data;
    data.push_back(std::make_pair("type", QOBJECT(qstring_from_str("testcase"))));

    switch (tcType) {
        case ExploitGenerator::POV: {
            data.push_back(std::make_pair("testcase_type", QOBJECT(qstring_from_str("pov"))));
        } break;

        case ExploitGenerator::CRASH: {
            data.push_back(std::make_pair("testcase_type", QOBJECT(qstring_from_str("crash"))));
        } break;

        case ExploitGenerator::END_OF_PATH: {
            data.push_back(std::make_pair("testcase_type", QOBJECT(qstring_from_str("end_of_path"))));
        } break;

        case ExploitGenerator::PARTIAL_PATH: {
            data.push_back(std::make_pair("testcase_type", QOBJECT(qstring_from_str("partial_path"))));
        } break;
    }

    if (recipeName.length()) {
        data.push_back(std::make_pair("recipe_name", QOBJECT(qstring_from_str(recipeName.c_str()))));
    }


    // Files could be huge, cannot pass them through qmp
    if (m_recordConstraints) {
        std::string constraintsPath = constraintsToJsonFile(state);
        data.push_back(std::make_pair("constraints_filename", QOBJECT(qstring_from_str(constraintsPath.c_str()))));
    }

    // Basic block coverage
    // XXX: This might be deprectated. The fuzzer might not need accurate basic block info.
    // TB coverage might be just as good. On the other hand, bb coverage gives interesting
    // data for the dashboard.
    std::stringstream coverageFileName;
    coverageFileName << "coverage-" << state->getID() << "-" << testCaseIndex << ".json";
    std::string coveragePath = s2e()->getOutputFilename(coverageFileName.str());
    m_coverage->generateJsonCoverageFile(state, coveragePath);
    data.push_back(std::make_pair("coverage_filename", QOBJECT(qstring_from_str(coveragePath.c_str()))));

    // Translation block coverage
    // This is important if cfg info is unavailable. At least we get some approximation.
    // Also TB coverage would work for jitted code or any code missing in the cfg.
    // Note: there is no actual known upper bound for TB coverage, so percentage
    // can't be computed there.
    std::stringstream tbcoverageFileName;
    tbcoverageFileName << "tbcoverage-" << state->getID() << "-" << testCaseIndex << ".json";
    coveragePath = s2e()->getOutputFilename(tbcoverageFileName.str());
    m_tbcoverage->generateJsonCoverageFile(state, coveragePath);
    data.push_back(std::make_pair("tbcoverage_filename", QOBJECT(qstring_from_str(coveragePath.c_str()))));


    data.push_back(std::make_pair("fault_address", QOBJECT(qint_from_int(opt.m_faultAddress))));

    data.push_back(std::make_pair("xml_testcase_filename", QOBJECT(qstring_from_str(xmlPovPath.c_str()))));
    data.push_back(std::make_pair("c_testcase_filename", QOBJECT(qstring_from_str(cPovPath.c_str()))));
    data.push_back(std::make_pair("pov_type", QOBJECT(qint_from_int(opt.m_type))));

    data.push_back(std::make_pair("state_id", QOBJECT(qint_from_int(state->getID()))));

    // Report which seed was used to find this test case
    data.push_back(std::make_pair("seed_id", QOBJECT(qint_from_int(m_seedSearcher->getSubtreeSeedIndex(state)))));

    QEMUEvents::emitQMPEvent(this, data);

    testCaseIndex++;
}

void CGCInterface::onPovReady(S2EExecutionState* state, const PovOptions &opt,
                              const std::string &recipeName,
                              const std::string &xmlFilename,
                              const std::string &cFilename,
                              TestCaseType tcType)
{
    sendTestcase(state, xmlFilename, cFilename, tcType, opt, recipeName);
}

bool CGCInterface::updateCoverage(S2EExecutionState *state)
{
    bool hasNewCoveredBlocks = false;
    bool success = true;
    auto bmp = m_coveredTbs.acquire();
    const auto tbcoverage = m_tbcoverage->getCoverage(state);

    for (auto it : tbcoverage) {
        const auto &module = it.first;
        const auto &tbs = it.second;

        ModuleDescriptor desc;
        unsigned index = 0;
        desc.Name = module;
        if (!m_detector->getModuleId(desc, &index)) {
            continue;
        }

        for (auto tbit : tbs) {
            bool covered = false;
            if (!bmp->setCovered(index, tbit.startOffset, tbit.size, covered)) {
                success = false;
            }
            hasNewCoveredBlocks |= !covered;
        }
    }

    m_coveredTbs.release();

    // In case global coverage could not be determined, fallback
    // to per-instance coverage.
    auto cov = m_tbcoverage->getCoverage(state);
    bool lret = coverage::mergeCoverage(m_localCoveredTbs, cov);
    if (!success) {
        hasNewCoveredBlocks |= lret;
    }

    return hasNewCoveredBlocks;
}

void CGCInterface::processIntermediateCoverage(uint64_t currentTime)
{
    if (currentTime - m_timeOfLastCoverageReport < m_coverageTimeout) {
        return;
    }

    getDebugStream() << "Looking for states with new covered blocks...\n";
    auto states = m_tbcoverage->getStatesWithNewBlocks();

    for (auto ks : states) {
        S2EExecutionState *state = dynamic_cast<S2EExecutionState*>(ks);
        bool hasNewBlocks = updateCoverage(state);
        if (hasNewBlocks) {
            getDebugStream(state) << "Reporting new blocks\n";
            sendCoveragePov(state, ExploitGenerator::PARTIAL_PATH);
        }
    }

    m_tbcoverage->clearStatesWithNewBlocks();
    m_timeOfLastCoverageReport = currentTime;
}

bool CGCInterface::sendCoveragePov(S2EExecutionState *state, TestCaseType tctype)
{
    std::string prefix;
    if (tctype == ExploitGenerator::END_OF_PATH) {
        prefix = "kill";
    } else if (tctype == ExploitGenerator::PARTIAL_PATH) {
        prefix = "partial";
    } else {
        getWarningsStream(state) << "Invalid coverage tc type\n";
        return false;
    }

    POVGenerator::PovOptions opt;
    std::string xmlPov, cPov;
    m_povGenerator->generatePoV(state, opt, xmlPov, cPov);
    if (!xmlPov.length() && !cPov.length()) {
        getWarningsStream(state) << "Failed to generate PoV\n";
        return false;
    }

    std::string xmlFilename, cFilename;
    if (xmlPov.length()) {
        xmlFilename = m_povGenerator->writeToFile(state, opt, prefix, "xml", xmlPov);
    }
    if (cPov.length()) {
        cFilename = m_povGenerator->writeToFile(state, opt, prefix, "c", cPov);
    }

    onPovReady(state, opt, "", xmlFilename, cFilename, tctype);

    return true;
}

void CGCInterface::onStateKill(S2EExecutionState *state)
{
    getInfoStream(state) << "State was killed, generating testcase\n";

    /* XXX: state might be killed because of resource issues ? */
    ++m_completedPaths;
    m_maxCompletedPathDepth = std::max(m_maxCompletedPathDepth, (unsigned) state->constraints.size());

    // TODO: share coverage info between nodes
    bool coveredNewBlocks = updateCoverage(state);
    bool submitPov = coveredNewBlocks;

    if (!submitPov) {
        return;
    }

    sendCoveragePov(state, ExploitGenerator::END_OF_PATH);
}

} // namespace plugins
} // namespace s2e
