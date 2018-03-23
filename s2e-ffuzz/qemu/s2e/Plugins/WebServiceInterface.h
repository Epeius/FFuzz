///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_WebServiceInterface_H
#define S2E_PLUGINS_WebServiceInterface_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Synchronization.h>

namespace s2e {
namespace plugins {

struct WebServiceStats {
    unsigned completedPaths;
};

struct WebServiceGlobalStats {
    //Number of active workers in the whole system
    //TODO: Periodically sync with info from the
    //load balancer. Instances may crash, so external
    //monitoring is required.
    uint32_t activeWorkersCount;

    //s2e-lb updates this variable.
    //Avoid forking if there are any queued jobs.
    uint32_t queuedJobs;

    WebServiceGlobalStats() {
        //Do not init members
    }
};

class WebServiceInterface : public Plugin
{
    S2E_PLUGIN
public:
    WebServiceInterface(S2E* s2e): Plugin(s2e) {

    }

    virtual ~WebServiceInterface();

    void initialize();

private:
    void onTimer();

    QDict *getStats();
    int getProcessCount();
    void onProcessForkDecide(bool *proceed);
    void onProcessFork(bool preFork, bool isChild, unsigned parentProcId);
    void onMonitorCommand(Monitor *mon, const QDict * qdict, QDict* ret);
    void onMonitorEvent(const QDict *event, QDict *ret);
    void onStateKill(S2EExecutionState *state);

    unsigned m_lastQueuedPaths;

    unsigned m_timerTicks;
    unsigned m_forkDelay;
    uint64_t m_firstTimerTick;
    uint64_t m_sendTimerTicks;

    S2ESynchronizedObject<WebServiceStats> m_experimentGlobalStats;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_WebServiceInterface_H
