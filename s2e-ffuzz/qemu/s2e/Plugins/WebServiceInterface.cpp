///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


extern "C" {
#include "qint.h"
}

#include <sys/types.h>

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500 //getpgid
#endif

#include <unistd.h>

//requires -lproc
#include <proc/readproc.h> //openproc, readproc, closeproc

#include "WebServiceInterface.h"
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/S2EStatsTracker.h>
#include <klee/SolverStats.h>
#include <klee/CoreStats.h>
#include <llvm/Support/TimeValue.h>
#include "QEMUEvents.h"

#include <iostream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(WebServiceInterface, "Interface S2E with Web services", "",);

void WebServiceInterface::initialize()
{
    s2e()->getCorePlugin()->onMonitorCommand.connect(
            sigc::mem_fun(*this, &WebServiceInterface::onMonitorCommand));

    s2e()->getCorePlugin()->onMonitorEvent.connect(
            sigc::mem_fun(*this, &WebServiceInterface::onMonitorEvent));

    s2e()->getCorePlugin()->onTimer.connect(
            sigc::mem_fun(*this, &WebServiceInterface::onTimer));

    s2e()->getCorePlugin()->onStateKill.connect(
            sigc::mem_fun(*this, &WebServiceInterface::onStateKill));

    m_lastQueuedPaths = 0;
    m_timerTicks = 0;
    m_firstTimerTick = 0;
    m_sendTimerTicks = 0;
}

WebServiceInterface::~WebServiceInterface()
{

}


void WebServiceInterface::onTimer()
{
    if (!m_firstTimerTick) {
        /* Measure how much time it takes for the VM to resume */
        m_firstTimerTick = llvm::sys::TimeValue::now().seconds();
        m_firstTimerTick -= s2e()->getStartTime();
    }

    ++m_timerTicks;

    /* Send data every 10 seconds */
    if (m_sendTimerTicks < 10) {
        ++m_sendTimerTicks;
        return;
    }

    m_sendTimerTicks = 0;

    QDict *stats = getStats();
    QEMUEvents::printDict(this, stats);


    if (!g_s2e_state || !monitor_ready()) {
        QDECREF(stats);
        return;
    }

    QEMUEvents::PluginData data;

    data.push_back(std::make_pair("stats", QOBJECT(stats)));
    QEMUEvents::emitQMPEvent(this, data);
}

void WebServiceInterface::onStateKill(S2EExecutionState *state)
{
    if (s2e()->getExecutor()->isLoadBalancing()) {
        return;
    }

    WebServiceStats *stats = m_experimentGlobalStats.acquire();

    ++stats->completedPaths;

    m_experimentGlobalStats.release();
}

QDict *WebServiceInterface::getStats()
{
    QDict *qdict = qdict_new();

#define INT2OBJ(x)  QOBJECT(qint_from_int(x))
#define STR2OBJ(x)  QOBJECT(qstring_from_str(x.c_str()))

    WebServiceStats *stats = m_experimentGlobalStats.acquire();
    qdict_put_obj(qdict, "process_index", INT2OBJ(s2e()->getCurrentProcessIndex()));
    qdict_put_obj(qdict, "pid", INT2OBJ(getpid()));
    qdict_put_obj(qdict, "start_time", INT2OBJ(s2e()->getStartTime()));

    qdict_put_obj(qdict, "global_completed_paths", INT2OBJ(stats->completedPaths));
    qdict_put_obj(qdict, "local_queued_paths", INT2OBJ(g_s2e->getExecutor()->getStatesCount()));

#if 0
    qdict_put_obj(qdict, "queries", INT2OBJ(klee::stats::queries));
    qdict_put_obj(qdict, "translation_blocks_concrete", INT2OBJ(klee::stats::translationBlocksConcrete));
    qdict_put_obj(qdict, "translation_blocks_symbolic", INT2OBJ(klee::stats::translationBlocksKlee));
    qdict_put_obj(qdict, "concrete_mode_time", INT2OBJ(klee::stats::concreteModeTime / 1000000));
    qdict_put_obj(qdict, "symbolic_mode_time", INT2OBJ(klee::stats::symbolicModeTime / 1000000));
    qdict_put_obj(qdict, "wall_time", INT2OBJ(llvm::sys::TimeValue::now().seconds() - s2e()->getStartTime()));
    qdict_put_obj(qdict, "query_time", INT2OBJ(klee::stats::queryTime / 1000000));
    qdict_put_obj(qdict, "solver_time", INT2OBJ(klee::stats::solverTime / 1000000));
    qdict_put_obj(qdict, "memory_usage", INT2OBJ(S2EStatsTracker::getProcessMemoryUsage()));
#endif

    m_experimentGlobalStats.release();

    qdict_put_obj(qdict, "resume_time", QOBJECT(qint_from_int(m_firstTimerTick)));
    qdict_put_obj(qdict, "s2e_memory_usage", QOBJECT(qint_from_int(S2EStatsTracker::getProcessMemoryUsage())));

    return qdict;
}

void WebServiceInterface::onMonitorEvent(const QDict *event, QDict *ret)
{
    /* Don't transmit any info unless the system is shutting down */
    const char *eventName = qdict_get_str(event, "event");
    if (strcmp(eventName, "SHUTDOWN")) {
        return;
    }

    QDict *result = QEMUEvents::createResult(this, ret);
    qdict_put(result, "status", getStats());
}


void WebServiceInterface::onMonitorCommand(Monitor *mon, const QDict *qdict, QDict* ret)
{
#if 0
    QDict *pluginData = QEMUEvents::getPluginData(this, qdict);
    if (!pluginData) {
        return;
    }

    QDict *result;
    Error *local_err = NULL;

    const char *command = qdict_get_try_str(pluginData, "command");
    if (!command) {
        error_set(&local_err, QERR_INVALID_PARAMETER, "command");
        goto out;
    }

    result = QEMUEvents::createResult(this, ret);

    if (!strcmp(command, "getstatus")) {
        qdict_put(result, "status", getStats());
    }

out:
    if (local_err) {
        QDECREF(result);
        qerror_report_err(local_err);
        error_free(local_err);
    }
    return;
#endif
}

int WebServiceInterface::getProcessCount()
{
    PROCTAB* ptp;
    proc_t proc;
    unsigned int processes = 0;

    assert(false && "buggy");

    ptp = openproc(PROC_FILLSTAT);
    if (!ptp) {
        fprintf(stderr, "Error: can not access /proc.\n");
        return -1;
    }

    while (readproc(ptp,&proc)) {
        if (proc.pgrp == getpgid(0)) {
            processes += 1;
        }
    }

    closeproc(ptp);

    return processes;
}


} // namespace plugins
} // namespace s2e
