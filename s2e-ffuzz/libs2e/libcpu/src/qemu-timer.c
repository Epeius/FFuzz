/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2016 Cyberhaven, Inc
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>
#include <signal.h>
#include <glib.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>

#include "qemu-timer.h"

/***********************************************************/
/* timers */

#define QEMU_CLOCK_REALTIME 0
#define QEMU_CLOCK_VIRTUAL  1
#define QEMU_CLOCK_HOST     2

struct QEMUClock {
    int type;
    int enabled;

    QEMUTimer *active_timers;

    int64_t last;
};

struct QEMUTimer {
    QEMUClock *clock;
    int64_t expire_time;	/* in nanoseconds */
    int scale;
    QEMUTimerCB *cb;
    void *opaque;
    struct QEMUTimer *next;

    int delayed;
    uint64_t delay_value;
};

static bool qemu_timer_expired_ns(QEMUTimer *timer_head, int64_t current_time)
{
    return timer_head && (timer_head->expire_time <= current_time);
}



QEMUClock *rt_clock;
QEMUClock *vm_clock;
QEMUClock *host_clock;

static QEMUClock *qemu_new_clock(int type)
{
    QEMUClock *clock;

    clock = g_malloc0(sizeof(QEMUClock));
    clock->type = type;
    clock->enabled = 1;
    clock->last = INT64_MIN;
    return clock;
}

void qemu_clock_enable(QEMUClock *clock, int enabled)
{
    clock->enabled = enabled;
}

int64_t qemu_clock_has_timers(QEMUClock *clock)
{
    return !!clock->active_timers;
}

int64_t qemu_clock_expired(QEMUClock *clock)
{
    return (clock->active_timers &&
            clock->active_timers->expire_time < qemu_get_clock_ns(clock));
}

int64_t qemu_clock_deadline(QEMUClock *clock)
{
    /* To avoid problems with overflow limit this to 2^32.  */
    int64_t delta = INT32_MAX;

    if (clock->active_timers) {
        delta = clock->active_timers->expire_time - qemu_get_clock_ns(clock);
    }
    if (delta < 0) {
        delta = 0;
    }
    return delta;
}

QEMUTimer *qemu_new_timer(QEMUClock *clock, int scale,
                          QEMUTimerCB *cb, void *opaque)
{
    QEMUTimer *ts;

    ts = g_malloc0(sizeof(QEMUTimer));
    ts->clock = clock;
    ts->cb = cb;
    ts->opaque = opaque;
    ts->scale = scale;
    return ts;
}

void qemu_free_timer(QEMUTimer *ts)
{
    g_free(ts);
}

/* stop a timer, but do not dealloc it */
void qemu_del_timer(QEMUTimer *ts)
{
    QEMUTimer **pt, *t;

    /* NOTE: this code must be signal safe because
       qemu_timer_expired() can be called from a signal. */
    pt = &ts->clock->active_timers;
    for(;;) {
        t = *pt;
        if (!t)
            break;
        if (t == ts) {
            *pt = t->next;
            break;
        }
        pt = &t->next;
    }
}

/* modify the current timer so that it will be fired when current_time
   >= expire_time. The corresponding callback will be called. */
void qemu_mod_timer_ns(QEMUTimer *ts, int64_t expire_time)
{
    QEMUTimer **pt, *t;

    qemu_del_timer(ts);

    /* add the timer in the sorted list */
    /* NOTE: this code must be signal safe because
       qemu_timer_expired() can be called from a signal. */
    pt = &ts->clock->active_timers;
    for(;;) {
        t = *pt;
        if (!qemu_timer_expired_ns(t, expire_time)) {
            break;
        }
        pt = &t->next;
    }
    ts->expire_time = expire_time;
    ts->next = *pt;
    *pt = ts;
}

void qemu_mod_timer(QEMUTimer *ts, int64_t expire_time)
{
    qemu_mod_timer_ns(ts, expire_time * ts->scale);
}

int qemu_timer_pending(QEMUTimer *ts)
{
    QEMUTimer *t;
    for (t = ts->clock->active_timers; t != NULL; t = t->next) {
        if (t == ts)
            return 1;
    }
    return 0;
}

int qemu_timer_expired(QEMUTimer *timer_head, int64_t current_time)
{
    return qemu_timer_expired_ns(timer_head, current_time * timer_head->scale);
}

void qemu_run_timers(QEMUClock *clock)
{
    QEMUTimer **ptimer_head, *ts;
    int64_t current_time;

    if (!clock->enabled)
        return;

    current_time = qemu_get_clock_ns(clock);
    ptimer_head = &clock->active_timers;
    for(;;) {
        ts = *ptimer_head;
        if (!qemu_timer_expired_ns(ts, current_time)) {
            break;
        }
        /* remove timer from the list before calling the callback */
        *ptimer_head = ts->next;
        ts->next = NULL;

        /* run the callback (the timer list can be modified) */
        ts->cb(ts->opaque);
    }
}

int64_t qemu_get_clock_ns(QEMUClock *clock)
{
    int64_t now, last;

    switch(clock->type) {
    case QEMU_CLOCK_REALTIME:
        return get_clock();
    default:
    case QEMU_CLOCK_VIRTUAL:
        return cpu_get_clock();
    case QEMU_CLOCK_HOST:
        now = get_clock_realtime();
        last = clock->last;
        clock->last = now;
        return now;
    }
}


void init_clocks(void)
{
    rt_clock = qemu_new_clock(QEMU_CLOCK_REALTIME);
    vm_clock = qemu_new_clock(QEMU_CLOCK_VIRTUAL);
    host_clock = qemu_new_clock(QEMU_CLOCK_HOST);
}

uint64_t qemu_timer_expire_time_ns(QEMUTimer *ts)
{
    return qemu_timer_pending(ts) ? ts->expire_time : -1;
}

void qemu_run_all_timers(void)
{
    /* vm time timers */
    qemu_run_timers(vm_clock);
    qemu_run_timers(rt_clock);
    qemu_run_timers(host_clock);
}


/***********************************************************/
/* real time host monotonic timer */

int use_rt_clock;

static void __attribute__((constructor)) init_get_clock(void)
{
    use_rt_clock = 0;
#if defined(__linux__) || (defined(__FreeBSD__) && __FreeBSD_version >= 500000) \
    || defined(__DragonFly__) || defined(__FreeBSD_kernel__) \
    || defined(__OpenBSD__)
    {
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
            use_rt_clock = 1;
        }
    }
#endif
}
