/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2016  Cyberhaven, Inc
/// Copyrights of all contributions belong to their respective owners.
///
/// This library is free software; you can redistribute it and/or
/// modify it under the terms of the GNU Library General Public
/// License as published by the Free Software Foundation; either
/// version 2 of the License, or (at your option) any later version.
///
/// This library is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
/// Library General Public License for more details.
///
/// You should have received a copy of the GNU Library General Public
/// License along with this library; if not, see <http://www.gnu.org/licenses/>.

#ifndef QEMU_TIMER_H
#define QEMU_TIMER_H

#include <inttypes.h>
#include <time.h>
#include <sys/time.h>

#define SCALE_MS 1000000
#define SCALE_US 1000
#define SCALE_NS 1

typedef struct QEMUTimer QEMUTimer;
typedef struct QEMUClock QEMUClock;
typedef void QEMUTimerCB(void *opaque);

/* The real time clock should be used only for stuff which does not
   change the virtual machine state, as it is run even if the virtual
   machine is stopped. The real time clock has a frequency of 1000
   Hz. */
extern QEMUClock *rt_clock;

/* The virtual clock is only run during the emulation. It is stopped
   when the virtual machine is stopped. Virtual timers use a high
   precision clock, usually cpu cycles (use ticks_per_sec). */
extern QEMUClock *vm_clock;

/* The host clock should be use for device models that emulate accurate
   real time sources. It will continue to run when the virtual machine
   is suspended, and it will reflect system time changes the host may
   undergo (e.g. due to NTP). The host clock has the same precision as
   the virtual clock. */
extern QEMUClock *host_clock;

int64_t qemu_get_clock_ns(QEMUClock *clock);
int64_t qemu_clock_has_timers(QEMUClock *clock);
int64_t qemu_clock_expired(QEMUClock *clock);
int64_t qemu_clock_deadline(QEMUClock *clock);
void qemu_clock_enable(QEMUClock *clock, int enabled);

QEMUTimer *qemu_new_timer(QEMUClock *clock, int scale,
                          QEMUTimerCB *cb, void *opaque);
void qemu_free_timer(QEMUTimer *ts);
void qemu_del_timer(QEMUTimer *ts);
void qemu_mod_timer_ns(QEMUTimer *ts, int64_t expire_time);
void qemu_mod_timer(QEMUTimer *ts, int64_t expire_time);
int qemu_timer_pending(QEMUTimer *ts);
int qemu_timer_expired(QEMUTimer *timer_head, int64_t current_time);
uint64_t qemu_timer_expire_time_ns(QEMUTimer *ts);

void qemu_run_timers(QEMUClock *clock);
void qemu_run_all_timers(void);
int qemu_alarm_pending(void);
void init_clocks(void);
int init_timer_alarm(int register_exit_handler);

static inline QEMUTimer *qemu_new_timer_ns(QEMUClock *clock, QEMUTimerCB *cb,
                                           void *opaque)
{
    return qemu_new_timer(clock, SCALE_NS, cb, opaque);
}

static inline QEMUTimer *qemu_new_timer_ms(QEMUClock *clock, QEMUTimerCB *cb,
                                           void *opaque)
{
    return qemu_new_timer(clock, SCALE_MS, cb, opaque);
}

static inline int64_t qemu_get_clock_ms(QEMUClock *clock)
{
    return qemu_get_clock_ns(clock) / SCALE_MS;
}

static inline int64_t get_ticks_per_sec(void)
{
    return 1000000000LL;
}

/* real time host monotonic timer */
static inline int64_t get_clock_realtime(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000000LL + (tv.tv_usec * 1000);
}

/* Warning: don't insert tracepoints into these functions, they are
   also used by simpletrace backend and tracepoints would cause
   an infinite recursion! */

extern int use_rt_clock;

static inline int64_t get_clock(void)
{
#if defined(__linux__) || (defined(__FreeBSD__) && __FreeBSD_version >= 500000) \
    || defined(__DragonFly__) || defined(__FreeBSD_kernel__)
    if (use_rt_clock) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return ts.tv_sec * 1000000000LL + ts.tv_nsec;
    } else
#endif
    {
        /* XXX: using gettimeofday leads to problems if the date
           changes, so it should be avoided. */
        return get_clock_realtime();
    }
}

int64_t cpu_get_clock(void);

/*******************************************/
/* host CPU ticks (if available) */


static inline int64_t cpu_get_real_ticks(void)
{
    int64_t val;
    asm volatile ("rdtsc" : "=A" (val));
    return val;
}

#endif
