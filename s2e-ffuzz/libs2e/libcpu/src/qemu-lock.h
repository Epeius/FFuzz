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

/* configure guarantees us that we have pthreads on any host except
 * mingw32, which doesn't support any of the user-only targets.
 * So we can simply assume we have pthread mutexes here.
 */
#if defined(CONFIG_USER_ONLY)

#include <pthread.h>
#define spin_lock pthread_mutex_lock
#define spin_unlock pthread_mutex_unlock
#define spinlock_t pthread_mutex_t
#define SPIN_LOCK_UNLOCKED PTHREAD_MUTEX_INITIALIZER

#else

/* Empty implementations, on the theory that system mode emulation
 * is single-threaded. This means that these functions should only
 * be used from code run in the TCG cpu thread, and cannot protect
 * data structures which might also be accessed from the IO thread
 * or from signal handlers.
 */
typedef int spinlock_t;
#define SPIN_LOCK_UNLOCKED 1

static inline void spin_lock(spinlock_t *lock)
{
    spinlock_t expected = SPIN_LOCK_UNLOCKED; // this variable will contain actual value after call
    while (!__atomic_compare_exchange_n(lock, &expected, 0, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        expected = SPIN_LOCK_UNLOCKED;
    }
}

static inline void spin_unlock(spinlock_t *lock)
{
    __atomic_store_n(lock, SPIN_LOCK_UNLOCKED, __ATOMIC_SEQ_CST);
}

#endif
