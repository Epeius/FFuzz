//===-- MemoryUsage.cpp ---------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Internal/System/MemoryUsage.h"

#include "klee/Config/config.h"

#ifdef HAVE_GPERFTOOLS_MALLOC_EXTENSION_H
#include "gperftools/malloc_extension.h"
#endif

#ifdef HAVE_MALLINFO
#include <malloc.h>
#endif
#ifdef HAVE_MALLOC_MALLOC_H
#include <malloc/malloc.h>
#endif

using namespace klee;

size_t util::GetTotalMallocUsage() {
#ifdef HAVE_GPERFTOOLS_MALLOC_EXTENSION_H
  size_t value = 0;
  MallocExtension::instance()->GetNumericProperty(
      "generic.current_allocated_bytes", &value);
  return value;
#elif HAVE_MALLINFO
  struct mallinfo mi = ::mallinfo();
  // The malloc implementation in glibc (pmalloc2)
  // does not include mmap()'ed memory in mi.uordblks
  // but other implementations (e.g. tcmalloc) do.
#if defined(__GLIBC__)
  return (size_t)(unsigned)mi.uordblks + (unsigned)mi.hblkhd;
#else
  return (unsigned)mi.uordblks;
#endif

#elif defined(HAVE_MALLOC_ZONE_STATISTICS) && defined(HAVE_MALLOC_MALLOC_H)

  // Support memory usage on Darwin.
  malloc_statistics_t Stats;
  malloc_zone_statistics(malloc_default_zone(), &Stats);
  return Stats.size_in_use;

#else // HAVE_MALLINFO

#warning Cannot get malloc info on this platform
  return 0;

#endif
}
