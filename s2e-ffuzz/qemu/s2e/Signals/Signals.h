///
/// Copyright (C) 2011-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///

#ifndef __S2E_SIGNALS_MAIN__

#define __S2E_SIGNALS_MAIN__

#include <s2e/s2e_config.h>

#ifdef S2E_USE_FAST_SIGNALS
#define sigc fsigc
#include "fsigc++.h"
#else
#include <sigc++/sigc++.h>
#endif

#endif
