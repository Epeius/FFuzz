///
/// Copyright (C) 2011-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///

#include "fsigc++.h"

namespace fsigc {

connection::connection(mysignal_base *sig, void *func) {
    m_functor = func;
    m_sig = sig;
    m_connected = true;
}

void connection::disconnect() {
    if (m_connected) {
        m_sig->disconnect(m_functor);
        m_functor = NULL;
        m_connected = false;
    }
}

}
