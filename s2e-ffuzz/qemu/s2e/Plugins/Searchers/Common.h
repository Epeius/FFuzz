///
/// Copyright (C) 2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///

#ifndef __S2E_SEARCHERS_COMMON__
#define __S2E_SEARCHERS_COMMON__

#include <s2e/S2EExecutionState.h>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>

namespace s2e {
namespace plugins {

namespace searchers {

struct StatePriority {
    S2EExecutionState *state;
    int64_t priority;

    StatePriority() {
        state = NULL;
        priority = 0;
    }

    StatePriority(S2EExecutionState *state, int64_t p) {
        this->state = state;

        /* State with a higher p get selected first */
        this->priority = p;
    }
};

struct state_t {};
struct priority_t {};

typedef boost::multi_index_container<
    StatePriority,
    boost::multi_index::indexed_by<
        boost::multi_index::ordered_unique<
            boost::multi_index::tag<state_t>,
            BOOST_MULTI_INDEX_MEMBER(StatePriority,S2EExecutionState *,state)
        >,
        boost::multi_index::ordered_non_unique<
            boost::multi_index::tag<priority_t>,
            BOOST_MULTI_INDEX_MEMBER(StatePriority,int64_t,priority)
        >
    >
> MultiStates;


typedef MultiStates::index<state_t>::type StatesByPointer;
typedef MultiStates::index<priority_t>::type StatesByPriority;

}
}
}

#endif
