///
/// Copyright (C) 2014-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_EdgeCoverage_H
#define S2E_PLUGINS_EdgeCoverage_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/EdgeDetector.h>
#include <s2e/Plugins/ModuleExecutionDetector.h>
#include <llvm/ADT/DenseSet.h>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>

namespace s2e {
namespace plugins {

class EdgeCoverage : public Plugin
{
    S2E_PLUGIN
private:

    typedef std::pair<uint64_t, uint64_t> Edge;
    struct StateEdge {
        S2EExecutionState *state;
        Edge edge;
    };

    struct state_t {};
    struct edge_t {};

    typedef boost::multi_index_container<
        StateEdge,
        boost::multi_index::indexed_by<
            boost::multi_index::ordered_unique<
                boost::multi_index::tag<state_t>,
                BOOST_MULTI_INDEX_MEMBER(StateEdge,S2EExecutionState *,state)
            >,
            boost::multi_index::ordered_non_unique<
                boost::multi_index::tag<edge_t>,
                BOOST_MULTI_INDEX_MEMBER(StateEdge,Edge,edge)
            >
        >
    > MultiStatesEdges;

    typedef MultiStatesEdges::index<state_t>::type StatesByPointer;
    typedef MultiStatesEdges::index<edge_t>::type StatesByEdge;
    typedef std::map<std::string, MultiStatesEdges> StateLocations;


    typedef llvm::DenseSet<Edge> CoveredEdges;
    typedef std::map<std::string, CoveredEdges> Coverage;


    Coverage m_coveredEdges;
    StateLocations m_nonCoveredEdges;
public:
    EdgeCoverage(S2E* s2e): Plugin(s2e) {}

    void initialize();


    bool isCovered(const std::string &module, uint64_t source, uint64_t dest) {
        Coverage::iterator mit = m_coveredEdges.find(module);
        if (mit == m_coveredEdges.end()){
            return false;
        }

        Edge edge = std::make_pair(source, dest);
        return (*mit).second.find(edge) != (*mit).second.end();
    }

    void addNonCoveredEdge(S2EExecutionState *state, const std::string &module, uint64_t source, uint64_t dest);
    S2EExecutionState *getNonCoveredState(llvm::DenseSet<S2EExecutionState*> &filter);

private:
    EdgeDetector *m_edgeDetector;
    ModuleExecutionDetector *m_exec;

    void onUpdateStates(S2EExecutionState* state,
                        const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);

    void onEdge(S2EExecutionState *state, uint64_t source, EdgeType type);

};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EdgeCoverage_H
