/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2013, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */


#include "klee/Common.h"
#include "klee/Solver.h"
#include "klee/SolverImpl.h"
#include "klee/util/Assignment.h"
#include "klee/util/ExprSMTLIBPrinter.h"
#include "klee/util/ExprUtil.h"

#include "llvm/Support/CommandLine.h"

#include <string>
#include <fstream>
#include <boost/asio.hpp>


namespace {
llvm::cl::opt<std::string>
ExternalSolverHost("external-solver-host",
                   llvm::cl::init("localhost"));

llvm::cl::opt<std::string>
ExternalSolverPort("external-solver-port",
                   llvm::cl::init("1234"));

llvm::cl::opt<bool>
ExternalSolverIncremental("external-solver-incremental",
                          llvm::cl::init(false));

llvm::cl::opt<bool>
ExternalSolverDebug("external-solver-debug",
                    llvm::cl::init(false));
}

using namespace boost::asio;

namespace klee {


class ExternalSolverImpl : public SolverImpl {
private:
    boost::asio::io_service m_io_service;
    ip::tcp::socket m_socket;
    ExprSMTLIBPrinter m_smtPrinter;
    std::ofstream *m_queryLog;

    bool m_incrementalModeInited;
    uint64_t m_csManagerId;
    uint64_t m_sessionId;

    std::set<const Array*> m_declaredArrays;

    bool initializeConnection(bool reuseSessionId = false);
    bool checkSat(const Query &query, bool &isSat,
                  const std::vector<const Array*> *array,
                  std::vector< std::vector<unsigned char> > *values);

    void parseConcreteInputs(boost::asio::streambuf &data,
                             std::istream &is,
                             const std::vector<const Array*> *array,
                             std::vector< std::vector<unsigned char> > *values);

    bool syncReadUntil(boost::asio::streambuf &data, const char *str);


    void setupQuery(const Query &query,
                    const std::vector<const Array*> *array,
                    bool queryIsConstraint);

    void setupIncrementalMode(const Query &query);
    void reinitialize(const Query &query);


public:
    ExternalSolverImpl(const std::string &logFile);
    ~ExternalSolverImpl();

    bool addConstraint(const ConstraintManager &owner, const ref<Expr> &constraint);
    void fork(bool preFork, bool child);
    bool computeTruth(const Query&, bool &isValid);
    bool computeValue(const Query&, ref<Expr> &result);
    bool computeInitialValues(const Query&,
                              const std::vector<const Array*> &objects,
                              std::vector< std::vector<unsigned char> > &values,
                              bool &hasSolution);
};

ExternalSolver::ExternalSolver(const std::string &logFile) : Solver(new ExternalSolverImpl(logFile))
{

}

Solver *createExternalSolver(const std::string &logFile)
{
    return new ExternalSolver(logFile);
}

ExternalSolverImpl::ExternalSolverImpl(const std::string &logFile) : SolverImpl(), m_socket(m_io_service),
    m_queryLog(NULL), m_incrementalModeInited(false)
{
    if (ExternalSolverDebug) {
        m_queryLog = new std::ofstream(logFile.c_str());
    }

    if (!initializeConnection()) {
        exit(-1);
    }
}

ExternalSolverImpl::~ExternalSolverImpl()
{
    if (m_queryLog) {
        delete m_queryLog;
    }
}

bool ExternalSolverImpl::initializeConnection(bool reuseSessionId)
{
    try {
        ip::tcp::resolver resolver(m_io_service);
        ip::tcp::resolver::query query(ExternalSolverHost, ExternalSolverPort);
        ip::tcp::resolver::iterator iter = resolver.resolve(query);

        m_socket.connect(*iter);

        //Get a new session id
        if (reuseSessionId) {
            std::stringstream ss;
            ss << "(set-session-id " << m_sessionId << ")\n";
            boost::asio::write(m_socket, boost::asio::buffer(ss.str().c_str(), ss.str().length()));
        } else {
            std::string cmd = "(get-session-id)\n";
            boost::asio::write(m_socket, boost::asio::buffer(cmd.c_str(), cmd.length()));
        }

        boost::asio::streambuf streamBuf;
        if (!syncReadUntil(streamBuf, "\n")) {
            return false;
        }

        std::istream is(&streamBuf);

        std::string session_id;
        std::getline(is, session_id);

        uint64_t receivedId = atol(session_id.c_str());
        if (reuseSessionId) {
            assert(receivedId == m_sessionId);
        } else {
            m_sessionId = receivedId;
        }

        if (m_queryLog) {
            *m_queryLog << "; New session id " << m_sessionId << "\n";
        }

        return true;
    } catch (std::exception &e) {
        std::cerr << "Exception while connecting to the external solver: "
                  << e.what() << "\n";
        return false;
    }
}

/**
 * Called upon first invocation of the solver.
 * Resets the solver and sends all the constraints.
 */
void ExternalSolverImpl::setupIncrementalMode(const Query &query)
{
    if (!ExternalSolverIncremental) {
        return;
    }

    if (m_incrementalModeInited) {
        if (query.constraints.getId() != m_csManagerId) {
            m_incrementalModeInited = false;
        } else {
            return;
        }
    }

    if (m_queryLog) {
        *m_queryLog << "; Setting up incremental mode for constraint set "
                    << query.constraints.getId() << "\n";
    }

    m_declaredArrays.clear();

    std::stringstream ss;
    m_smtPrinter.setOutput(ss);

    //XXX: grossly inefficient, will scan the whole query
    m_smtPrinter.setQuery(query);

    m_smtPrinter.printReset();
    m_smtPrinter.printOptions();
    m_smtPrinter.printSetLogic();

    m_smtPrinter.printPush();

    if (query.constraints.size()) {
        m_smtPrinter.printArrayDeclarations();
        m_smtPrinter.printConstraints();
        m_smtPrinter.printAction();

        const std::set<const Array*> &newArrays = m_smtPrinter.getUsedArrays();
        m_declaredArrays.insert(newArrays.begin(), newArrays.end());
    }

    if (m_queryLog) {
        *m_queryLog << ss.str() << "\n";
    }

    try {
        boost::asio::write(m_socket, boost::asio::buffer(ss.str().c_str(), ss.str().length()));

        if (query.constraints.size()) {
            boost::asio::streambuf data;
            if (!syncReadUntil(data, "\n")) {
                exit(-1);
            }

            std::istream is(&data);

            std::string status;
            std::getline(is, status);

            if (ExternalSolverDebug) {
                std::cerr << "Received: " << status << "\n";
            }

            if (m_queryLog) {
                *m_queryLog << "; reply: " << status << "\n";
            }

            if (status != "sat") {
                std::cerr << "ExternalSolverImpl::setupIncrementalMode: initial set of constraints is inconsistent\n";
                exit(-1);
            }
        }

    } catch (std::exception& e) {
        //TODO: handle interrupted syscalls
        std::cerr << "ExternalSolverImpl::setupIncrementalMode: exception while communicating with the external solver: "
                  << e.what() << "\n";
        exit(-1);
    }

    m_incrementalModeInited = true;
    m_csManagerId = query.constraints.getId();

    if (m_queryLog) {
        *m_queryLog << "\n";
    }
}

void ExternalSolverImpl::fork(bool preFork, bool child)
{
    std::cerr << "Forking solver\n";
    if (preFork) {
        m_socket.close();
        return;
    }

    if (child) {
        m_incrementalModeInited = false;
    }

    if (!initializeConnection(!child)) {
        exit(-1);
    }
}

bool ExternalSolverImpl::addConstraint(const ConstraintManager &owner, const ref<Expr> &constraint)
{
    if (!ExternalSolverIncremental) {
        return true;
    }

    /* Only send constraints that belong to the current path */
    if (owner.getId() != m_csManagerId) {
        return true;
    }

    assert(m_incrementalModeInited);

    if (m_queryLog) {
        *m_queryLog << ";Adding constraint\n" << std::flush;
    }

    std::stringstream ss;
    m_smtPrinter.setOutput(ss);

    ConstraintManager dummyManager;
    Query incrementalQuery(dummyManager, constraint);
    setupQuery(incrementalQuery, NULL, true);

    if (ExternalSolverDebug) {
        *m_queryLog << ss.str() << "\n\n";
    }

    try {
        boost::asio::write(m_socket, boost::asio::buffer(ss.str().c_str(), ss.str().length()));
    } catch (std::exception& e) {
        //TODO: handle interrupted syscalls
        std::cerr << "ExternalSolverImpl::computeTruth: exception while communicating with the external solver: "
                  << e.what() << "\n";
        exit(-1);
    }

    return true;
}


bool ExternalSolverImpl::syncReadUntil(boost::asio::streambuf &data, const char *str)
{
    try {
        boost::system::error_code ec;
        do {
            boost::asio::read_until(m_socket, data, str, ec);
            if (ec != boost::system::errc::interrupted) {
                if (ec != boost::system::errc::success) {
                    std::cerr << "ExternalSolverImpl::syncRead: exception while communicating with the external solver: "
                              << ec << "\n";
                    return false;
                }
            }
        } while (ec == boost::system::errc::interrupted);

        return true;
    } catch (std::exception& e) {
        //TODO: handle interrupted syscalls
        std::cerr << "ExternalSolverImpl::syncRead: exception while communicating with the external solver: "
                  << e.what() << "\n";
        return false;
    }
}

void ExternalSolverImpl::parseConcreteInputs(boost::asio::streambuf &data,
                                             std::istream &is,
                                             const std::vector<const Array*> *array,
                                             std::vector< std::vector<unsigned char> > *values)
{
    //Determine how many concrete bytes to wait for
    unsigned concreteBytes = 0;

    typedef std::map<std::string, unsigned> concrete_buffers_t;
    concrete_buffers_t concreteBuffers;

    (*values).resize(array->size());

    for (unsigned i = 0; i < array->size(); ++i) {
        concreteBytes += (*array)[i]->getSize();
        (*values)[i].resize((*array)[i]->getSize());
        concreteBuffers[(*array)[i]->getName()] = i;
    }

    if (m_queryLog) {
        std::cerr << "; concrete bytes: " << concreteBytes << "\n";
        *m_queryLog << "; concrete bytes: " << concreteBytes << "\n";
    }

    for (unsigned i = 0; i < concreteBytes; ++i) {
        std::string line;
        std::string variable;
        unsigned index;
        unsigned value;

        if (!syncReadUntil(data, "\n")) {
            exit(-1);
        }

        std::getline(is, line);

        std::stringstream ss(line);

        ss >> variable >> index >> value;
        //std::cerr << line << "\n";

        if (m_queryLog) {
            std::cerr << variable << "[" << index << "] = " << value << " \n";
            *m_queryLog << variable << "[" << index << "] = " << value << " \n";
        }

        concrete_buffers_t::iterator it = concreteBuffers.find(variable);
        assert(it != concreteBuffers.end());
        assert(index < (*values)[(*it).second].size());
        (*values)[(*it).second][index] = value;
    }
}

void ExternalSolverImpl::setupQuery(const Query &query,
                                    const std::vector<const Array*> *array,
                                    bool queryIsConstraint)
{
    //Make sure to break down the query in multiple lines,
    //so that the server does not complain about long lines (>64K)
    m_smtPrinter.setHumanReadable(true);

    if (ExternalSolverIncremental) {
        //The solver already has the path constraints,
        //Just ask the query.
        ConstraintManager dummyManager;
        Query incrementalQuery(dummyManager, query.expr);
        m_smtPrinter.setQuery(incrementalQuery);

        if (array) {
            m_smtPrinter.setArrayValuesToGet(*array);
        }

        if (!queryIsConstraint) {
            m_smtPrinter.printPush();
        }

        //XXX: What about constant arrays. Make sure to unique their name.
        m_smtPrinter.printArrayDeclarations(m_declaredArrays);
        m_smtPrinter.printQuery();

        //Declarations are not forgotten when there is a (pop)
        const std::set<const Array*> &newArrays = m_smtPrinter.getUsedArrays();
        m_declaredArrays.insert(newArrays.begin(), newArrays.end());


        if (!queryIsConstraint) {
            m_smtPrinter.printAction();
            m_smtPrinter.printPop();
        }

    } else {
        //XXX: grossly inefficient, will scan the whole query
        m_smtPrinter.setQuery(query);

        if (array) {
            m_smtPrinter.setArrayValuesToGet(*array);
        }

        m_smtPrinter.printOptions();
        m_smtPrinter.printSetLogic();
        m_smtPrinter.printArrayDeclarations();
        m_smtPrinter.printConstraints();
        m_smtPrinter.printQuery();
        m_smtPrinter.printAction();
        m_smtPrinter.printReset();
    }
}

bool ExternalSolverImpl::checkSat(const Query &query, bool &isSat,
                                  const std::vector<const Array*> *array,
                                  std::vector< std::vector<unsigned char> > *values)
{
    if (m_queryLog) {
        *m_queryLog << ";Checking SAT (constraint set " << query.constraints.getId() << ")\n";
        //*m_queryLog << query.expr << "\n";
    }

    std::stringstream ss;
    m_smtPrinter.setOutput(ss);

    setupQuery(query, array, false);

    if (m_queryLog) {
        *m_queryLog << ss.str();
    }

    try {
        boost::asio::write(m_socket, boost::asio::buffer(ss.str().c_str(), ss.str().length()));

        std::string status;
        boost::asio::streambuf data;
        std::istream is(&data);

        if (!syncReadUntil(data, "\n")) {
            exit(-1);
        }

        std::getline(is, status);

        if (m_queryLog) {
            std::cerr << "reply: " << status << "\n";
            *m_queryLog << "; reply: " << status << "\n";
        }

        if (status == "sat") {
            isSat = true;
        } else if (status == "unsat") {
            isSat = false;
        } else {
            if (m_queryLog) {
                *m_queryLog << "; invalid status " << status << "\n";
            }
            std::cerr << "ExternalSolverImpl::checkSat: invalid status " << status << "\n";
            exit(-1);
        }


        if (array && isSat) {
            parseConcreteInputs(data, is, array, values);
        }

        if (m_queryLog) {
            *m_queryLog << "\n\n";
        }

    } catch (std::exception& e) {
        //TODO: handle interrupted syscalls
        std::cerr << "ExternalSolverImpl::checkSat: exception while communicating with the external solver: "
                  << e.what() << "\n";
        exit(-1);
    }

    return true;
}

bool ExternalSolverImpl::computeTruth(const Query &query, bool &isValid)
{
    setupIncrementalMode(query);

    //A query is valid iff its negation is unsatisfiable
    Query negQuery = query.negateExpr();
    bool isSat = false;
    bool ret = checkSat(negQuery, isSat, NULL, NULL);
    isValid = !isSat;
    return ret;
}

bool ExternalSolverImpl::computeValue(const Query &query, ref<Expr> &result)
{
    std::vector<const Array*> objects;
    std::vector< std::vector<unsigned char> > values;
    bool hasSolution;

    setupIncrementalMode(query);

    // Find the object used in the expression, and compute an assignment
    // for them.
    findSymbolicObjects(query.expr, objects);
    if (!computeInitialValues(query.withFalse().negateExpr(), objects, values, hasSolution))
        return false;

    assert(hasSolution && "state has invalid constraint set");

    // Evaluate the expression with the computed assignment.
    Assignment a(objects, values);
    result = a.evaluate(query.expr);
    return true;
}

bool ExternalSolverImpl::computeInitialValues(const Query &query,
                                              const std::vector<const Array*> &objects,
                                              std::vector< std::vector<unsigned char> > &values,
                                              bool &hasSolution)
{
    setupIncrementalMode(query);
    return checkSat(query.withFalse().negateExpr(), hasSolution, &objects, &values);
}


}
