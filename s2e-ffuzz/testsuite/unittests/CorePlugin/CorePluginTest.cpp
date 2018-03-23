extern "C" {
#include <cpu.h>
#include <helper.h>
#include <s2e/s2e_config.h>

int g_s2e_fast_concrete_invocation = 1;
CPUX86State *env;
s2e::S2EExecutionState *g_s2e_state;
}

#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/PluginManager.h>
#include <s2e/Plugins/CorePlugin.h>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

extern "C" {
void tb_flush(CPUX86State *env) {

}
}

/* Basic mocks for Executor class */
namespace klee {

/***/

ObjectHolder::ObjectHolder(const ObjectHolder &b) : os(b.os) {}
ObjectHolder::ObjectHolder(ObjectState *_os) : os(_os) {}
ObjectHolder::~ObjectHolder() {}

Executor::Executor(const InterpreterOptions &opts,
                   InterpreterHandler *ih, llvm::ExecutionEngine *engine) : Interpreter(opts) {}

Executor::~Executor() {}

const llvm::Module *
Executor::setModule(llvm::Module *module, const ModuleOptions &opts,
          bool createStatsTracker){ return NULL; }

void Executor::runFunctionAsMain(llvm::Function *f,
                               int argc,
                               char **argv,
                               char **envp){}

Executor::StatePair Executor::fork(ExecutionState &current,
                       ref<Expr> condition, bool isInternal,
                       bool deterministic){ return Executor::StatePair(); }

Executor::StatePair Executor::concolicFork(ExecutionState &current,
                       ref<Expr> condition, bool isInternal){ return Executor::StatePair(); }

void Executor::branch(ExecutionState &state,
            const std::vector< ref<Expr> > &conditions,
            std::vector<ExecutionState*> &result){}

void Executor::notifyBranch(ExecutionState &state){}

void Executor::notifyFork(ExecutionState &originalState, ref<Expr> &condition,
                Executor::StatePair &targets){}

bool Executor::merge(ExecutionState &base, ExecutionState &other) { return false; }
void Executor::terminateState(ExecutionState &state) {}
void Executor::terminateStateEarly(ExecutionState &state, const llvm::Twine &message) {}

void Executor::deleteState(ExecutionState *state){}

unsigned Executor::getPathStreamID(const ExecutionState &state){ return 0; }

unsigned Executor::getSymbolicPathStreamID(const ExecutionState &state){ return 0; }

void Executor::getConstraintLog(const ExecutionState &state,
                              std::string &res,
                              bool asCVC){}

bool Executor::getSymbolicSolution(const ExecutionState &state,
                                 std::vector<
                                 std::pair<std::string,
                                 std::vector<unsigned char> > >
                                 &res){ return false; }

void Executor::getCoveredLines(const ExecutionState &state,
                             std::map<const std::string*, std::set<unsigned> > &res){}

void Executor::copyOutConcretes(ExecutionState &state){}
bool Executor::copyInConcretes(ExecutionState &state){ return false; }

void Executor::updateStates(ExecutionState *current){}

void Executor::setupTimersHandler(){}

}

namespace s2e {

/* Basic mocks for S2E class */
llvm::raw_ostream& S2E::getStream(llvm::raw_ostream &stream,
                             const S2EExecutionState* state) const
{
    return llvm::nulls();
}

S2E::S2E() {
    S2EExecutor::InterpreterOptions opts;
    m_s2eExecutor = new S2EExecutor(this, NULL, opts, NULL);
}

S2E::~S2E() {
    delete m_s2eExecutor;
    m_s2eExecutor = NULL;
}



/* Basic mocks for S2EExecutor class */
S2EExecutor::S2EExecutor(S2E* s2e, TCGLLVMContext *tcgLVMContext,
            const InterpreterOptions &opts,
            klee::InterpreterHandler *ie):Executor(opts, NULL)
{

}

S2EExecutor::~S2EExecutor() {}
void S2EExecutor::terminateStateEarly(klee::ExecutionState &state, const llvm::Twine &message) {}
void S2EExecutor::terminateState(klee::ExecutionState &state) {}
void S2EExecutor::yieldState(klee::ExecutionState &state) {}
void S2EExecutor::registerSharedExternalObject(S2EExecutionState *state,
                                         void *address, unsigned size) {}
void S2EExecutor::updateStates(klee::ExecutionState *current){}
void S2EExecutor::branch(klee::ExecutionState &state,
          const std::vector< klee::ref<klee::Expr> > &conditions,
          std::vector<klee::ExecutionState*> &result){}

void S2EExecutor::notifyBranch(klee::ExecutionState &state){}
void S2EExecutor::notifyFork(klee::ExecutionState &originalState, klee::ref<klee::Expr> &condition,
                StatePair &targets){}
void S2EExecutor::setupTimersHandler(){}
void S2EExecutor::deleteState(klee::ExecutionState *state){};

klee::Executor::StatePair S2EExecutor::fork(klee::ExecutionState &current,
               klee::ref<klee::Expr> condition, bool isInternal,
               bool deterministic) { return klee::Executor::StatePair(); }

bool S2EExecutor::merge(klee::ExecutionState &base, klee::ExecutionState &other)
{
    return false;
}

/* Basic mocks for ConfigFile class */
ConfigFile::ConfigFile(const std::string &configFileName)
{

}

ConfigFile::~ConfigFile()
{

}

bool ConfigFile::getBool(const std::string& name, bool def, bool *ok)
{
    if (ok) {
        *ok = false;
    }

    return def;
}

std::string ConfigFile::getString(const std::string& name, const std::string& def, bool *ok)
{
    if (ok) {
        *ok = false;
    }
    return def;
}

ConfigFile::string_list ConfigFile::getStringList(
            const std::string& name, const string_list& def, bool *ok)
{
    if (ok) {
        *ok = false;
    }
    return def;
}

/*************************/

class S2EMock: public S2E
{
public:
    void initmock(ConfigFile *cfg) {
        m_configFile = cfg;
        m_pluginManager.initialize(this, m_configFile);
    }
};


} //namespace s2e

using namespace s2e;
using namespace testing;

class CorePluginTest : public Test, S2E {
protected:
    ConfigFile m_cfg;
    S2EMock *m_s2e;

public:
    CorePluginTest() : m_cfg("none") {}

    virtual void SetUp() {
        m_s2e = new S2EMock();
        m_s2e->initmock(&m_cfg);
    }

    virtual void TearDown() {
        delete m_s2e;
        m_s2e = NULL;
    }
};


TEST_F(CorePluginTest, Initialization) {
    CorePlugin *cp = m_s2e->getCorePlugin();
    ASSERT_EQ(g_s2e_on_tlb_miss_signals_count, cp->onTlbMiss.getActiveSignalsPtr());
}
