extern "C" {
#include <cpu.h>
#include <helper.h>
#include <s2e/s2e_config.h>

int g_s2e_fast_concrete_invocation = 1;
CPUX86State *env;
s2e::S2EExecutionState *g_s2e_state;
}

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/WindowsMonitor2.h>
#include <s2e/Plugins/Vmi.h>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

extern "C" {
void tb_flush(CPUX86State *env) {

}
}

namespace s2e {

/* Basic mocks for S2E class */
llvm::raw_ostream& S2E::getStream(llvm::raw_ostream &stream,
                             const S2EExecutionState* state) const
{
    return llvm::nulls();
}

Plugin* S2E::getPlugin(const std::string& name) const
{
    return NULL;
}

/* Basic mocks for S2EExecutionStateMemory class */
bool S2EExecutionStateMemory::readMemoryConcrete(uint64_t address, void *buf,
                                   uint64_t size, AddressType addressType)
{
    return false;
}

bool S2EExecutionStateMemory::readUnicodeString(uint64_t address, std::string &s, unsigned maxLen)
{
    return false;
}


/* Basic mocks for S2EExecutionState class */
unsigned S2EExecutionState::getPointerSize() const
{
    return 4;
}

/* Basic mocks for S2EExecutionStateRegisters class */
void S2EExecutionStateRegisters::read(unsigned offset, void *buffer, unsigned size) const
{

}

void S2EExecutionStateRegisters::write(unsigned offset, const void *buffer, unsigned size)
{

}

uint64_t S2EExecutionStateRegisters::getFlags()
{
    return 0;
}

uint64_t S2EExecutionStateRegisters::getPc() const
{
    return read<target_ulong>(CPU_OFFSET(eip));
}

void S2EExecutionStateRegisters::setPc(uint64_t pc)
{
    write<target_ulong>(CPU_OFFSET(eip), pc);
}

void S2EExecutionStateRegisters::setSp(uint64_t sp)
{
    write<target_ulong>(CPU_OFFSET(regs[R_ESP]), sp);
}

void S2EExecutionStateRegisters::setBp(uint64_t bp)
{
    write<target_ulong>(CPU_OFFSET(regs[R_EBP]), bp);
}

uint64_t S2EExecutionStateRegisters::getSp() const
{
    return read<target_ulong>(CPU_OFFSET(regs[R_ESP]));
}

uint64_t S2EExecutionStateRegisters::getBp() const
{
    return read<target_ulong>(CPU_OFFSET(regs[R_EBP]));
}

uint64_t S2EExecutionStateRegisters::getPageDir() const
{
    return read<target_ulong>(CPU_OFFSET(cr[3]));
}

/* Basic mocks for ConfigFile class */
bool ConfigFile::getBool(const std::string& name, bool def, bool *ok)
{
    *ok = false;
    return def;
}

std::string ConfigFile::getString(const std::string& name, const std::string& def, bool *ok)
{
    *ok = false;
    return def;
}


namespace plugins {

/* Basic mocks for Vmi class */
bool Vmi::readGuestVirtual(void *opaque, uint64_t address, void *dest, unsigned size)
{
    return false;
}

bool Vmi::findModule(const std::string &module, llvm::sys::Path &path)
{
    return false;
}

std::string Vmi::stripWindowsModulePath(const std::string &path)
{
    return path;
}

Vmi::PeData Vmi::getPeFromDisk(const ModuleDescriptor &module, bool caseInsensitive)
{
    return Vmi::PeData();
}

} //namespace plugins

} //namespace s2e

using namespace s2e;
using namespace testing;

class WindowsMonitor2Test : public Test {
protected:
    PluginsFactory *m_pluginsFactory;
    CorePlugin *m_corePlugin;

    virtual void SetUp() {
        m_pluginsFactory = new PluginsFactory();

        /*m_corePlugin = dynamic_cast<CorePlugin*>(
                m_pluginsFactory->createPlugin(this, "CorePlugin"));
        EXPECT_NE(NULL, m_corePlugin); */
    }

    virtual void TearDown() {

    }

};


TEST_F(WindowsMonitor2Test, Initialization) {

}
