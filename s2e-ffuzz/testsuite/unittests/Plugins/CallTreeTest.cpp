#include <iostream>
#include <s2e/Plugin.h>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <klee/Expr.h>

#include <s2e/Plugins/CallTree.h>
#include <llvm/Support/raw_ostream.h>

using namespace testing;
using namespace s2e::plugins::calltree;

static void InitCallStack(CallStack &cs, const std::string &module)
{
    CallStackEntry ce;
    ce.Module = module;
    ce.FunctionAddress = 0x1000;
    ce.ReturnAddress = 0xfd022345;
    cs.push_back(ce);

    ce.Module = module;
    ce.FunctionAddress = 0x1200;
    ce.ReturnAddress = 0x1003;
    cs.push_back(ce);
}

TEST(CallTreeTest, AddRemoveSingle) {
    CallTree<uint64_t> ct;
    CallStack cs;
    InitCallStack(cs, "driver.sys");


    EXPECT_TRUE(ct.add(123, cs, Location("driver.sys", 0x1234)));


    CallTreeDotPrinter<uint64_t>(llvm::outs()).visit(ct);

    ct.remove(123);
    EXPECT_EQ((unsigned) 0, ct.size());

    CallTreeDotPrinter<uint64_t>(llvm::outs()).visit(ct);

}

TEST(CallTreeTest, AddTwiceTheSameThing) {
    CallTree<uint64_t> ct;
    CallStack cs;
    InitCallStack(cs, "driver.sys");

    EXPECT_TRUE(ct.add(123, cs, Location("driver.sys", 0x1234)));
    EXPECT_FALSE(ct.add(123, cs, Location("driver.sys", 0x1234)));
    EXPECT_EQ((unsigned) 1, ct.size());
}

TEST(CallTreeTest, AddMultiple) {
    CallTree<uint64_t> ct;
    CallStack cs;
    InitCallStack(cs, "driver.sys");

    EXPECT_TRUE(ct.add(123, cs, Location("driver.sys", 0x1234)));
    EXPECT_TRUE(ct.add(124, cs, Location("driver.sys", 0x1234)));
    EXPECT_TRUE(ct.add(125, cs, Location("driver.sys", 0x1254)));
    EXPECT_TRUE(ct.add(126, cs, Location("driver.sys", 0x1264)));
    EXPECT_TRUE(ct.add(127, cs, Location("driver.sys", 0x1274)));

    EXPECT_EQ((unsigned) 5, ct.size());
    CallTreeDotPrinter<uint64_t>(llvm::outs()).visit(ct);
}

TEST(CallTreeTest, AddMultipleItemsToMultipleNodes) {
    CallTree<uint64_t> ct;
    CallStack cs;
    InitCallStack(cs, "driver.sys");

    EXPECT_TRUE(ct.add(123, cs, Location("driver.sys", 0x1234)));
    EXPECT_TRUE(ct.add(124, cs, Location("driver.sys", 0x1234)));

    CallStackEntry ce;
    ce.Module = "driver.sys";
    ce.FunctionAddress = 0x1400;
    ce.ReturnAddress = 0x1205;
    cs.push_back(ce);

    EXPECT_TRUE(ct.add(125, cs, Location("driver.sys", 0x1254)));
    EXPECT_TRUE(ct.add(126, cs, Location("driver.sys", 0x1264)));
    EXPECT_TRUE(ct.add(127, cs, Location("driver.sys", 0x1274)));

    cs.clear();
    InitCallStack(cs, "program.exe");
    EXPECT_TRUE(ct.add(128, cs, Location("driver.sys", 0x1254)));
    EXPECT_TRUE(ct.add(129, cs, Location("driver.sys", 0x1264)));
    EXPECT_TRUE(ct.add(130, cs, Location("driver.sys", 0x1274)));

    EXPECT_EQ((unsigned) 8, ct.size());
    CallTreeDotPrinter<uint64_t>(llvm::outs()).visit(ct);
    CallTreeTextPrinter<uint64_t>(llvm::outs()).visit(ct);

    for (unsigned i = 123; i < 131; ++i) {
        ct.remove(i);
    }

    CallTreeDotPrinter<uint64_t>(llvm::outs()).visit(ct);
}

TEST(CallTreeTest, TestSelection) {
    CallTree<uint64_t> ct;
    CallStack cs;
    InitCallStack(cs, "driver.sys");

    EXPECT_TRUE(ct.add(123, cs, Location("driver.sys", 0x1234)));

    EXPECT_TRUE(ct.select(123));
    EXPECT_EQ((unsigned) 1, ct.getRoot()->getSelectionCount());
    CallTreeDotPrinter<uint64_t>(llvm::outs()).visit(ct);
}

TEST(CallTreeTest, TestRandomPathSingleState) {
    CallTree<uint64_t> ct;
    CallStack cs;
    InitCallStack(cs, "driver.sys");

    EXPECT_TRUE(ct.add(123, cs, Location("driver.sys", 0x1234)));

    CallTreeRandomPath<uint64_t> rp;
    CallTreeRandomPath<uint64_t>::ThingsT selected;
    rp.visit(ct);
    selected = rp.getSelectedThings();
    EXPECT_EQ((unsigned) 1, selected.size());
}

TEST(CallTreeTest, TestRandomPathEmpty) {
    CallTree<uint64_t> ct;

    CallTreeRandomPath<uint64_t> rp;
    CallTreeRandomPath<uint64_t>::ThingsT selected;
    rp.visit(ct);
    selected = rp.getSelectedThings();
    EXPECT_EQ((unsigned) 0, selected.size());
}


TEST(CallTreeTest, TestRandomPathCallTree) {
    CallTree<uint64_t> ct;
    CallStack cs;
    InitCallStack(cs, "driver.sys");

    EXPECT_TRUE(ct.add(123, cs, Location("driver.sys", 0x1234)));
    cs.pop_back();
    EXPECT_TRUE(ct.add(128, cs, Location("driver.sys", 0x1134)));

    for (int i = 0; i < 10; ++i) {
        CallTreeRandomPath<uint64_t> rp;
        CallTreeRandomPath<uint64_t>::ThingsT selected;
        rp.visit(ct);
        selected = rp.getSelectedThings();
        EXPECT_EQ((unsigned) 1, selected.size());
        llvm::outs() << "Selected: " << *(selected.begin()) << "\n";
    }
}
