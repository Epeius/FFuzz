///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_RecipeDescriptor_H_
#define S2E_PLUGINS_RecipeDescriptor_H_

#include <s2e/cpu.h>

#include <llvm/Support/Path.h>
#include <vector>
#include <klee/util/ExprUtil.h>
#include <s2e/Plugins/CGC/POVGenerator.h>

namespace s2e {
namespace plugins {
namespace recipe {

typedef POVGenerator::PovOptions PovOptions;
typedef POVGenerator::PovType PovType;
typedef POVGenerator::VariableRemapping VariableRemapping;
typedef POVGenerator::ExprList ExprList;


struct Register
{
    enum Reg
    {
        REG_EAX = R_EAX,
        REG_ECX = R_ECX,
        REG_EDX = R_EDX,
        REG_EBX = R_EBX,
        REG_ESP = R_ESP,
        REG_EBP = R_EBP,
        REG_ESI = R_ESI,
        REG_EDI = R_EDI,
        REG_EIP = INT_MAX - 1,
        REG_INV = INT_MAX
    } reg;

    uint8_t byteIdx;

    Register() : reg(REG_INV), byteIdx(0) {}
    Register(Reg reg) : reg(reg), byteIdx(0) {}
    Register(Reg reg, uint8_t byteIdx) : reg(reg), byteIdx(byteIdx) {}

    std::string regName() const {
        switch(reg) {
            case REG_EAX: return "EAX";
            case REG_ECX: return "ECX";
            case REG_EDX: return "EDX";
            case REG_EBX: return "EBX";
            case REG_ESP: return "ESP";
            case REG_EBP: return "EBP";
            case REG_ESI: return "ESI";
            case REG_EDI: return "EDI";
            case REG_EIP: return "EIP";
            case REG_INV: return "INV";
        }
    }

    static Reg regFromStr(const std::string &s) {
        if (s == "EAX") { return REG_EAX; }
        else if (s == "ECX") { return REG_ECX; }
        else if (s == "EDX") { return REG_EDX; }
        else if (s == "EBX") { return REG_EBX; }
        else if (s == "ESP") { return REG_ESP; }
        else if (s == "EBP") { return REG_EBP; }
        else if (s == "ESI") { return REG_ESI; }
        else if (s == "EDI") { return REG_EDI; }
        else if (s == "EIP") { return REG_EIP; }
        else { return REG_INV; }
    }

    bool operator==(const Register &rhs) const {
        return reg == rhs.reg;
    }
};

typedef Register::Reg Reg;

typedef std::vector<Register> RegList;


/**
 * Left part of expression.
 */
struct Left
{
    enum Type
    {
        INV,         // invalid
        REGBYTE,     // register[offset] (EAX[0])
        ADDR,        // memory referenced by address
        REGPTR,      // memory referenced by register+offset
        REGPTR_EXEC, // register must point to executable memory
        REGPTR_PTR   // [register+offs1][offs2] ([ESP+4][0])
    } type;

    Register reg;
    uint64_t addr;
    off_t offset;
    off_t mem_offset;

    Left(): type(INV), reg(Reg::REG_EAX), addr(0), offset(0), mem_offset(0) {}
    Left(Reg reg, off_t offset, uint8_t byteIdx, Type type) :
        type(type), reg(reg, byteIdx), addr(0), offset(offset), mem_offset(0) {}

    Left(Reg reg, uint8_t byteIdx) : type(REGBYTE), reg(reg, byteIdx), addr(0), offset(0), mem_offset(0) {}
    Left(Reg reg, off_t offset) : type(REGPTR), reg(reg), addr(0), offset(offset), mem_offset(0) {}

    Left(uint64_t addr) : type(ADDR), reg(Reg::REG_EAX), addr(addr), offset(0), mem_offset(0) {}
    Left(const std::string reg, off_t offset, off_t mem_offset) :
        type(REGPTR_PTR), reg(Register::regFromStr(reg)), offset(offset), mem_offset(mem_offset) {}

    Left(const std::string reg, uint8_t byteIdx) : Left(Register::regFromStr(reg), byteIdx) {}
    Left(const std::string reg, off_t offset) : Left(Register::regFromStr(reg), offset) {}

    template<typename T> friend T& operator<<(T &stream, const Left &l) {
        switch(l.type) {
            case INV: stream << "INV"; break;
            case REGBYTE: stream << l.reg.regName() << "[" << hexval(l.reg.byteIdx) << "]"; break;
            case ADDR: stream << "[" << hexval(l.addr) << "]"; break;
            case REGPTR: stream << "[" << l.reg.regName() << "+" << hexval(l.offset) << "]"; break;
            case REGPTR_EXEC: stream << "*" << l.reg.regName() << " points to executable memory*"; break;
            case REGPTR_PTR: stream << "[" << l.reg.regName() << "+" << hexval(l.offset) << "]["
                                    << hexval(l.mem_offset) << "]"; break;
        }
        return stream;
    }


    std::string name() const {
        std::ostringstream ss;
        ss << *this;
        return ss.str();
    }
};

/**
 * Right part of expression.
 */
struct Right
{
    enum Type
    {
        INV, // invalid
        REGBYTE, // register[offset] (EAX[0])
        NEGOTIABLE, // can take arbitrary values
        CONCRETE // has concrete value
    } type = INV;

    std::string tag = "INVALID";
    Register reg = Reg::REG_INV;

    uint64_t value = 0;
    klee::Expr::Width valueWidth = klee::Expr::InvalidWidth;

    Right() {}
    Right(const std::string tag) : type(NEGOTIABLE), tag(tag) {}
    Right(uint64_t v, klee::Expr::Width w) : type(CONCRETE), value(v), valueWidth(w) {
        s2e_assert(NULL, v == klee::bits64::truncateToNBits(v, w), "Value " << hexval(v) << " does not fit " << w << " bits");
    }
    Right(Reg reg, uint8_t idx, Type type) : type(type), reg(reg, idx) {}

    Right(const std::string reg, uint8_t idx) : Right(Register::regFromStr(reg), idx, REGBYTE) {}

    template<typename T> friend T& operator<<(T &stream, const Right &r) {
        switch(r.type) {
            case INV: stream << "INV"; break;
            case REGBYTE: stream << r.reg.regName() << "[" << hexval(r.reg.byteIdx) << "]"; break;
            case NEGOTIABLE: stream << r.tag; break;
            case CONCRETE: stream << hexval(r.value); break;
        }
        return stream;
    }

    std::string name() const {
        std::ostringstream ss;
        ss << *this;
        return ss.str();
    }
};

/**
 * Precondtion is expressed as "left == right"
 */
struct Precondition
{
    Left left;
    Right right;

    Precondition() {}
    Precondition(const Left &l, const Right &r) : left(l), right(r) {}

    template<typename T> friend T& operator<<(T &stream, const Precondition &p) {
        stream << p.left;
        if (p.left.type != Left::REGPTR_EXEC) {
            stream << " == " << p.right;
        }
        return stream;
    }
};

typedef std::vector<Precondition> Preconditions;

struct RecipeSettings
{
    PovType type;
    Register gp;
    uint32_t regMask;
    uint32_t ipMask;
    uint32_t skip;
    std::string cbid;

    RecipeSettings(): type(PovType::POV_GENERAL), gp(), regMask(), ipMask(), skip(), cbid() {}
    RecipeSettings(PovType type, Register gp, uint32_t regMask, uint32_t ipMask, uint32_t skip, std::string cbid) :
        type(type), gp(gp), regMask(regMask), ipMask(ipMask), skip(skip), cbid(cbid) {}

    RecipeSettings(PovType type, const std::string gp) :
        RecipeSettings(type, Register::regFromStr(gp), 0xffffffff, 0xffffffff, 0, "") {}

    RecipeSettings(PovType type, const std::string gp, uint32_t regMask, uint32_t ipMask) :
        RecipeSettings(type, Register::regFromStr(gp), regMask, ipMask, 0, "") {}

};

class RecipeConditions
{
public:
    ExprList constraints;
    ExprList usedExprs;
    VariableRemapping remappings;
    RegList usedRegs;

    RecipeConditions& operator=(const RecipeConditions &other)
    {
        if(this == &other) {
            return *this;
        }

        this->constraints = other.constraints;
        this->usedExprs = other.usedExprs;
        this->remappings = other.remappings;
        this->usedRegs = other.usedRegs;

        return *this;
    }
};

enum EIPType {
    SYMBOLIC_EIP = 1u << 0,
    CONCRETE_EIP = 1u << 1,
};

struct StateConditions
{
    ModuleDescriptor module;
    klee::ref<klee::Expr> nextEip;
    EIPType eipType;
};

const std::string VARNAME_EIP = "$eip";
const std::string VARNAME_GP = "$gp";
const std::string VARNAME_ADDR = "$addr";
const std::string VARNAME_SIZE = "$size";

struct RecipeDescriptor {
    RecipeSettings settings;
    Preconditions preconditions;
    EIPType eipType;

    static RecipeDescriptor* fromFile(const std::string &recipeFile);
    static bool mustTryRecipe(const RecipeDescriptor& recipe, const std::string& recipeName,
                              const StateConditions& sc, uint64_t eip);
private:
    uint64_t concreteTargetEIP;
    bool parseSettingsLine(const std::string &line);
    bool parsePreconditionLine(const std::string &line);
    bool isValid() const;
};



}
}
}

#endif
