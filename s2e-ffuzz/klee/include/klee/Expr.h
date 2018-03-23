//===-- Expr.h --------------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_EXPR_H
#define KLEE_EXPR_H

#include "klee/util/Bits.h"
#include "klee/util/Ref.h"

#include "llvm/ADT/APInt.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/raw_os_ostream.h"

#include <set>
#include <vector>
#include <tr1/unordered_set>
#include <sstream>
#include <iosfwd> // FIXME: Remove this!!!
#include <inttypes.h>


namespace llvm {
class Type;
}

namespace klee {

class Array;
class ConstantExpr;
class ObjectState;

template<class T> class ref;


/// Class representing symbolic expressions.
/**

<b>Expression canonicalization</b>: we define certain rules for
canonicalization rules for Exprs in order to simplify code that
pattern matches Exprs (since the number of forms are reduced), to open
up further chances for optimization, and to increase similarity for
caching and other purposes.

The general rules are:
<ol>
<li> No Expr has all constant arguments.</li>

<li> Booleans:
    <ol type="a">
     <li> \c Ne, \c Ugt, \c Uge, \c Sgt, \c Sge are not used </li>
     <li> The only acceptable operations with boolean arguments are
          \c Not \c And, \c Or, \c Xor, \c Eq,
      as well as \c SExt, \c ZExt,
          \c Select and \c NotOptimized. </li>
     <li> The only boolean operation which may involve a constant is boolean not (<tt>== false</tt>). </li>
     </ol>
</li>

<li> Linear Formulas:
   <ol type="a">
   <li> For any subtree representing a linear formula, a constant
   term must be on the LHS of the root node of the subtree.  In particular,
   in a BinaryExpr a constant must always be on the LHS.  For example, subtraction
   by a constant c is written as <tt>add(-c, ?)</tt>.  </li>
    </ol>
</li>


<li> Chains are unbalanced to the right </li>

</ol>


<b>Steps required for adding an expr</b>:
   -# Add case to printKind
   -# Add to ExprVisitor
   -# Add to IVC (implied value concretization) if possible

Todo: Shouldn't bool \c Xor just be written as not equal?

*/

template <typename T>
struct hash_ptr_t {
    unsigned operator()(const T *expr) const {
        return expr->hash();
    }
};

template <typename T>
struct equal_ptr_t {
    unsigned operator()(const T *a, const T *b) const {
        return *a == *b;
    }
};

class Expr {
public:
    static const unsigned MAGIC_HASH_CONSTANT = 39;

    /// The type of an expression is simply its width, in bits.
    typedef unsigned Width;

    static const Width InvalidWidth = 0;
    static const Width Bool = 1;
    static const Width Int8 = 8;
    static const Width Int16 = 16;
    static const Width Int32 = 32;
    static const Width Int64 = 64;
    static const Width Int128 = 128;

    enum Kind {
        InvalidKind = -1,

        // Primitive

        Constant = 0,

        // Special

        /// Prevents optimization below the given expression.  Used for
        /// testing: make equality constraints that KLEE will not use to
        /// optimize to concretes.
        NotOptimized,

        //// Skip old varexpr, just for deserialization, purge at some point
        Read=NotOptimized+2,
        Select,
        Concat,
        Extract,

        Not,

        // Casting,
        ZExt,
        SExt,

        // All subsequent kinds are binary.

        // Arithmetic
        Add,
        Sub,
        Mul,
        UDiv,
        SDiv,
        URem,
        SRem,

        // Bit
        And,
        Or,
        Xor,
        Shl,
        LShr,
        AShr,

        // Compare
        Eq,
        Ne,  ///< Not used in canonical form
        Ult,
        Ule,
        Ugt, ///< Not used in canonical form
        Uge, ///< Not used in canonical form
        Slt,
        Sle,
        Sgt, ///< Not used in canonical form
        Sge, ///< Not used in canonical form

        LastKind=Sge,

        CastKindFirst=ZExt,
        CastKindLast=SExt,
        BinaryKindFirst=Add,
        BinaryKindLast=Sge,
        CmpKindFirst=Eq,
        CmpKindLast=Sge
    };

    unsigned refCount;
    bool temporary;
    bool permanent;
    static uint64_t permanentCount;
protected:
    unsigned hashValue;

public:
    Expr() : refCount(0) {permanent = false;}
    virtual ~Expr() {}

    virtual Kind getKind() const = 0;
    virtual Width getWidth() const = 0;

    virtual unsigned getNumKids() const = 0;
    virtual ref<Expr> getKid(unsigned i) const = 0;

    virtual void print(llvm::raw_ostream &os) const;

    /// dump - Print the expression to stderr.
    void dump() const;

    /// Returns the pre-computed hash of the current expression
    virtual unsigned hash() const { return hashValue; }

    /// (Re)computes the hash of the current expression.
    /// Returns the hash value.
    virtual unsigned computeHash();

    /// Returns 0 iff b is structuraly equivalent to *this
    int compare(const Expr &b) const;
    virtual int compareContents(const Expr &b) const { return 0; }

    // Given an array of new kids return a copy of the expression
    // but using those children.
    virtual ref<Expr> rebuild(ref<Expr> kids[/* getNumKids() */]) const = 0;

    //

    /// isZero - Is this a constant zero.
    bool isZero() const;

    /// isTrue - Is this the true expression.
    bool isTrue() const;

    /// isFalse - Is this the false expression.
    bool isFalse() const;

    /// isIsZero - Is this expression Eq(0, e)
    bool isIsZeroOf(const ref<Expr> &e) const;

    bool isNegationOf(const ref<Expr> &e) const;


    /* Static utility methods */

    static void printKind(llvm::raw_ostream &os, Kind k);
    static void printWidth(llvm::raw_ostream &os, Expr::Width w);

    /// returns the smallest number of bytes in which the given width fits
    static inline unsigned getMinBytesForWidth(Width w) {
        return (w + 7) / 8;
    }

    /* Kind utilities */

    /* Utility creation functions */
    static ref<Expr> createCoerceToPointerType(const ref<Expr> &e);
    static ref<Expr> createImplies(const ref<Expr> &hyp, const ref<Expr> &conc);
    static ref<Expr> createIsZero(const ref<Expr> &e);

    /// Create a little endian read of the given type at offset 0 of the
    /// given object.
    static ref<Expr> createTempRead(const Array *array, Expr::Width w);

    static ref<ConstantExpr> createPointer(uint64_t v);

    struct CreateArg;
    static ref<Expr> createFromKind(Kind k, std::vector<CreateArg> args);

    static bool isValidKidWidth(unsigned kid, Width w) { return true; }
    static bool needsResultType() { return false; }

    static bool classof(const Expr *) { return true; }

#ifdef ENABLE_EXPRESSION_CACHING
    template<typename C, typename S>
    static ref<C> exprCachedAlloc(C &temp, S &cache) {
        //ConstantExpr ce(v);
        temp.computeHash();
        temp.temporary = true;

        typename S::iterator it = cache.find(&temp);
        C *ptr;
        if (it != cache.end()) {
            ptr = (*it);
            C::cacheHits++;
        } else {
            ptr = new C(temp);
            ptr->temporary = false;
            ptr->computeHash();
            cache.insert(ptr);
            C::cacheMisses++;
            C::count++;
        }

        ref<C> r(ptr);
        return r;
    }

    template<typename C, typename S>
    static void exprCacheClean(C *expr, S &cache) {
        if (!expr->temporary) {
            cache.erase(expr);
            --C::count;
        }
    }
#else
    template<typename C, typename S>
    static ref<C> exprCachedAlloc(C &temp, S &cache) {
        //ConstantExpr ce(v);
        temp.computeHash();
        temp.temporary = true;

        C *ptr;
        ptr = new C(temp);
        ptr->temporary = false;
        ptr->computeHash();

        ref<C> r(ptr);
        return r;
    }

    template<typename C, typename S>
    static void exprCacheClean(C *expr, S &cache) {

    }
#endif

};


struct Expr::CreateArg {
    ref<Expr> expr;
    Width width;

    CreateArg(Width w = Bool) : expr(0), width(w) {}
    CreateArg(const ref<Expr> &e) : expr(e), width(Expr::InvalidWidth) {}

    bool isExpr() { return !isWidth(); }
    bool isWidth() { return width != Expr::InvalidWidth; }
};

// Comparison operators

inline bool operator==(const Expr &lhs, const Expr &rhs) {
    return lhs.compare(rhs) == 0;
}

inline bool operator<(const Expr &lhs, const Expr &rhs) {
    return lhs.compare(rhs) < 0;
}

inline bool operator!=(const Expr &lhs, const Expr &rhs) {
    return !(lhs == rhs);
}

inline bool operator>(const Expr &lhs, const Expr &rhs) {
    return rhs < lhs;
}

inline bool operator<=(const Expr &lhs, const Expr &rhs) {
    return !(lhs > rhs);
}

inline bool operator>=(const Expr &lhs, const Expr &rhs) {
    return !(lhs < rhs);
}

// Printing operators

inline llvm::raw_ostream &operator<<(llvm::raw_ostream &os, const Expr &e) {
    e.print(os);
    return os;
}

inline llvm::raw_ostream &operator<<(llvm::raw_ostream &os, const Expr::Kind kind) {
    Expr::printKind(os, kind);
    return os;
}

inline std::ostream &operator<<(std::ostream &out, const Expr::Kind kind) {
    std::string ss;
    llvm::raw_string_ostream ros(ss);
    Expr::printKind(ros, kind);
    out << ros.str();
    return out;
}

inline std::ostream& operator<<(std::ostream& out, const klee::ref<klee::Expr> &expr)
{
    std::string ss;
    llvm::raw_string_ostream ros(ss);
    ros << expr;
    out << ros.str();
    return out;
}

inline llvm::raw_ostream& operator<<(llvm::raw_ostream& out, const klee::ref<klee::Expr> &expr)
{
    klee::Expr *e = expr.get();
    if (e) {
        e->print(out);
    } else {
        out << "NULL";
    }
    return out;
}

// Terminal Exprs

class ConstantExpr : public Expr {
public:

    static const Kind kind = Constant;
    static const unsigned numKids = 0;
    typedef std::tr1::unordered_set<ConstantExpr *,
    hash_ptr_t<ConstantExpr>, equal_ptr_t<ConstantExpr> > ExprCache;

    static uint64_t cacheHits;
    static uint64_t cacheMisses;
    static uint64_t count;

private:
    static  ExprCache s_cache;
    llvm::APInt value;
    static const unsigned CET_MAX_VALUE = 4096;
    static const unsigned CET_MAX_BITS = 65;

    class Table {
    public:
        Table() {
            for (uint64_t i = 1; i < CET_MAX_BITS; ++i) {
                uint64_t max = 1ll << (i - 1);
                if (max > CET_MAX_VALUE) {
                    max = CET_MAX_VALUE;
                }

                for (uint64_t j = 0; j < max; ++j) {
                    ref<ConstantExpr> r(new ConstantExpr(llvm::APInt(i,j)));
                    r->computeHash();
                    _const_table[i][j] = r;
                }
            }
        }

        ref<ConstantExpr>
        lookup(const llvm::APInt &v)
        {
            const unsigned width = v.getBitWidth();
            if (width && width < CET_MAX_BITS && !v.isNegative()) {
                const uint64_t value = v.getZExtValue();
                if (value < CET_MAX_VALUE) {
                    assert(!_const_table[width][value].isNull());
                    return _const_table[width][value];
                }
            }

            ref<ConstantExpr> r(new ConstantExpr(v));
            r->computeHash();
            return r;
        }
    private:
        ref<ConstantExpr> _const_table[CET_MAX_BITS][CET_MAX_VALUE];
    };

    ConstantExpr(const llvm::APInt &v) : Expr(), value(v) {}

public:
    /**
   * Custom allocation for constants.
   * There is a huge amount of churn going on with constants,
   * but the overall number of allocated constants is limited.
   */
    virtual ~ConstantExpr() {
        assert(!permanent);
        exprCacheClean<ConstantExpr, ExprCache>(this, s_cache);
    }

    Width getWidth() const { return value.getBitWidth(); }
    Kind getKind() const { return Constant; }

    unsigned getNumKids() const { return 0; }
    ref<Expr> getKid(unsigned i) const { return 0; }

    /// getAPValue - Return the arbitrary precision value directly.
    ///
    /// Clients should generally not use the APInt value directly and instead use
    /// native ConstantExpr APIs.
    const llvm::APInt &getAPValue() const { return value; }

    /// getZExtValue - Return the constant value for a limited number of bits.
    ///
    /// This routine should be used in situations where the width of the constant
    /// is known to be limited to a certain number of bits.
    uint64_t getZExtValue(unsigned bits = 64) const {
        assert(getWidth() <= bits && "Value may be out of range!");
        return value.getZExtValue();
    }

    /// getLimitedValue - If this value is smaller than the specified limit,
    /// return it, otherwise return the limit value.
    uint64_t getLimitedValue(uint64_t Limit = ~0ULL) const {
        return value.getLimitedValue(Limit);
    }

    /// toString - Return the constant value as a decimal string.
    void toString(std::string &Res, int Base=10) const;

    int compareContents(const Expr &b) const {
        const ConstantExpr &cb = static_cast<const ConstantExpr&>(b);
        if (getWidth() != cb.getWidth())
            return getWidth() < cb.getWidth() ? -1 : 1;
        if (value == cb.value)
            return 0;
        return value.ult(cb.value) ? -1 : 1;
    }

    virtual ref<Expr> rebuild(ref<Expr> kids[]) const {
        assert(0 && "rebuild() on ConstantExpr");
        return (Expr*) this;
    }

    virtual unsigned computeHash();

    static ref<Expr> fromMemory(void *address, Width w);
    void toMemory(void *address);

    static ref<ConstantExpr> alloc(const llvm::APInt &v) {
#if 0
        ConstantExpr ce(v);
        ref<ConstantExpr> ret = exprCachedAlloc<ConstantExpr, ExprCache>(ce, s_cache);
#ifdef ENABLE_EXPRESSION_CACHING
        if (!ret->permanent && ret->value.getBitWidth() <= 64 && ret->value.getZExtValue() < 1024) {
            ret->permanent = true;
            ++ret->permanentCount;
        }
#endif
        return ret;
#endif
        static Table table;
        return table.lookup(v);
    }

    static ref<ConstantExpr> alloc(uint64_t v, Width w) {
        return alloc(llvm::APInt(w, v));
    }

    static ref<ConstantExpr> create(uint64_t v, Width w) {
        assert(v == bits64::truncateToNBits(v, w) &&
               "invalid constant");
        return alloc(v, w);
    }

    static bool classof(const Expr *E) {
        return E->getKind() == Expr::Constant;
    }
    static bool classof(const ConstantExpr *) { return true; }

    /* Utility Functions */

    /// isZero - Is this a constant zero.
    bool isZero() const { return getZExtValue() == 0; }

    /// isOne - Is this a constant one.
    bool isOne() const { return getZExtValue() == 1; }

    /// isTrue - Is this the true expression.
    bool isTrue() const {
        return getZExtValue(1) == 1;
    }

    /// isFalse - Is this the false expression.
    bool isFalse() const {
        return getZExtValue(1) == 0;
    }

    /// isAllOnes - Is this constant all ones.
    bool isAllOnes() const {
        return getZExtValue(getWidth()) == bits64::maxValueOfNBits(getWidth());
    }

    /* Constant Operations */

    ref<ConstantExpr> Concat(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> Extract(unsigned offset, Width W);
    ref<ConstantExpr> ZExt(Width W);
    ref<ConstantExpr> SExt(Width W);
    ref<ConstantExpr> Add(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> Sub(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> Mul(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> UDiv(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> SDiv(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> URem(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> SRem(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> And(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> Or(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> Xor(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> Shl(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> LShr(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> AShr(const ref<ConstantExpr> &RHS);

    // Comparisons return a constant expression of width 1.

    ref<ConstantExpr> Eq(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> Ne(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> Ult(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> Ule(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> Ugt(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> Uge(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> Slt(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> Sle(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> Sgt(const ref<ConstantExpr> &RHS);
    ref<ConstantExpr> Sge(const ref<ConstantExpr> &RHS);

    ref<ConstantExpr> Neg();
    ref<ConstantExpr> Not();
};


// Utility classes

class NonConstantExpr : public Expr {
public:
    static bool classof(const Expr *E) {
        return E->getKind() != Expr::Constant;
    }
    static bool classof(const NonConstantExpr *) { return true; }
};

class BinaryExpr : public NonConstantExpr {
public:
    typedef std::pair<ref<Expr>, ref<Expr> > ExprPair;                  \

    struct hash_t {
        unsigned operator()(const ExprPair &v) const {
            return v.first->hash() + v.second->hash();
        }
    };

    struct equal_t {
        bool operator()(const ExprPair &a, const ExprPair &b) const {
            return a.first == b.first && a.second == b.second;
        }
    };


public:
    unsigned getNumKids() const { return 2; }
    ref<Expr> getKid(unsigned i) const {
        if(i == 0)
            return left;
        if(i == 1)
            return right;
        return 0;
    }

protected:
    BinaryExpr(const ref<Expr> &l, const ref<Expr> &r) : left(l), right(r) {}

protected:
    ref<Expr> left, right;

public:
    static bool classof(const Expr *E) {
        Kind k = E->getKind();
        return Expr::BinaryKindFirst <= k && k <= Expr::BinaryKindLast;
    }
    static bool classof(const BinaryExpr *) { return true; }

    ref<Expr> getLeft() const {
        return left;
    }

    ref<Expr> getRight() const {
        return right;
    }
};


class CmpExpr : public BinaryExpr {

protected:
    CmpExpr(const ref<Expr> &l, const ref<Expr> &r) : BinaryExpr(l,r) {}

public:
    Width getWidth() const { return Bool; }

    static bool classof(const Expr *E) {
        Kind k = E->getKind();
        return Expr::CmpKindFirst <= k && k <= Expr::CmpKindLast;
    }
    static bool classof(const CmpExpr *) { return true; }
};

// Special

class NotOptimizedExpr : public NonConstantExpr {
private:

    typedef std::tr1::unordered_set<NotOptimizedExpr *,
    hash_ptr_t<NotOptimizedExpr>, equal_ptr_t<NotOptimizedExpr> > ExprCache;
    static ExprCache s_cache;

    ref<Expr> src;

public:
    static const Kind kind = NotOptimized;
    static const unsigned numKids = 1;
    static uint64_t cacheMisses;
    static uint64_t cacheHits;
    static uint64_t count;

    virtual ~NotOptimizedExpr() {
        exprCacheClean<NotOptimizedExpr, ExprCache>(this, s_cache);
    }

    static ref<Expr> alloc(const ref<Expr> &src) {
        NotOptimizedExpr ce(src);
        return exprCachedAlloc<NotOptimizedExpr, ExprCache>(ce, s_cache);
    }

    static ref<Expr> create(const ref<Expr> &src);

    ref<Expr> getSrc() const {
        return src;
    }

    Width getWidth() const { return src->getWidth(); }
    Kind getKind() const { return NotOptimized; }

    unsigned getNumKids() const { return 1; }
    ref<Expr> getKid(unsigned i) const { return src; }

    virtual ref<Expr> rebuild(ref<Expr> kids[]) const { return create(kids[0]); }

private:
    NotOptimizedExpr(const ref<Expr> &_src) : src(_src) {}

public:
    static bool classof(const Expr *E) {
        return E->getKind() == Expr::NotOptimized;
    }
    static bool classof(const NotOptimizedExpr *) { return true; }
};


/// Class representing a byte update of an array.
class UpdateNode {
    friend class UpdateList;

    mutable unsigned refCount;
    // cache instead of recalc
    unsigned hashValue;

private:
    const UpdateNode *next;
    ref<Expr> index, value;

    /// size of this update sequence, including this update
    unsigned size;

public:
    UpdateNode(const UpdateNode *_next,
               const ref<Expr> &_index,
               const ref<Expr> &_value);

    unsigned getSize() const { return size; }

    int compare(const UpdateNode &b) const;
    unsigned hash() const { return hashValue; }

    ref<Expr> getIndex() const {
        return index;
    }

    ref<Expr> getValue() const {
        return value;
    }

    const UpdateNode *getNext() const {
        return next;
    }

private:
    UpdateNode() : refCount(0) {}
    ~UpdateNode();

    unsigned computeHash();
};

class Array {
private:
    const std::string rawName; /* The user name, before it was stripped and made unique */
    const std::string name;
    // FIXME: Not 64-bit clean.
    unsigned size;

    /// constantValues - The constant initial values for this array, or empty for
    /// a symbolic array. If non-empty, this size of this array is equivalent to
    /// the array size.
    const std::vector< ref<ConstantExpr> > constantValues;

public:
    // FIXME: This does not belong here.
    mutable void *stpInitialArray;
    static uint64_t aggregatedSize;

public:
    /// Array - Construct a new array object.
    ///
    /// \param _name - The name for this array. Names should generally be unique
    /// across an application, but this is not necessary for correctness, except
    /// when printing expressions. When expressions are printed the output will
    /// not parse correctly since two arrays with the same name cannot be
    /// distinguished once printed.
    Array(const std::string &_name, uint64_t _size,
          const ref<ConstantExpr> *constantValuesBegin = 0,
          const ref<ConstantExpr> *constantValuesEnd = 0,
          const std::string _rawName = "")
        : rawName(_rawName), name(_name), size(_size),
          constantValues(constantValuesBegin, constantValuesEnd),
          stpInitialArray(0) {
        aggregatedSize += _size;
        assert((isSymbolicArray() || constantValues.size() == size) &&
               "Invalid size for constant array!");
#ifdef NDEBUG
        for (const ref<ConstantExpr> *it = constantValuesBegin;
             it != constantValuesEnd; ++it)
            assert(it->getWidth() == getRange() &&
                   "Invalid initial constant value!");
#endif
    }
    ~Array();

    bool isSymbolicArray() const { return constantValues.empty(); }
    bool isConstantArray() const { return !isSymbolicArray(); }

    Expr::Width getDomain() const { return Expr::Int32; }
    Expr::Width getRange() const { return Expr::Int8; }

    const std::string &getName() const {
        return name;
    }

    const std::string &getRawName() const {
        return rawName;
    }

    unsigned getSize() const {
        return size;
    }

    const std::vector<ref<ConstantExpr>> &getConstantValues() const {
        return constantValues;
    }
};

/// Class representing a complete list of updates into an array.
class UpdateList {
    friend class ReadExpr; // for default constructor
    static uint64_t count;
private:
    const Array *root;

    /// pointer to the most recent update node
    const UpdateNode *head;

public:
    UpdateList(const Array *_root, const UpdateNode *_head);
    UpdateList(const UpdateList &b);
    ~UpdateList();

    UpdateList &operator=(const UpdateList &b);

    /// size of this update list
    unsigned getSize() const { return (head ? head->getSize() : 0); }

    void extend(const ref<Expr> &index, const ref<Expr> &value);

    int compare(const UpdateList &b) const;
    unsigned hash() const;

    const Array *getRoot() const {
        return root;
    }

    const UpdateNode *getHead() const {
        return head;
    }
};

/// Class representing a one byte read from an array.
class ReadExpr : public NonConstantExpr {
public:
    static const Kind kind = Read;
    static const unsigned numKids = 1;
    static uint64_t cacheMisses;
    static uint64_t cacheHits;
    static uint64_t count;


private:
    typedef std::tr1::unordered_set<ReadExpr*,
    hash_ptr_t<ReadExpr>, equal_ptr_t<ReadExpr> > ExprCache;
    static ExprCache s_cache;

    UpdateList updates;
    ref<Expr> index;

public:
    virtual ~ReadExpr() {
        exprCacheClean<ReadExpr, ExprCache>(this, s_cache);
    }

    static ref<Expr> alloc(const UpdateList &updates, const ref<Expr> &index) {
        ReadExpr temp(updates, index);
        return exprCachedAlloc<ReadExpr, ExprCache>(temp, s_cache);
    }

    static ref<Expr> create(const UpdateList &updates, ref<Expr> i);

    Width getWidth() const { return Expr::Int8; }
    Kind getKind() const { return Read; }

    unsigned getNumKids() const { return numKids; }
    ref<Expr> getKid(unsigned i) const { return !i ? index : 0; }

    int compareContents(const Expr &b) const;

    ref<Expr> getIndex() const {
        return index;
    }

    const UpdateList &getUpdates() const {
        return updates;
    }

    virtual ref<Expr> rebuild(ref<Expr> kids[]) const {
        return create(updates, kids[0]);
    }

    virtual unsigned computeHash();

private:
    ReadExpr(const UpdateList &_updates, const ref<Expr> &_index) :
        updates(_updates), index(_index) {}

public:
    static bool classof(const Expr *E) {
        return E->getKind() == Expr::Read;
    }
    static bool classof(const ReadExpr *) { return true; }
};


/// Class representing an if-then-else expression.
class SelectExpr : public NonConstantExpr {
public:
    static const Kind kind = Select;
    static const unsigned numKids = 3;
    static uint64_t cacheMisses;
    static uint64_t cacheHits;
    static uint64_t count;

private:
    ref<Expr> cond, trueExpr, falseExpr;

private:
    typedef std::tr1::unordered_set<SelectExpr*,
    hash_ptr_t<SelectExpr>, equal_ptr_t<SelectExpr> > ExprCache;
    static ExprCache s_cache;

public:
    virtual ~SelectExpr() {
        exprCacheClean<SelectExpr, ExprCache>(this, s_cache);
    }

    static ref<Expr> alloc(const ref<Expr> &c, const ref<Expr> &t,
                           const ref<Expr> &f) {
        SelectExpr temp(c, t, f);
        return exprCachedAlloc<SelectExpr, ExprCache>(temp, s_cache);
    }

    static ref<Expr> create(const ref<Expr> &c, const ref<Expr> &t, const ref<Expr> &f);

    Width getWidth() const { return trueExpr->getWidth(); }
    Kind getKind() const { return Select; }

    ref<Expr> getCondition() const {
        return cond;
    }

    ref<Expr> getTrue() const {
        return trueExpr;
    }

    ref<Expr> getFalse() const {
        return falseExpr;
    }

    unsigned getNumKids() const { return numKids; }
    ref<Expr> getKid(unsigned i) const {
        switch(i) {
        case 0: return cond;
        case 1: return trueExpr;
        case 2: return falseExpr;
        default: return 0;
        }
    }

    static bool isValidKidWidth(unsigned kid, Width w) {
        if (kid == 0)
            return w == Bool;
        else
            return true;
    }

    virtual ref<Expr> rebuild(ref<Expr> kids[]) const {
        return create(kids[0], kids[1], kids[2]);
    }

    bool isConstantCases() const {
        bool res = true;
        if (SelectExpr* te = dyn_cast<SelectExpr>(trueExpr))
            res &= te->isConstantCases();
        else
            res &= isa<ConstantExpr>(trueExpr);
        if (SelectExpr* fe = dyn_cast<SelectExpr>(falseExpr))
            res &= fe->isConstantCases();
        else
            res &= isa<ConstantExpr>(falseExpr);
        return res;
    }

    bool hasConstantCases() const {
        if (isa<ConstantExpr>(trueExpr) || isa<ConstantExpr>(falseExpr))
            return true;
        if (SelectExpr* te = dyn_cast<SelectExpr>(trueExpr))
            if (te->hasConstantCases())
                return true;
        if (SelectExpr* fe = dyn_cast<SelectExpr>(falseExpr))
            if (fe->hasConstantCases())
                return true;
        return false;
    }


private:
    SelectExpr(const ref<Expr> &c, const ref<Expr> &t, const ref<Expr> &f)
        : cond(c), trueExpr(t), falseExpr(f) {}

public:
    static bool classof(const Expr *E) {
        return E->getKind() == Expr::Select;
    }
    static bool classof(const SelectExpr *) { return true; }
};


/** Children of a concat expression can have arbitrary widths.
    Kid 0 is the left kid, kid 1 is the right kid.
*/
class ConcatExpr : public NonConstantExpr {
public:
    static const Kind kind = Concat;
    static const unsigned numKids = 2;
    static uint64_t cacheMisses;
    static uint64_t cacheHits;
    static uint64_t count;


    typedef std::tr1::unordered_set<ConcatExpr*,
    hash_ptr_t<ConcatExpr>, equal_ptr_t<ConcatExpr> > ExprCache;
    static ExprCache s_cache;
private:
    Width width;
    ref<Expr> left, right;

public:
    virtual ~ConcatExpr() {
        exprCacheClean<ConcatExpr, ExprCache>(this, s_cache);
    }

    static ref<Expr> alloc(const ref<Expr> &l, const ref<Expr> &r) {
        ConcatExpr ce(l, r);
        return exprCachedAlloc<ConcatExpr, ExprCache>(ce, s_cache);
    }

    static ref<Expr> create(const ref<Expr> &l, const ref<Expr> &r);

    Width getWidth() const { return width; }
    Kind getKind() const { return kind; }
    ref<Expr> getLeft() const { return left; }
    ref<Expr> getRight() const { return right; }

    unsigned getNumKids() const { return numKids; }
    ref<Expr> getKid(unsigned i) const {
        if (i == 0) return left;
        else if (i == 1) return right;
        else return NULL;
    }

    /// Shortcuts to create larger concats.  The chain returned is unbalanced to the right
    static ref<Expr> createN(unsigned nKids, const ref<Expr> kids[]);
    static ref<Expr> create4(const ref<Expr> &kid1, const ref<Expr> &kid2,
                             const ref<Expr> &kid3, const ref<Expr> &kid4);
    static ref<Expr> create8(const ref<Expr> &kid1, const ref<Expr> &kid2,
                             const ref<Expr> &kid3, const ref<Expr> &kid4,
                             const ref<Expr> &kid5, const ref<Expr> &kid6,
                             const ref<Expr> &kid7, const ref<Expr> &kid8);

    virtual ref<Expr> rebuild(ref<Expr> kids[]) const { return create(kids[0], kids[1]); }

private:
    ConcatExpr(const ref<Expr> &l, const ref<Expr> &r) : left(l), right(r) {
        width = l->getWidth() + r->getWidth();
    }

public:
    static bool classof(const Expr *E) {
        return E->getKind() == Expr::Concat;
    }
    static bool classof(const ConcatExpr *) { return true; }
};


/** This class represents an extract from expression {\tt expr}, at
    bit offset {\tt offset} of width {\tt width}.  Bit 0 is the right most
    bit of the expression.
 */
class ExtractExpr : public NonConstantExpr {
public:
    static const Kind kind = Extract;
    static const unsigned numKids = 1;

    static uint64_t cacheMisses;
    static uint64_t cacheHits;
    static uint64_t count;

private:
    typedef std::tr1::unordered_set<ExtractExpr*,
    hash_ptr_t<ExtractExpr>, equal_ptr_t<ExtractExpr> > ExprCache;
    static ExprCache s_cache;

    ref<Expr> expr;
    unsigned offset;
    Width width;

public:
    virtual ~ExtractExpr() {
        exprCacheClean<ExtractExpr, ExprCache>(this, s_cache);
    }

    static ref<Expr> alloc(const ref<Expr> &e, unsigned o, Width w) {
        ExtractExpr temp(e, o, w);
        return exprCachedAlloc(temp, s_cache);
    }

    /// Creates an ExtractExpr with the given bit offset and width
    static ref<Expr> create(const ref<Expr> &e, unsigned bitOff, Width w);

    Width getWidth() const { return width; }
    Kind getKind() const { return Extract; }

    unsigned getOffset() const {
        return offset;
    }

    ref<Expr> getExpr() const {
        return expr;
    }

    unsigned getNumKids() const { return numKids; }
    ref<Expr> getKid(unsigned i) const { return expr; }

    int compareContents(const Expr &b) const {
        const ExtractExpr &eb = static_cast<const ExtractExpr&>(b);
        if (offset != eb.offset) return offset < eb.offset ? -1 : 1;
        if (width != eb.width) return width < eb.width ? -1 : 1;
        return 0;
    }

    virtual ref<Expr> rebuild(ref<Expr> kids[]) const {
        return create(kids[0], offset, width);
    }

    virtual unsigned computeHash();

private:
    ExtractExpr(const ref<Expr> &e, unsigned b, Width w)
        : expr(e),offset(b),width(w) {}

public:
    static bool classof(const Expr *E) {
        return E->getKind() == Expr::Extract;
    }
    static bool classof(const ExtractExpr *) { return true; }
};


/**
    Bitwise Not
*/
class NotExpr : public NonConstantExpr {
public:
    static const Kind kind = Not;
    static const unsigned numKids = 1;


    static uint64_t cacheMisses;
    static uint64_t cacheHits;
    static uint64_t count;

private:
    typedef std::tr1::unordered_set<NotExpr*,
    hash_ptr_t<NotExpr>, equal_ptr_t<NotExpr> > ExprCache;
    static ExprCache s_cache;

    ref<Expr> expr;
public:
    virtual ~NotExpr() {
        exprCacheClean<NotExpr, ExprCache>(this, s_cache);
    }

    static ref<Expr> alloc(const ref<Expr> &e) {
        NotExpr temp(e);
        return exprCachedAlloc(temp, s_cache);
    }

    static ref<Expr> create(const ref<Expr> &e);

    ref<Expr> getExpr() const {
        return expr;
    }

    Width getWidth() const { return expr->getWidth(); }
    Kind getKind() const { return Not; }

    unsigned getNumKids() const { return numKids; }
    ref<Expr> getKid(unsigned i) const { return expr; }

    int compareContents(const Expr &b) const {
        const NotExpr &eb = static_cast<const NotExpr&>(b);
        if (expr != eb.expr) return expr < eb.expr ? -1 : 1;
        return 0;
    }

    virtual ref<Expr> rebuild(ref<Expr> kids[]) const {
        return create(kids[0]);
    }

    virtual unsigned computeHash();

public:
    static bool classof(const Expr *E) {
        return E->getKind() == Expr::Not;
    }
    static bool classof(const NotExpr *) { return true; }

private:
    NotExpr(const ref<Expr> &e) : expr(e) {}
};



// Casting

class CastExpr : public NonConstantExpr {
private:
    ref<Expr> src;
    Width width;

public:
    CastExpr(const ref<Expr> &e, Width w) : src(e), width(w) {}

    Width getWidth() const { return width; }

    unsigned getNumKids() const { return 1; }
    ref<Expr> getKid(unsigned i) const { return (i==0) ? src : 0; }

    static bool needsResultType() { return true; }

    ref<Expr> getSrc() const {
        return src;
    }

    int compareContents(const Expr &b) const {
        const CastExpr &eb = static_cast<const CastExpr&>(b);
        if (width != eb.width) return width < eb.width ? -1 : 1;
        return 0;
    }

    virtual unsigned computeHash();

    static bool classof(const Expr *E) {
        Expr::Kind k = E->getKind();
        return Expr::CastKindFirst <= k && k <= Expr::CastKindLast;
    }
    static bool classof(const CastExpr *) { return true; }
};

#define CAST_EXPR_CLASS(_class_kind)                             \
    class _class_kind ## Expr : public CastExpr {                    \
        public:                                                          \
        static const Kind kind = _class_kind;                          \
        static const unsigned numKids = 1;                             \
        static uint64_t cacheMisses;                                   \
        static uint64_t cacheHits;                                     \
        static uint64_t count;                                         \
        private:                                                         \
        typedef std::tr1::unordered_set<_class_kind ## Expr*,          \
        hash_ptr_t<_class_kind ## Expr>, equal_ptr_t<_class_kind ## Expr> > ExprCache; \
        static ExprCache s_cache;                                      \
        public:                                                          \
        virtual ~_class_kind ## Expr() {                             \
            exprCacheClean<_class_kind ## Expr, ExprCache>(this, s_cache); \
        }                                                            \
        _class_kind ## Expr(const ref<Expr> &e, Width w) : CastExpr(e,w) {} \
        static ref<Expr> alloc(const ref<Expr> &e, Width w) {        \
        _class_kind ## Expr temp(e, w);                            \
            return exprCachedAlloc(temp, s_cache);                     \
        }                                                            \
        static ref<Expr> create(const ref<Expr> &e, Width w);        \
        Kind getKind() const { return _class_kind; }                 \
        virtual ref<Expr> rebuild(ref<Expr> kids[]) const {          \
            return create(kids[0], getWidth());                             \
        }                                                            \
        \
        static bool classof(const Expr *E) {                         \
            return E->getKind() == Expr::_class_kind;                  \
        }                                                            \
        static bool classof(const  _class_kind ## Expr *) {          \
            return true;                                               \
        }                                                            \
    };                                                               \

CAST_EXPR_CLASS(SExt)
CAST_EXPR_CLASS(ZExt)

// Arithmetic/Bit Exprs

#define ARITHMETIC_EXPR_CLASS(_class_kind)                           \
    class _class_kind ## Expr : public BinaryExpr {                      \
        private:                                                             \
            typedef std::tr1::unordered_set<_class_kind ## Expr*,              \
            hash_ptr_t<_class_kind ## Expr>, equal_ptr_t<_class_kind ## Expr> > ExprCache; \
            static ExprCache s_cache;                                          \
        public:                                                              \
            static const Kind kind = _class_kind;                              \
            static const unsigned numKids = 2;                                 \
            static uint64_t cacheMisses;                                       \
            static uint64_t cacheHits;                                         \
            static uint64_t count;                                             \
        public:                                                              \
            virtual ~_class_kind ## Expr() {                                 \
                exprCacheClean<_class_kind ## Expr, ExprCache>(this, s_cache); \
            }                                                                \
            _class_kind ## Expr(const ref<Expr> &l,                          \
                const ref<Expr> &r) : BinaryExpr(l,r) {}     \
            static ref<Expr> alloc(const ref<Expr> &l, const ref<Expr> &r) { \
                _class_kind ## Expr temp(l, r);                              \
                return exprCachedAlloc(temp, s_cache);                       \
            }                                                                \
            static ref<Expr> create(const ref<Expr> &l, const ref<Expr> &r); \
            Width getWidth() const { return left->getWidth(); }              \
            Kind getKind() const { return _class_kind; }                     \
            virtual ref<Expr> rebuild(ref<Expr> kids[]) const {              \
                return create(kids[0], kids[1]);                               \
            }                                                                \
            \
            static bool classof(const Expr *E) {                             \
                return E->getKind() == Expr::_class_kind;                      \
            }                                                                \
            static bool classof(const  _class_kind ## Expr *) {              \
                return true;                                                   \
            }                                                                \
    };                                                                   \

ARITHMETIC_EXPR_CLASS(Add)
ARITHMETIC_EXPR_CLASS(Sub)
ARITHMETIC_EXPR_CLASS(Mul)
ARITHMETIC_EXPR_CLASS(UDiv)
ARITHMETIC_EXPR_CLASS(SDiv)
ARITHMETIC_EXPR_CLASS(URem)
ARITHMETIC_EXPR_CLASS(SRem)
ARITHMETIC_EXPR_CLASS(And)
ARITHMETIC_EXPR_CLASS(Or)
ARITHMETIC_EXPR_CLASS(Xor)
ARITHMETIC_EXPR_CLASS(Shl)
ARITHMETIC_EXPR_CLASS(LShr)
ARITHMETIC_EXPR_CLASS(AShr)

// Comparison Exprs

#define COMPARISON_EXPR_CLASS(_class_kind)                           \
    class _class_kind ## Expr : public CmpExpr {                         \
    private:                                                             \
    typedef std::tr1::unordered_set<_class_kind ## Expr*,              \
    hash_ptr_t<_class_kind ## Expr>, equal_ptr_t<_class_kind ## Expr> > ExprCache; \
    static ExprCache s_cache;                                          \
    public:                                                              \
    static const Kind kind = _class_kind;                              \
    static const unsigned numKids = 2;                                 \
    static uint64_t cacheMisses;                                       \
    static uint64_t cacheHits;                                         \
    static uint64_t count;                                             \
    public:                                                              \
    virtual ~_class_kind ## Expr() {                                 \
    exprCacheClean<_class_kind ## Expr, ExprCache>(this, s_cache); \
}                                                                \
    _class_kind ## Expr(const ref<Expr> &l,                          \
    const ref<Expr> &r) : CmpExpr(l,r) {}        \
    static ref<Expr> alloc(const ref<Expr> &l, const ref<Expr> &r) { \
    _class_kind ## Expr temp(l, r);                              \
    return exprCachedAlloc(temp, s_cache);                       \
}                                                                \
    static ref<Expr> create(const ref<Expr> &l, const ref<Expr> &r); \
    Kind getKind() const { return _class_kind; }                     \
    virtual ref<Expr> rebuild(ref<Expr> kids[]) const {              \
    return create(kids[0], kids[1]);                               \
}                                                                \
    \
    static bool classof(const Expr *E) {                             \
    return E->getKind() == Expr::_class_kind;                      \
}                                                                \
    static bool classof(const  _class_kind ## Expr *) {              \
    return true;                                                   \
}                                                                \
};                                                                   \

COMPARISON_EXPR_CLASS(Eq)
COMPARISON_EXPR_CLASS(Ne)
COMPARISON_EXPR_CLASS(Ult)
COMPARISON_EXPR_CLASS(Ule)
COMPARISON_EXPR_CLASS(Ugt)
COMPARISON_EXPR_CLASS(Uge)
COMPARISON_EXPR_CLASS(Slt)
COMPARISON_EXPR_CLASS(Sle)
COMPARISON_EXPR_CLASS(Sgt)
COMPARISON_EXPR_CLASS(Sge)

// Implementations

inline bool Expr::isZero() const {
    if (const ConstantExpr *CE = dyn_cast<ConstantExpr>(this))
        return CE->isZero();
    return false;
}

inline bool Expr::isTrue() const {
    assert(getWidth() == Expr::Bool && "Invalid isTrue() call!");
    if (const ConstantExpr *CE = dyn_cast<ConstantExpr>(this))
        return CE->isTrue();
    return false;
}

inline bool Expr::isFalse() const {
    assert(getWidth() == Expr::Bool && "Invalid isFalse() call!");
    if (const ConstantExpr *CE = dyn_cast<ConstantExpr>(this))
        return CE->isFalse();
    return false;
}

} // End klee namespace

#endif
