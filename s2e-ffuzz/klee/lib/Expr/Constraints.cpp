//===-- Constraints.cpp ---------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Constraints.h"

#include "klee/util/ExprPPrinter.h"
#include "klee/util/ExprVisitor.h"

#include <iostream>
#include <map>

namespace klee {

#if 0
class ExprReplaceVisitor : public ExprVisitor {
private:
    ref<Expr> src, dst;

public:
    ExprReplaceVisitor(ref<Expr> _src, ref<Expr> _dst) : src(_src), dst(_dst) {}

    Action visitExpr(const Expr &e) {
        if (e == *src.get()) {
            return Action::changeTo(dst);
        } else {
            return Action::doChildren();
        }
    }

    Action visitExprPost(const Expr &e) {
        if (e == *src.get()) {
            return Action::changeTo(dst);
        } else {
            return Action::doChildren();
        }
    }
};

class ExprReplaceVisitor2 : public ExprVisitor {
private:
    const ConstraintManager::constraints_ty &replacements;

public:
    ExprReplaceVisitor2(const ConstraintManager::constraints_ty &_replacements)
        : ExprVisitor(true),
          replacements(_replacements) {}

    Action visitExprPost(const Expr &e) {
        ConstraintManager::iterator it =
                replacements.find(ref<Expr>(const_cast<Expr*>(&e)));
        if (it!=replacements.end()) {
            return Action::changeTo(it->second);
        } else {
            return Action::doChildren();
        }
    }
};
#endif


void ConstraintManager::addConstraint(const ref<Expr> e) {
    switch (e->getKind()) {
    case Expr::Constant:
        assert(cast<ConstantExpr>(e)->isTrue()
               && "attempt to add invalid (false) constraint");
        break;
    case Expr::And: {
        BinaryExpr *be = cast<BinaryExpr>(e);
        addConstraint(be->getKid(0));
        addConstraint(be->getKid(1));
        break;
    }
    default:
        head_ = head_->getOrCreate(e);
    }
}


}
