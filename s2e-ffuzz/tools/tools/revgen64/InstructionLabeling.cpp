/*
 * Copyright (c) 2014, CodeTickler
 * All rights reserved.
 *
 * Proprietary and confidential
 */

#include <llvm/ADT/SmallVector.h>

#include <lib/Utils/Utils.h>
#include <Translator/Translator.h>

#include "InstructionLabeling.h"

using namespace llvm;

namespace s2etools {

LogKey InstructionLabeling::TAG = LogKey("InstructionLabeling");
char InstructionLabeling::PID;


bool InstructionLabeling::runOnFunction(llvm::Function &F)
{    
    foreach2(bbit, F.begin(), F.end()) {
        BasicBlock &bb = *bbit;
        bb.setName("");

        foreach2(iit, bb.begin(), bb.end()) {
            Instruction *instr = &*iit;
            instr->setName("");

            LoadInst *li = dynamic_cast<LoadInst*>(instr);
            unsigned regIndex;
            if (li) {
                Value *ptr = li->getPointerOperand();
                if (Translator::isGpRegister(ptr, &regIndex)) {
                    instr->setName(X86Translator::getRegisterName(regIndex));
                } else if (Translator::isPcRegister(ptr)) {
                    instr->setName("eip");
                }
            }


        }
    }

    return false;
}

}

