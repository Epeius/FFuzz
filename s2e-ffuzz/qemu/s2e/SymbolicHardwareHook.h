///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_SYMHW_HOOK_H
#define S2E_SYMHW_HOOK_H

#include <inttypes.h>
#include <klee/Expr.h>

namespace s2e {

enum SymbolicHardwareAccessType {
    SYMB_MMIO, SYMB_DMA, SYMB_PORT
};

class SymbolicPortHook {
public:
    /**
     * This is a callback to check whether some port returns symbolic values.
     * An interested plugin can use it. Only one plugin can use it at a time.
     * This is necessary tp speedup checks (and avoid using signals)
     */
    typedef bool (*SYMB_PORT_CHECK)(uint16_t port, void *opaque);
    typedef klee::ref<klee::Expr> (*SYMB_PORT_READ)(uint16_t port, unsigned size, uint64_t concreteValue, void *opaque);

    /* Returns whether to call the native cpu_out* handler */
    typedef bool (*SYMB_PORT_WRITE)(uint16_t port, const klee::ref<klee::Expr> &value, void *opaque);

    void *m_opaque;
    SYMB_PORT_CHECK m_isSymbolic;
    SYMB_PORT_READ m_readCb;
    SYMB_PORT_WRITE m_writeCb;

public:

    SymbolicPortHook(SYMB_PORT_CHECK isSymbolicCb,
                     SYMB_PORT_READ readCb,
                     SYMB_PORT_WRITE writeCb, void *opaque) {
        m_opaque = opaque;
        m_isSymbolic = isSymbolicCb;
        m_readCb = readCb;
        m_writeCb = writeCb;
    }

    SymbolicPortHook() {
        m_opaque = NULL;
        m_isSymbolic = NULL;
        m_readCb = NULL;
        m_writeCb = NULL;
    }

    inline bool symbolic(uint16_t port) const {
        if (m_isSymbolic) {
            return m_isSymbolic(port, m_opaque);
        }
        return false;
    }

    inline klee::ref<klee::Expr> read(uint16_t port, unsigned size, uint64_t concreteValue) const {
        assert(m_readCb);
        return m_readCb(port, size, concreteValue, m_opaque);
    }

    inline bool write(uint16_t port, const klee::ref<klee::Expr> &value) {
        assert(m_writeCb);
        return m_writeCb(port, value, m_opaque);
    }
};

class SymbolicMemoryHook {
public:
    typedef bool (*SYMB_MEM_CHECK)(struct MemoryRegion *mr, uint64_t physaddress, uint64_t size, void *opaque);
    typedef klee::ref<klee::Expr> (*SYMB_MEM_READ)(
                struct MemoryRegion *mr,
                uint64_t physaddress,
                const klee::ref<klee::Expr> &value,
                SymbolicHardwareAccessType type,
                void *opaque
            );

    typedef void (*SYMB_MEM_WRITE)(
                struct MemoryRegion *mr,
                uint64_t physaddress,
                const klee::ref<klee::Expr> &value,
                SymbolicHardwareAccessType type,
                void *opaque
            );

private:
    void *m_opaque;
    SYMB_MEM_CHECK m_isSymbolic;
    SYMB_MEM_READ m_readCb;
    SYMB_MEM_WRITE m_writeCb;

public:
    SymbolicMemoryHook(SYMB_MEM_CHECK isSymbolicCb,
                     SYMB_MEM_READ readCb,
                     SYMB_MEM_WRITE writeCb, void *opaque) {
        m_opaque = opaque;
        m_isSymbolic = isSymbolicCb;
        m_readCb = readCb;
        m_writeCb = writeCb;
    }

    SymbolicMemoryHook() {
        m_opaque = NULL;
        m_isSymbolic = NULL;
        m_readCb = NULL;
        m_writeCb = NULL;
    }

    inline bool symbolic(struct MemoryRegion *mr, uint64_t physAddress, uint64_t size) const {
        if (m_isSymbolic) {
            return m_isSymbolic(mr, physAddress, size, m_opaque);
        }
        return false;
    }

    inline klee::ref<klee::Expr> read(struct MemoryRegion *mr, uint64_t physAddress,
                                      const klee::ref<klee::Expr> &concolicValue,
                                      SymbolicHardwareAccessType type) const {
        assert (m_readCb);
        return m_readCb(mr, physAddress, concolicValue, type, m_opaque);
    }

    inline void write(struct MemoryRegion *mr, uint64_t physAddress,
                      const klee::ref<klee::Expr> &val,
                      SymbolicHardwareAccessType type) const {
        assert (m_writeCb);
        m_writeCb(mr, physAddress, val, type, m_opaque);
    }

    inline bool readable() const {
        return m_readCb != NULL;
    }

    inline bool writable() const {
        return m_writeCb != NULL;
    }
};

void SymbolicHardwareHookEnableMmioCallbacks(bool enable);

extern SymbolicPortHook g_symbolicPortHook;
extern SymbolicMemoryHook g_symbolicMemoryHook;

}

#endif
