///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_UTILS_H
#define S2E_UTILS_H

#include <cstdio>
#include <cassert>
#include <ostream>
#include <iomanip>
#include <sstream>
#include <deque>
#include <inttypes.h>
#include <llvm/Support/raw_ostream.h>

namespace s2e {


struct hexval {
    uint64_t value;
    int width;
    bool prefix;

    hexval(uint64_t _value, int _width=0, bool _prefix = true) : value(_value), width(_width), prefix(_prefix) {}
    hexval(const void* _value, int _width=0, bool _prefix = true): value((uint64_t)_value), width(_width), prefix(_prefix) {}

    std::string str() const {
        std::stringstream ss;

        if (prefix) {
            ss << "0x";
        }
        ss << std::hex;
        if (width) {
            ss << std::setfill('0') << std::setw(width);
        }
        ss << value;

        return ss.str();
    }
};

inline std::ostream& operator<<(std::ostream& out, const hexval& h)
{
    out << h.str();
    return out;
}

inline llvm::raw_ostream& operator<<(llvm::raw_ostream& out, const hexval& h)
{
    out << h.str();
    return out;
}

struct charval {
    uint8_t value;

    charval(uint8_t value): value(value) {}

    std::string str() const {
        std::stringstream ss;

        if (isalnum(value)) {
            ss << (char) value;
        } else {
            ss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (unsigned) value;
        }

        return ss.str();
    }
};

inline std::ostream& operator<<(std::ostream& out, const charval& v)
{
    out << v.str();
    return out;
}

inline llvm::raw_ostream& operator<<(llvm::raw_ostream& out, const charval& v)
{
    out << v.str();
    return out;
}

struct cbyte {
    uint8_t value;

    cbyte(uint8_t value): value(value) {}

    std::string str() const {
        std::stringstream ss;

        if (isalnum(value)) {
            ss << "'" << (char) value << "'";
        } else {
            ss << hexval(value);
        }

        return ss.str();
    }
};

inline std::ostream& operator<<(std::ostream& out, const cbyte& v)
{
    out << v.str();
    return out;
}

inline llvm::raw_ostream& operator<<(llvm::raw_ostream& out, const cbyte& v)
{
    out << v.str();
    return out;
}

/*inline llvm::raw_ostream& operator<<(llvm::raw_ostream& out, const klee::ref<klee::Expr> &expr)
{
    std::stringstream ss;
    ss << expr;
    out << ss.str();
    return out;
}*/

/** A macro used to escape "," in an argument to another macro */
#define S2E_NOOP(...) __VA_ARGS__

#ifdef NDEBUG
#define DPRINTF(...)
#define TRACE(...) 
#else
#define DPRINTF(...) printf(__VA_ARGS__)
#define TRACE(...) { printf("%s - ", __FUNCTION__); printf(__VA_ARGS__); }
#endif

/* The following is GCC-specific implementation of foreach.
   Should handle correctly all crazy C++ corner cases */

#if 0
template <typename T>
class _S2EForeachContainer {
public:
    inline _S2EForeachContainer(const T& t) : c(t), brk(0), i(c.begin()), e(c.end()) { }
    const T c; /* Compiler will remove the copying here */
    int brk;
    typename T::const_iterator i, e;
};

#define foreach(variable, container) \
for (_S2EForeachContainer<__typeof__(container)> _container_(container); \
     !_container_.brk && _container_.i != _container_.e; \
     __extension__  ({ ++_container_.brk; ++_container_.i; })) \
    for (variable = *_container_.i;; __extension__ ({--_container_.brk; break;}))
#endif

#define foreach2(_i, _b, _e) \
      for(__typeof__(_b) _i = _b, _i ## end = _e; _i != _i ## end;  ++ _i)


/** A stream that writes both to parent streamf and cerr */
class raw_tee_ostream : public llvm::raw_ostream {
    std::deque<llvm::raw_ostream*> m_parentBufs;

    virtual void write_impl(const char *Ptr, size_t size) {
        foreach2(it, m_parentBufs.begin(), m_parentBufs.end()) {
            (*it)->write(Ptr, size);
        }
    }

    virtual uint64_t current_pos() const {
        return 0;
    }

    virtual ~raw_tee_ostream() {
        flush();
    }

    size_t preferred_buffer_size() const {
        return 0;
    }

public:
    raw_tee_ostream(llvm::raw_ostream* master): m_parentBufs(1, master) {

    }
    void addParentBuf(llvm::raw_ostream* buf) { m_parentBufs.push_front(buf); }
};

class raw_highlight_ostream : public llvm::raw_ostream {
    llvm::raw_ostream* m_parentBuf;

    virtual void write_impl(const char *Ptr, size_t size) {
        *m_parentBuf << "\033[31m";
        m_parentBuf->flush();
        m_parentBuf->write(Ptr, size);
        *m_parentBuf << "\033[0m";
    }

    virtual uint64_t current_pos() const {
        return 0;
    }

    virtual ~raw_highlight_ostream() {
        flush();
    }

    size_t preferred_buffer_size() const {
        return 0;
    }

public:

    raw_highlight_ostream(llvm::raw_ostream* master): m_parentBuf(master) {}
};




} // namespace s2e

#endif // S2E_UTILS_H
