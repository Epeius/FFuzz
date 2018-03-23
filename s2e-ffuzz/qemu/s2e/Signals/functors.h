///
/// Copyright (C) 2011-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


template <class T, typename RET, TYPENAMES>
class FUNCTOR_NAME : public functor_base <RET, BASE_CLASS_INST>
{
public:
    typedef RET (T::*func_t)(FUNCT_DECL);
protected:
    func_t m_func;
    T* m_obj;

public:
    FUNCTOR_NAME(T* obj, func_t f) {
        m_obj = obj;
        m_func = f;
    };

    virtual ~FUNCTOR_NAME() {}

    virtual RET operator()(OPERATOR_PARAM_DECL) {
        FASSERT(this->m_refcount > 0);
        return (*m_obj.*m_func)(CALL_PARAMS);
    };
};

template <class T, typename RET, TYPENAMES>
inline functor_base<RET, BASE_CLASS_INST>*
mem_fun(T &obj, RET (T::*f)(FUNCT_DECL)) {
    return new FUNCTOR_NAME<T, RET, FUNCT_DECL>(&obj, f);
}


/*** Stateless functors ***/
#define xglue(x, y) x ## y
#define glue(x, y) xglue(x, y)


template <typename RET, TYPENAMES>
class glue(FUNCTOR_NAME, _sl) : public functor_base <RET, BASE_CLASS_INST>
{
public:
    typedef RET (*func_t)(FUNCT_DECL);
protected:
    func_t m_func;

public:
    glue(FUNCTOR_NAME, _sl)(func_t f) {
        m_func = f;
    };

    virtual ~glue(FUNCTOR_NAME, _sl)() {}

    virtual RET operator()(OPERATOR_PARAM_DECL) {
        FASSERT(this->m_refcount > 0);
        return (*m_func)(CALL_PARAMS);
    };
};

template <typename RET, TYPENAMES>
inline functor_base<RET, BASE_CLASS_INST>*
ptr_fun(RET (*f)(FUNCT_DECL)) {
    return new glue(FUNCTOR_NAME, _sl)<RET, FUNCT_DECL>(f);
}

#undef glue
#undef xglue
