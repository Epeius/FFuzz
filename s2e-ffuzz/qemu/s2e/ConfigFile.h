///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_CONFIG_FILE_H
#define S2E_CONFIG_FILE_H

#include <vector>
#include <string>
#include <inttypes.h>

extern "C" {
struct lua_State;
}

namespace s2e {
class S2EExecutionState;


class ConfigFile
{
private:
    /* Don't print warning messages */
    bool m_silent;

    lua_State *m_luaState;

    /* Called on errors during initial loading. Will terminate the program */
    void luaError(const char *fmt, ...);

    /* Called on errors that can be ignored */
    void luaWarning(const char *fmt, ...);

    /* Fake data type for list size */
    struct _list_size { int size; };

    /* Fake data type for table key list */
    struct _key_list { std::vector<std::string> keys; };

    /* Helper to get C++ type name */
    template<typename T>
    const char* getTypeName();

    /* Helper to get topmost value of lua stack as a C++ value */
    template<typename T>
    bool getLuaValue(T* res, const T& def, int index = -1);

    /* Universal implementation for getXXX functions */
    template<typename T>
    T getValueT(const std::string& expr, const T& def, bool *ok);

public:
    ConfigFile(const std::string &configFileName);
    ~ConfigFile();

    /* Return value from configuration file.

       Example:
         width = getValueInt("window.width");

       Arguments:
         name  the name or the value (actually,
               any valid lua expression that will be
               prepended by "return ")
         def   default value to return on error
         ok    if non-null then will be false on error
    */
    bool getBool(const std::string& name, bool def = false, bool *ok = NULL);
    int64_t getInt(const std::string& name, int64_t def = 0, bool *ok = NULL);
    double getDouble(const std::string& name, double def = 0, bool *ok = NULL);
    std::string getString(const std::string& name,
                    const std::string& def = std::string(), bool *ok = NULL);

    typedef std::vector<std::string> string_list;
    string_list getStringList(const std::string& name,
                    const string_list& def = string_list(), bool *ok = NULL);

    typedef std::vector<uint64_t> integer_list;
    integer_list getIntegerList(
            const std::string& name, const integer_list& def = integer_list(), bool *ok = NULL);


    /* Return all string keys for a given table.
       Fails if some keys are not strings. */
    string_list getListKeys(const std::string& name, bool *ok = NULL);

    /* Return the size of the list. Works for all types of
       lua lists just like '#' operator in lua. */
    int getListSize(const std::string& name, bool *ok = NULL);

    bool setBool(const std::string& name, bool value);

    /* Returns true if a config key exists */
    bool hasKey(const std::string& name);


    void invokeLuaCommand(const char *cmd);

    //void invokeAnnotation(const std::string &annotation, S2EExecutionState *param);

    lua_State* getState() const {
        return m_luaState;
    }

    bool isFunctionDefined(const std::string &name) const;

    inline void setSilent(bool silent) {
        m_silent = silent;
    }

    inline bool isSilent() const {
        return m_silent;
    }
};

} // namespace s2e

#endif
