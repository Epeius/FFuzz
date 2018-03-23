/*
 * QObject JSON integration
 *
 * Copyright IBM, Corp. 2009
 * Copyright 2016 - Cyberhaven
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *  Vitaly Chipounov  <vitaly@cyberhaven.io>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#ifndef QJSON_H
#define QJSON_H

#include <stdarg.h>
#include "qobject.h"
#include "qstring.h"

QObject *qobject_from_json(const char *string);
QObject *qobject_from_jsonf(const char *string, ...);
QObject *qobject_from_jsonv(const char *string, va_list *ap);

QString *qobject_to_json(const QObject *obj);
QString *qobject_to_json_pretty(const QObject *obj);

#endif /* QJSON_H */
