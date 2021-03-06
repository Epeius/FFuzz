/*
 * QInt Module
 *
 * Copyright (C) 2009 Red Hat Inc.
 * Copyright 2016 - Cyberhaven
 *
 * Authors:
 *  Luiz Capitulino <lcapitulino@redhat.com>
 *  Vitaly Chipounov  <vitaly@cyberhaven.io>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

#ifndef QINT_H
#define QINT_H

#include <stdint.h>
#include "qobject.h"

typedef struct QInt {
    QObject_HEAD;
    int64_t value;
} QInt;

QInt *qint_from_int(int64_t value);
int64_t qint_get_int(const QInt *qi);
QInt *qobject_to_qint(const QObject *obj);

#endif /* QINT_H */
