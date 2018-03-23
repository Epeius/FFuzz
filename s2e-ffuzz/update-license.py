#!/usr/bin/python
#This script updates license information in source files

import sys
import os
import subprocess

s_copyright_map = {
    "epfl": "Dependable Systems Laboratory, EPFL",
    "cyberhaven": "Cyberhaven, Inc",
}

# This maps an email address to the copyright holder institution.
# We need to preserve the original BSD license if someone external
# contributed to the code base.
s_emails_map = {
    "adrian.herrera@epfl.ch": "epfl",
    "alexandre.gouraud@enst-bretagne.fr": "other",
    "alex@cyberhaven.io": "epfl",
    "alex.mihai.c@gmail.com": "epfl",
    "ana.sima@epfl.ch": "epfl",
    "aristide@cyberhaven.io": "cyberhaven",
    "cristi@codetickler.com": "cyberhaven",
    "daniel.mahu@gmail.com": "epfl",
    "dengels@cisco.com": "other",
    "diego@biurrun.de": "other",
    "jonas.wagner@epfl.ch": "epfl",
    "ks.vladimir@gmail.com": "epfl",
    "laurent.fasnacht@epfl.ch": "epfl",
    "lucab@debian.org": "other",
    "michael@inetric.com": "other",
    "mjr@cs.wisc.edu": "other",
    "peter@cyberhaven.io": "epfl",
    "petr.zankov@gmail.com": "epfl",
    "pzankov@yandex.ru": "epfl",
    "raimondas.sasnauskas@cs.rwth-aachen.de": "other",
    "stefan.bucur@epfl.ch": "epfl",
    "swami@cs.wisc.edu": "epfl",
    "vitaly.chipounov@epfl.ch": "epfl",
    "vitalych@users.noreply.github.com": "cyberhaven",
    "vitaly@codetickler.com": "cyberhaven",
    "vitaly@cyberhaven.io": "cyberhaven",
    "vitaly@dslabpc9.epfl.ch": "epfl",
    "vitaly@dslab-picard.epfl.ch": "epfl",
    "vitaly@.(none)": "epfl",
    "vladimir@cyberhaven.io": "epfl",
    "vova@codetickler.com": "cyberhaven",
    "vova.kuznetsov@epfl.ch": "epfl",
    "yoan.blanc@epfl.ch": "epfl",
    "zaddach@eurecom.fr": "other",
}

def get_commit_log(filename):
    output = subprocess.Popen(["git", "log", '--pretty=%ai|%ce', filename], stdout=subprocess.PIPE).communicate()[0]
    lines = output.split('\n')
    result = []
    for l in lines:
        l = l.strip()
        if len(l) == 0:
            continue
        date, email = l.split('|')
        year = date.split('-')[0]
        result.append((year, email))

    return result

def get_institutions(commit_log):
    # map institution => min year, max year
    result = {}

    for year, email in commit_log:
        if email not in s_emails_map:
            print "!! Unknown email:", email
            continue

        inst = s_emails_map[email]
        if inst not in result:
            result[inst] = [year, year]
        else:
            if result[inst][0] > year:
                result[inst][0] = year

            if result[inst][1] < year:
                result[inst][1] = year

    return result

def get_copyrights(insts):
    copyrights = []
    for inst, years in insts.iteritems():
        if inst == 'other':
            continue

        if years[0] == years[1]:
            span = years[0]
        else:
            span = "%s-%s" % (years[0], years[1])

        result = "Copyright (C) %s, %s" % (span, s_copyright_map[inst])
        copyrights.append(result)

    return copyrights

def print_copyrights(copyrights):
    result = "///\n"
    for c in copyrights:
        result = result + "/// " + c + "\n"
    result += "/// All rights reserved. Proprietary and confidential.\n"
    result += "///\n"
    result += "/// Distributed under the terms of S2E-LICENSE\n"
    result += "///\n"

    return result

def strip_header(filename):
    state = 0
    output = ""
    orig_header = ""

    with open(filename, "r") as fp:
        for line in fp.readlines():
            if state == 0:
                if line == "/*\n" or line == "/**\n":
                    state = 1
                    orig_header += line
                    continue
                elif line.strip() != "":
                    # Stop searching when some code is found.
                    state = 2

            elif state == 1:
                if line == " */\n":
                    state = 2
                orig_header += line
                continue

            output += line

    with open(filename, "w") as fp:
        fp.write(output)

    return orig_header

def inject_header(filename, hdr):
    with open(filename, "r") as fp:
        original = fp.read()

    output = hdr + "\n" + original

    with open(filename, "w") as fp:
        fp.write(output)

def check_for_other_emails(hdr):
    for email, inst in s_emails_map.iteritems():
        if (email in hdr) and inst == 'other':
            return True

    return False

def main():
    for f in sys.argv[1:]:
        if os.path.isdir(f):
            continue

        if os.path.islink(f):
            continue

        print "Processing " + f + "..."
        fn, ext = os.path.splitext(f)
        if ext not in [".c", ".cpp", ".h"]:
            print "   Unsupported file type"
            continue


        log = get_commit_log(f)
        insts = get_institutions(log)
        print insts
        cr = get_copyrights(insts)
        cp = print_copyrights(cr)

        # If someone else has copyright in that file, need to preserve
        # the original BSD header.
        if 'other' not in insts:
            orig_header = strip_header(f)
        else:
            print "    Preserving original copyright header"

        # Need to check if there are specific copyrights in the original header.
        # Sometimes, commits are done by other people.
        if orig_header is not None:
            if check_for_other_emails(orig_header):
                print "    Preserving original copyright header"
                cp = cp + "\n\n" + orig_header

        inject_header(f, cp)

if __name__ == "__main__":
    main()
