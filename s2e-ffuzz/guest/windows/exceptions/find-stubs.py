
import idc
from idaapi import *

import sys
import os
import pefile
import pickle
import argparse

KNOWN_SYMBOLS = (
    'RtlpExceptionHandler', '__C_specific_handler', '__CxxFrameHandler3',
    '__GSHandlerCheck', '__GSHandlerCheck_SEH',  '__GSHandlerCheck_EH', 'X86SwitchTo64BitMode'
)

class ToFileStdOut(object):
    def __init__(self, filename):
        self.outfile = open(filename, "w")

    def write(self, text):
        self.outfile.write(text)

    def flush(self):
        self.outfile.flush()

    def isatty(self):
        return False

    def __del__(self):
        self.outfile.close()


def is_in_unknown_area(ea):
    for start_ea in unknown:
        end_ea = unknown[start_ea]
        if ea >= start_ea and ea < end_ea:
            return True
    return False

def get_func_info(name):
    try:
        return funcs_name[name]
    except KeyError:
        return None

def find_functions():
    print("Looking for functions and unknown spaces")
    # Get functions start and end
    for seg_ea in Segments():
        seg_end = SegEnd(seg_ea)
        prev_func = None
        print("Seg start {:x} end {:x}".format(seg_ea, seg_end))
        for funcea in Functions(seg_ea, seg_end):
            func = get_func(funcea)
            funcname = GetFunctionName(funcea)
            print "Function %s at 0x%x" % (funcname, funcea)

            if prev_func is not None:
                unknown[prev_func.endEA] = funcea
                print("Unknown start {:x} end {:x}".format(prev_func.endEA, funcea))
            else:
                unknown[seg_ea] = funcea
                print("Unknown start {:x} end {:x}".format(seg_ea, funcea))

            funcs_start[funcea] = (funcea, func.endEA, funcname)
            funcs_name[funcname] = (funcea, func.endEA, funcname)

            prev_func = func

        if prev_func is not None:
            unknown[prev_func.endEA] = seg_end
            print("Unknown start {:x} end {:x}".format(prev_func.endEA, seg_end))


def find_stubs():
    print("Searching for stubs in unknown areas")
    stubs = []
    # Look for instructions outside functions that have no calls to them
    for seg_ea in Segments():
        for head in Heads(seg_ea, SegEnd(seg_ea)):
            if isCode(GetFlags(head)):
                decoded = idc.GetDisasm(head)
                ref = get_first_cref_to(head)
                code_refs = CodeRefsTo(head, 1)
                data_refs = DataRefsTo(head)

                #if ref == BADADDR and not is_in_function(head):
                if ref == BADADDR and is_in_unknown_area(head):
                    stubs += [head]
    return stubs

def get_file_info(filename):
    pe = pefile.PE(filename, fast_load=True)
    chksum = pe.generate_checksum()
    base = pe.OPTIONAL_HEADER.ImageBase
    filename = os.path.basename(filename)

    return {
        "name": filename,
        "nativebase": base,
        "checksum": chksum,
        "symbols": {}
    }


def get_symbol_addresses(symbols, file_info):
    syms = {}
    for symb in symbols:
        f_info = get_func_info(symb)
        if f_info is None:
            continue
        name = f_info[2]
        syms[name] = f_info[0]

    return syms


parser = argparse.ArgumentParser(description='Analyze file.')
parser.add_argument('-f', '--file', dest="filename", required=True,
                    help="File to analyze")
parser.add_argument('-o', '--out', dest="output", required=True,
                    help="Output pickle")
parser.add_argument('-l', '--log', dest="log", default='idaout.txt',
                    help="Output log file")

args = parser.parse_args(args=idc.ARGV[1:])

sys.stdout = sys.stderr = ToFileStdOut(args.log)
print("Starting analysis")

funcs_start = {}
funcs_name = {}
unknown = {}

idaapi.autoWait()

find_functions()
stubs = find_stubs()

filename = args.filename
output = args.output

file_info = get_file_info(filename)
file_info["symbols"] = get_symbol_addresses(KNOWN_SYMBOLS, file_info)
print(file_info)

i = 0
for s in stubs:
    file_info["symbols"]["_stub" + str(i)] = s
    i += 1

pickle.dump(file_info, open(output, 'wb'))

print("Done")

idc.Exit(0)
