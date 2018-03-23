#!/usr/bin/python

"""
Generates symbol definitions for the S2E Vmi plugin.
"""

import os
import subprocess
import pprint
import pickle

import jinja2
jinja_environment = jinja2.Environment(trim_blocks = True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), '.')))

def filter_hex(value):
    try:
        return '%#x' % (value)
    except:
        return value

jinja_environment.filters['hex'] = filter_hex



pdb_parser = './lfipdbparser/Debug/pdbparser.exe'

def get_exe_info(exe_file, pdb_file):
    #print exe_file, pdb_file
    proc = subprocess.Popen([pdb_parser, '-i', exe_file, pdb_file], stdout=subprocess.PIPE)
    ret = proc.stdout.readline().rstrip().split()
    #Checksum, bits
    return int(ret[0], 16), int(ret[1], 10), int(ret[2], 16)

def get_function_address(exe_file, pdb_file, function):
    proc = subprocess.Popen([pdb_parser, '-f', function, exe_file, pdb_file], stdout=subprocess.PIPE)
    ret = proc.stdout.readline().rstrip().split()
    if len(ret) != 3:
        return 0
    return int(ret[2], 16)

def get_field_offset(exe_file, pdb_file, type_name):
    proc = subprocess.Popen([pdb_parser, '-t', type_name, exe_file, pdb_file], stdout=subprocess.PIPE)
    ret = proc.stdout.readline().rstrip().split()
    return int(ret[2], 16)

def get_syscalls(exe_file, pdb_file):
    proc = subprocess.Popen([pdb_parser, '-s', exe_file, pdb_file], stdout=subprocess.PIPE)
    ret = proc.stdout.readlines()
    syscalls = []
    for l in ret:
        (num, addr, name) = l.split()
        syscalls.append((addr, name))
    return syscalls

def get_info(exe_file, pdb_file):
    split_name = os.path.basename(exe_file).split('-')
    filename = split_name[2]
    version_str = split_name[1]
    version = version_str.split('.')

    exe_info = get_exe_info(exe_file, pdb_file)

    symbols = ['RtlpExceptionHandler', '_C_specific_handler', '_CxxFrameHandler3',
               '_GSHandlerCheck', '_GSHandlerCheck_SEH', 'X86SwitchTo64BitMode']

    ret = {
        'version': version_str,
        'name': filename,
        'checksum': exe_info[0],
        'bits': exe_info[1],
        'nativebase': exe_info[2],
        'symbols': {},
    }

    added = False
    for f in symbols:
        address = get_function_address(exe_file, pdb_file, f)
        if address != 0:
            ret['symbols'][f] = address
            added = True

    syscalls = get_syscalls(exe_file, pdb_file)
    if len(syscalls) > 0:
        added = True
        ret['syscalls'] = syscalls

    if not added:
        return None

    #pp = pprint.PrettyPrinter(indent=4)
    #pp.pprint(ret)
    return ret


def extract_info(directory):
    result = []

    for root, dirs, files in os.walk(directory):
        for f in files:
            if '.exe' not in f and '.dll' not in f:
                continue

            print "Processing", f
            exe_file = os.path.join(os.path.join(os.getcwd(), root), f)
            fn,ext = os.path.splitext(exe_file)
            pdb_file = exe_file.replace(ext, '.pdb')
            if not os.path.isfile(pdb_file):
                print "Could not find ", pdb_file
                return

            info = get_info(exe_file, pdb_file)
            if info is not None:
                result.append(info)



    pickle.dump(result, open('vmi.pyh', 'wb'))


def main():
    from optparse import OptionParser

    parser = OptionParser()

    parser.add_option('-d', '--directory', dest="directory",
                      help='Directory cointaining all EXE and PDB files of Windows kernels')

    opts,args = parser.parse_args()

    if opts.directory:
        extract_info(opts.directory)
        return

    fp = open(args[0], "rb")
    data = pickle.load(fp)

    template = jinja_environment.get_template('genvmi.tpl')
    ret = template.render({'data': data})
    print ret

    fp.close()



if __name__ == "__main__":
    main()
