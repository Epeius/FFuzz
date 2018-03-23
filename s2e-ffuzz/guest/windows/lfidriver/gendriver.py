#!/usr/bin/python

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
    proc = subprocess.Popen([pdb_parser, '-i', 'dd', exe_file, pdb_file], stdout=subprocess.PIPE)
    ret = proc.stdout.readline().rstrip().split()
    #Checksum, bits
    return int(ret[0], 16), int(ret[1], 10)

def get_function_address(exe_file, pdb_file, function, allow_null = False):
    proc = subprocess.Popen([pdb_parser, '-f', function, exe_file, pdb_file], stdout=subprocess.PIPE)
    ret = proc.stdout.readline().rstrip().split()
    if len(ret) != 3:
        if allow_null:
            return 0
        else:
            raise RuntimeError('Function %s does not exist in %s' % (function, pdb_file))
    return int(ret[2], 16)

def get_field_offset(exe_file, pdb_file, type_name):
    proc = subprocess.Popen([pdb_parser, '-t', type_name, exe_file, pdb_file], stdout=subprocess.PIPE)
    ret = proc.stdout.readline().rstrip().split()
    if len(ret) == 3:
        return int(ret[2], 16)
    return None

def get_info(exe_file, pdb_file):
    version_str = os.path.basename(exe_file).split('-')[1]
    version = version_str.split('.')

    exe_info = get_exe_info(exe_file, pdb_file)

    ret = {
        'version': version,
        'checksum': exe_info[0],
        'bits': exe_info[1],
        'IopDeleteDriver': get_function_address(exe_file, pdb_file, 'IopDeleteDriver'),
        'KeBugCheck2': get_function_address(exe_file, pdb_file, 'KeBugCheck2'),
        'KdDebuggerDataBlock': get_function_address(exe_file, pdb_file, 'KdDebuggerDataBlock'),
        'KdCopyDataBlock': get_function_address(exe_file, pdb_file, 'KdCopyDataBlock', True),
        'KdpDataBlockEncoded': get_function_address(exe_file, pdb_file, 'KdpDataBlockEncoded', True),

        'PsActiveProcessHead': get_function_address(exe_file, pdb_file, 'PsActiveProcessHead'),
        'PsLoadedModuleList': get_function_address(exe_file, pdb_file, 'PsLoadedModuleList'),
        'PerfLogImageUnload': get_function_address(exe_file, pdb_file, 'PerfLogImageUnload', True),
        'ObpCreateHandle': get_function_address(exe_file, pdb_file, 'ObpCreateHandle'),
        'MmAccessFault': get_function_address(exe_file, pdb_file, 'MmAccessFault'),

        '_EPROCESS_VadRoot': get_field_offset(exe_file, pdb_file, '_EPROCESS:VadRoot'),

        'NtAllocateVirtualMemory': get_function_address(exe_file, pdb_file, 'NtAllocateVirtualMemory'),
        'NtFreeVirtualMemory': get_function_address(exe_file, pdb_file, 'NtFreeVirtualMemory'),
        'NtProtectVirtualMemory': get_function_address(exe_file, pdb_file, 'NtProtectVirtualMemory'),
        'NtMapViewOfSection': get_function_address(exe_file, pdb_file, 'NtMapViewOfSection'),
        'NtUnmapViewOfSection': get_function_address(exe_file, pdb_file, 'NtUnmapViewOfSection'),
        'MiUnmapViewOfSection': get_function_address(exe_file, pdb_file, 'MiUnmapViewOfSection'),
        #'NtUnmapViewOfSectionEx': get_function_address(exe_file, pdb_file, 'NtUnmapViewOfSectionEx'),

        'KiInitialPCR': get_function_address(exe_file, pdb_file, 'KiInitialPCR', True),

        '_KPRCB_ProcessorState': get_field_offset(exe_file, pdb_file, '_KPRCB:ProcessorState'),

        '_EPROCESS_ActiveProcessLinks': get_field_offset(exe_file, pdb_file, '_EPROCESS:ActiveProcessLinks'),
        '_EPROCESS_ThreadListHead': get_field_offset(exe_file, pdb_file, '_EPROCESS:ThreadListHead'),
        '_EPROCESS_UniqueProcessId': get_field_offset(exe_file, pdb_file, '_EPROCESS:UniqueProcessId'),
        '_EPROCESS_CommitCharge': get_field_offset(exe_file, pdb_file, '_EPROCESS:CommitCharge'),
        '_EPROCESS_VirtualSize': get_field_offset(exe_file, pdb_file, '_EPROCESS:VirtualSize'),
        '_EPROCESS_PeakVirtualSize': get_field_offset(exe_file, pdb_file, '_EPROCESS:PeakVirtualSize'),
        '_EPROCESS_CommitChargePeak': get_field_offset(exe_file, pdb_file, '_EPROCESS:CommitChargePeak'),
        '_ETHREAD_ThreadListEntry': get_field_offset(exe_file, pdb_file, '_ETHREAD:ThreadListEntry'),
        '_ETHREAD_Cid': get_field_offset(exe_file, pdb_file, '_ETHREAD:Cid'),

        '_KPRCB_CurrentThread': get_field_offset(exe_file, pdb_file, '_KPRCB:CurrentThread'),
        '_KPCR_Prcb': get_field_offset(exe_file, pdb_file, '_KPCR:Prcb'),
        '_KPCR_KdVersionBlock': get_field_offset(exe_file, pdb_file, '_KPCR:KdVersionBlock'),
        '_KTHREAD_StackBase': get_field_offset(exe_file, pdb_file, '_KTHREAD:StackBase'),
        '_KTHREAD_StackLimit': get_field_offset(exe_file, pdb_file, '_KTHREAD:StackLimit'),
        '_KTHREAD_Process': get_field_offset(exe_file, pdb_file, '_KTHREAD:Process'),
        '_KPRCB_DpcStack': get_field_offset(exe_file, pdb_file, '_KPRCB:DpcStack'),
    }

    process = get_field_offset(exe_file, pdb_file, '_KTHREAD:Process')
    if process is not None:
        ret['_KTHREAD_Process'] = process
    else:
        process = get_field_offset(exe_file, pdb_file, '_ETHREAD:ThreadsProcess')
        if process is None:
            raise RuntimeError('Could not find process field')
        ret['_KTHREAD_Process'] = process

    if version[0] == '5':
        ret['_KPCR_PrcbData'] = get_field_offset(exe_file, pdb_file, '_KPCR:PrcbData')


    #pp = pprint.PrettyPrinter(indent=4)
    #pp.pprint(ret)
    return ret


def extract_info(directory):
    result = []

    for root, dirs, files in os.walk(directory):
        for f in files:
            if '.pdb' not in f:
                continue

            pdb_file = os.path.join(os.path.join(os.getcwd(), root), f)
            exe_file = pdb_file.replace('.pdb', '.exe')
            if not os.path.isfile(exe_file):
                print "Could not find ", exe_file
                return

            info = get_info(exe_file, pdb_file)
            result.append(info)
            print "Processing", f, info['version']

    pickle.dump(result, open('os.pyh', 'wb'))


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

    template = jinja_environment.get_template('gendriver.tpl')
    ret = template.render({'data': data})
    print ret

    fp.close()



if __name__ == "__main__":
    main()
