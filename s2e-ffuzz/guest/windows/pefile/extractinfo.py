#!/usr/bin/env python

import sys
import os
import re
import pefile
import argparse

def grepFileInfo(filePath):
    pe_info = filePath+": "

    try:
        pe =  pefile.PE(filePath, fast_load=True)

        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'] ])

        moreInfoSet = 0

        for fileinfo in pe.FileInfo:
            if fileinfo.Key == 'StringFileInfo':
                for st in fileinfo.StringTable:
                    for entry in st.entries.items():
                        if entry[0] == "FileDescription":
                        #if entry[0] == "LegalCopyright" or entry[0] == "CompanyName" or entry[0] == "FileDescription":
                            if moreInfoSet:
                                    pe_info += ", "
                            #pe_info += entry[0] +": "+entry[1]
                            pe_info += entry[1]
                            moreInfoSet = 1
        pe_info = re.sub(r'[^\x00-\x7F]', '#', pe_info)
    except:
        pe_info += "Could not parse %s" % filePath

    return pe_info

def getDescription(pe):
    pe_info = ""
    try:
        moreInfoSet = 0

        for fileinfo in pe.FileInfo:
            if fileinfo.Key == 'StringFileInfo':
                for st in fileinfo.StringTable:
                    for entry in st.entries.items():
                        if entry[0] == "FileDescription":
                            if moreInfoSet:
                                    pe_info += ", "
                            #pe_info += entry[0] +": "+entry[1]
                            pe_info += entry[1]
                            moreInfoSet = 1
        pe_info = re.sub(r'[^\x00-\x7F]', '#', pe_info)
    except:
        return None

    return pe_info

def getNumberOfImports(pe):
    size = 0
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        size += len(entry.imports)
        #print entry.dll
        #for imp in entry.imports:
        #    print '\t', hex(imp.address), imp.name
    return size

def getNumberOfExports(pe):
    try:
        return len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        #print pe.DIRECTORY_ENTRY_EXPORT.symbols
        #for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        #   print entry.name
    except:
        return 0

if __name__ == "__main__":
    argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description='Extract PE file descriptions')
    parser.add_argument('pefiles', metavar='files', nargs='+',
                        help='PE files')

    args = vars(parser.parse_args(argv))
    pefiles = args['pefiles']

    print "File;Description;Size;ImportCount;ExportCount"
    for f in pefiles:
        try:
            pe =  pefile.PE(f, fast_load=True)

            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'] ])

            size = os.path.getsize(f)
            description = getDescription(pe).replace('\n', ' ').replace('\r', '')
            importCount =  getNumberOfImports(pe)
            exportCount = getNumberOfExports(pe)

            print "%s;%s;%d;%d;%d" % (os.path.basename(f), description, size, importCount, exportCount)
        except:
            pass

