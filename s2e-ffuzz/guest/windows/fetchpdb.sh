#!/bin/sh

#This script downloads from Microsoft's symbol store the PDB file of the given executable

SCRIPT="$(dirname $0)"
export PYTHONPATH="$SCRIPT/pdbparse:$SCRIPT/pefile"
$SCRIPT/pdbparse/examples/symchk.py $*
