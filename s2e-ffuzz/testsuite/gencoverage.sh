#!/bin/bash

usage() {
    echo "Usage: gencoverage.sh"
    echo "  --help              show usage info"
    echo "  --coverage-data     Location of *.gcda files generated at run-time"
}


while [ $# -gt 0 ]; do
    case $1 in
        --coverage-data)
            COVERAGE_DATA="$2"
            shift; shift;;
        --help|-h)
            usage
            exit 0;;
        *)
            echo "Unknown parameter $1" >&1
            usage >&1
            exit 1
    esac
done

if [ "x$COVERAGE_DATA" = "x" ]; then
   usage
   exit 1
fi

#Copy gcno files to the space place where gcda is located
for f in $(find $COVERAGE_DATA/ -name '*.gcda'); do
    gcda=${f#$COVERAGE_DATA}
    gcno=${gcda%.gcda}.gcno
    cp $gcno "${f%.gcda}.gcno"
done

#Note: later gcov versions produce data that lcov can't parse

lcov --gcov-tool /usr/bin/gcov-4.6 -c -i -d data -o coverage.base
lcov --gcov-tool /usr/bin/gcov-4.6 -r coverage.base '*llvm*' -o coverage.base
lcov --gcov-tool /usr/bin/gcov-4.6 -r coverage.base '*c++*' -o coverage.base

lcov --gcov-tool /usr/bin/gcov-4.6 -c -d data -o coverage.run
lcov --gcov-tool /usr/bin/gcov-4.6 -r coverage.run '*llvm*' -o coverage.run
lcov --gcov-tool /usr/bin/gcov-4.6 -r coverage.run '*c++*' -o coverage.run

lcov -d data -a coverage.base -a coverage.run -o coverage.total
genhtml -o . coverage.total

