===========
Testing S2E
===========

1. Building the test suite
==========================

    ::

       $ mkdir $S2EDIR/build
       $ cd $S2EDIR/build
       $ make -f ../s2e/Makefile all-testsuite


2. Running the test suite
=========================

    The following commands run unit tests and generate a coverage report

    ::

        $ cd $S2EDIR/build/testsuite-debug
        $ make ENABLE_OPTIMIZED=0 unitcheck
        $ make ENABLE_OPTIMIZED=0 coverage-report


    The coverage report is in ``$S2EDIR/build/testsuite-debug/coverage/index.html``


