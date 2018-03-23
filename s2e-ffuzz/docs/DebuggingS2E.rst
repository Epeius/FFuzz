=============
Debugging S2E
=============

S2E is a complex aggregation of various tools totaling over 1 million LOCs.
Debugging S2E may be hard. The following types of bugs often turn into a nightmare to diagnose:

* Non-deterministic crashes
* Crashes that happen after a very long execution time
* Crashes that happen all over the place and seem to be caused by corrupted pointers

If one of these applies to your case, you may want to read the following.
The following sections are sorted from simplest to most advanced.

0. The obvious checks
---------------------

Make sure that your code compiles without warnings.
A missing return statement burried somewhere may have dramatic consequences.
Fortunaltey, recent versions of clang put checks in the binary in such cases
(as well as for other undefined behavior), so the program will crash sooner rather than later.


1. Record-replay
----------------

If your bug is non-deterministic and happens 10s of minutes to hours
in your exeperiment, use record replay. VMware Workstation 7 has this feature
and will allow you to come as close to the bug as possible so that you
can look at it in a debugger. If you somehow miss the bug, no problem, you
can replay over and over again. Unfortunatley, recent versions of VMware Workstation
do not have record-replay anymore and you will need a rather old setup and processor
to use version 7.


3. Valgrind
-----------

Valgrind works for small-sized VMs only (typically 1-8MB of guest RAM and very little code).
It is mostly useful when debugging the internals of the execution engine, which does not
require a lot of environment to run.


4. Reverse debugging
--------------------

Like for Valgrind, forget about reverse debugging if you want to debug your full-fledged Linux guest running in S2E.
Neither GDB's built-in reverse debugger nor commercial reverse debugging tools such as `undodb-gdb <http://undo-software.com/>`_
will help when debugging S2E running a full-sized VM.
However, they may be of some help when debugging tiny guest code (e.g., a 1MB-sized VM running a tiny OS kernel).


5. Address Sanitizer
--------------------

S2E can be built with `Address Sanitizer <http://code.google.com/p/address-sanitizer/>`_ turned on.
This should allow to catch
use-after-free types of errors and some more. Execution is reasonably fast so that
you can run a full-fledged VM.

However, Address Sanitizer will work for S2E only after applying some patches.
S2E comes with the required patches and applies them when compiling LLVM.
Attempting to run S2E without patching Address Sanitizer might freeze your system
(Address Sanitizer might erroneously allocate many terabytes of memory, instead of just reserving it).


6. Thread Sanitizer
-------------------

** To be done. **

In principle, S2E could be compiled with `Thread Sanitizer <http://code.google.com/p/thread-sanitizer/>`_ as well.
This should allow to catch data races.
